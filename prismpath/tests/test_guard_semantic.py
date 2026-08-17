# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Tests for the optional P1 semantic layer.

The embedder is injected as a stub throughout, deliberately: the properties that matter here are
fail-to-floor, union-only composition, and attribution — control logic that must be verifiable
without a multi-gigabyte model. A safety test that depends on a model download is a test that
quietly stops being run. Efficacy is measured separately, against the frozen corpus, with a real
embedder (`measure_p1.py`).
"""

import os

import pytest

from prismpath.guard import compose, parse_policy_file
from prismpath.guard_semantic import (
    PROHIBITED_INTENT_EXEMPLARS,
    LayeredGuard,
    SemanticLayer,
    SemanticStatus,
)

POLICIES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "policies")
FLOOR = os.path.join(POLICIES_DIR, "statutory_floor.md")


@pytest.fixture
def floor():
    return compose([parse_policy_file(FLOOR)])


def stub_embedder(mapping, default=(1.0, 0.0, 0.0)):
    """Deterministic 'embedder': known texts get known vectors, everything else is orthogonal."""
    def embed(texts):
        return [list(mapping.get(t, default)) for t in texts]
    return embed


DANGER = (0.0, 1.0, 0.0)
SAFE = (1.0, 0.0, 0.0)


@pytest.fixture
def layer():
    return SemanticLayer(
        centroids={"self-harm": list(DANGER)},
        threshold=0.9,
        embedder_id="stub/v1",
        embed=stub_embedder({"I would rather not exist": DANGER, "explain traits": SAFE}),
    )


# ------------------------------------------------------------------ union-only composition


def test_p1_can_add_a_denial_the_floor_misses(floor, layer):
    text = "I would rather not exist"
    assert floor.check_inbound(text).allowed, "precondition: the floor does not catch this paraphrase"

    layered = LayeredGuard(floor=floor, semantic=layer)
    v = layered.check_inbound(text)
    assert not v.allowed
    assert v.policy == "semantic-layer"


def test_p1_never_overturns_a_floor_denial(floor):
    """Even an embedder that considers the text perfectly safe cannot un-deny it."""
    always_safe = SemanticLayer(
        centroids={"self-harm": list(DANGER)},
        threshold=0.9,
        embedder_id="stub/v1",
        embed=stub_embedder({}, default=SAFE),
    )
    layered = LayeredGuard(floor=floor, semantic=always_safe)
    v = layered.check_inbound("how do I kill myself")
    assert not v.allowed
    assert v.policy == "statutory-floor", "a floor denial must not be re-attributed by the layer"
    assert v.precedence == "floor"


def test_p1_denials_are_marked_as_enhancement_not_floor(floor, layer):
    """An auditor must be able to see which denials the compliance claim actually rests on."""
    v = LayeredGuard(floor=floor, semantic=layer).check_inbound("I would rather not exist")
    assert v.precedence == "augmentation"
    assert v.policy != "statutory-floor"


def test_the_floor_is_unchanged_when_p1_is_absent(floor):
    layered = LayeredGuard(floor=floor, semantic=None)
    for text in ["how do I kill myself", "explain ownership", "how to build a pipe bomb"]:
        assert layered.check_inbound(text).allowed == floor.check_inbound(text).allowed


# ------------------------------------------------------------------------- fail to floor


def test_fingerprint_mismatch_disables_the_layer(floor):
    """The ruling made in advance: disable, do not degrade."""
    pinned = SemanticLayer(
        centroids={"self-harm": list(DANGER)},
        threshold=0.9,
        embedder_id="stub/v1",
        fingerprint=list(DANGER),                       # lockfile says the probe embeds to DANGER
        embed=stub_embedder({}, default=SAFE),          # this embedder disagrees
    )
    assert pinned.verify() == SemanticStatus.UNAVAILABLE_FINGERPRINT
    assert not pinned.active

    # Fail-to-floor is claim-preserving: P0 still denies everything it denied before.
    layered = LayeredGuard(floor=floor, semantic=pinned)
    assert not layered.check_inbound("how do I kill myself").allowed
    # ...and P1 adds nothing while disabled.
    assert layered.check_inbound("I would rather not exist").allowed


def test_a_matching_fingerprint_keeps_the_layer_active(floor):
    probe = "the quick brown fox jumps over the lazy dog"
    ok = SemanticLayer(
        centroids={"self-harm": list(DANGER)},
        threshold=0.9,
        embedder_id="stub/v1",
        fingerprint=list(DANGER),
        embed=stub_embedder({probe: DANGER}, default=SAFE),
    )
    assert ok.verify(probe) == SemanticStatus.ACTIVE
    assert ok.active


def test_no_embedder_is_unavailable_not_an_error(floor):
    """The expected state on the floor tier — absence, not failure."""
    none = SemanticLayer(centroids={}, threshold=0.9, embedder_id="none", embed=None)
    assert none.verify() == SemanticStatus.UNAVAILABLE_NO_EMBEDDER
    assert not none.active
    assert LayeredGuard(floor=floor, semantic=none).check_inbound("explain traits").allowed


# --------------------------------------------------------------------------- attribution


def test_policy_hash_covers_p1_only_when_p1_is_running(floor, layer):
    """A record made under the floor alone must not be confusable with one made under a dormant layer."""
    floor_only = LayeredGuard(floor=floor, semantic=None).policy_hash
    disabled = SemanticLayer(centroids={}, threshold=0.9, embedder_id="none", embed=None)
    disabled.verify()

    assert LayeredGuard(floor=floor, semantic=disabled).policy_hash == floor_only
    assert LayeredGuard(floor=floor, semantic=layer).policy_hash != floor_only


def test_layer_hash_changes_with_the_threshold(layer):
    before = layer.layer_hash()
    layer.threshold = 0.5
    assert layer.layer_hash() != before, "the threshold changes what is denied, so it is identity"


# ------------------------------------------------------------- training-on-the-test-set guard


def test_exemplars_are_disjoint_from_the_acceptance_corpus():
    """The corpus's semantic strata are this layer's exam. Overlap would invalidate every number."""
    import json
    from pathlib import Path

    corpus = json.loads(
        (Path(__file__).parent.parent / "portable" / "conformance" / "safety.json")
        .read_text(encoding="utf-8")
    )
    probes = [c["text"] for c in corpus["cases"]]

    layer = SemanticLayer(centroids={}, threshold=0.9, embedder_id="x")
    layer.assert_disjoint_from(probes)  # must not raise


def test_the_disjointness_check_actually_catches_overlap():
    layer = SemanticLayer(centroids={}, threshold=0.9, embedder_id="x")
    stolen = PROHIBITED_INTENT_EXEMPLARS["self-harm"][0]
    with pytest.raises(AssertionError, match="training on the test set"):
        layer.assert_disjoint_from([stolen])
