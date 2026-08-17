# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Prototype/centroid routing tests (roadmap item 2). A stub embedder keeps them fast + deterministic;
the real N=301 cross-validated result is measured separately (see `prismpath centroids`)."""
import numpy as np
import pytest

from prismpath import centroid, embedder
from prismpath.parser import parse
from prismpath.router import EmbeddingRouter, HybridRouter, LLMRouter

_VEC = {"cond_a": [1, 0, 0], "cond_b": [0, 1, 0], "tricky": [0.7, 0.5, 0]}


def _stub(texts, is_query=False):
    out = []
    for t in texts:
        v = _VEC.get(t)
        if v is None:                       # deterministic hash for unknown text
            h = abs(hash(t))
            v = [(h >> 0) & 7, (h >> 3) & 7, (h >> 6) & 7]
        v = np.asarray(v, dtype="float32")
        n = np.linalg.norm(v)
        out.append(v / n if n else v)
    return np.asarray(out, dtype="float32")


@pytest.fixture
def stub(monkeypatch):
    monkeypatch.setattr(embedder, "embed", _stub)


EDGES = [("a", "cond_a"), ("b", "cond_b")]
GRAPH = parse("---\nname:t\nstart:n\n---\n## n\nGo.\n-> a: cond_a\n-> b: cond_b\n## a\n## b\n")


def test_centroid_overrides_a_confident_zeroshot_error(stub):
    # zero-shot routes "tricky" to a (the condition-phrase similarity) — but the correct edge is b
    assert EmbeddingRouter().route("tricky", EDGES).target == "a"
    # history: 3 real "tricky"-shaped outcomes actually took edge b -> the centroid captures it
    recs = [{"flow": "t", "node": "n", "outcome": "tricky", "label": "b"}] * 3
    cr = centroid.CentroidRouter.from_labeled(recs, {"t": GRAPH}, prior_weight=1.0)
    d = cr.route("tricky", EDGES)
    assert d.target == "b"                              # the confident error is fixed by history


def test_zero_history_falls_back_to_the_condition_prior(stub):
    cr = centroid.CentroidRouter({}, {}, prior_weight=4.0)   # no centroids at all
    # with no history it routes exactly like the condition-prior embedding router
    assert cr.route("tricky", EDGES).target == EmbeddingRouter().route("tricky", EDGES).target


def test_shrinkage_needs_enough_history_to_flip(stub):
    # ONE example under a heavy prior is not enough to overturn the condition prior (graceful cold-start)
    one = centroid.CentroidRouter.from_labeled(
        [{"flow": "t", "node": "n", "outcome": "tricky", "label": "b"}], {"t": GRAPH}, prior_weight=20.0)
    assert one.route("tricky", EDGES).target == "a"    # prior still dominates with n=1, prior=20


def test_build_centroids_only_semantic_and_counts(stub):
    g = parse("---\nname:t\nstart:n\n---\n## n\nGo.\n-> a: cond_a\n-> keep: when x\n## a\n## keep\n")
    recs = [{"flow": "t", "node": "n", "outcome": "tricky", "label": "a"},
            {"flow": "t", "node": "n", "outcome": "tricky", "label": "keep"}]   # deterministic edge -> ignored
    cen, cnt = centroid.build_centroids(recs, {"t": g})
    assert cnt == {"cond_a": 1}                        # only the semantic edge's condition gets a centroid


def test_record_condition_resolves_all_shapes(stub):
    # explicit condition
    assert centroid.record_condition({"condition": "cond_x"}, {}) == "cond_x"
    # routelog candidates
    assert centroid.record_condition(
        {"label": "b", "candidates": [{"target": "a", "condition": "ca"}, {"target": "b", "condition": "cb"}]},
        {}) == "cb"
    # via the graph
    assert centroid.record_condition({"flow": "t", "node": "n", "label": "b"}, {"t": GRAPH}) == "cond_b"


def test_drops_into_hybrid_as_the_embed_tier(stub):
    recs = [{"flow": "t", "node": "n", "outcome": "tricky", "label": "b"}] * 5
    cr = centroid.CentroidRouter.from_labeled(recs, {"t": GRAPH}, prior_weight=1.0)
    # a HybridRouter with a confident centroid decision does NOT escalate (margin above default δ)
    called = {"llm": False}
    h = HybridRouter(LLMRouter(lambda p: called.__setitem__("llm", True) or "1"), embed=cr)
    d = h.route("tricky", EDGES)
    assert d.target == "b" and called["llm"] is False


def test_cross_validate_returns_per_stratum(stub):
    recs = ([{"flow": "t", "node": "n", "outcome": "tricky", "label": "b", "stratum": "polarity"}] * 6 +
            [{"flow": "t", "node": "n", "outcome": "cond_a", "label": "a", "stratum": "intent"}] * 4)
    res = centroid.cross_validate(recs, {"t": GRAPH}, folds=2, prior_weight=1.0)
    assert "ALL" in res and set(res["ALL"]) == {"n", "baseline", "centroid", "delta"}
    assert res["config"]["n_decisions"] == 10
