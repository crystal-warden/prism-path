# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Bidirectional bridge for the frozen safety vectors.

Enforces both directions on every run, the same discipline as `test_conformance_vectors.py`:
  * the committed vectors must match a fresh regeneration from the live guard  -> no silent
    REFERENCE drift (someone edits guard.py or the floor policy and forgets the corpus)
  * the live guard must satisfy the committed vectors                          -> no silent
    IMPLEMENTATION drift

Either failure means the safety boundary moved without the move being reviewed, which for a trusted
control is exactly what must never happen quietly.
"""

import json
import os

from prismpath.guard import compose, parse_policy
from prismpath.portable import gen_safety_conformance as gen

VECTORS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "portable", "conformance", "safety.json",
)


def _load():
    with open(VECTORS, encoding="utf-8") as fh:
        return json.load(fh)


def test_committed_vectors_match_a_fresh_regeneration():
    """`git diff` over the corpus IS the boundary-change review."""
    fresh = json.dumps(gen.generate(), indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    with open(VECTORS, encoding="utf-8") as fh:
        assert fh.read() == fresh, (
            "safety vectors are stale — regenerate with "
            "`python -m prismpath.portable.gen_safety_conformance` and review the diff"
        )


def test_the_guard_satisfies_every_committed_vector():
    data = _load()
    guards = {}
    for name, src in data["policy_sources"].items():
        guards[name] = parse_policy(src)

    failures = []
    for case in data["cases"]:
        policies = [guards[n] for n in case["policies"]]
        verdict = compose(policies).check(case["text"], case["direction"])
        expect = case["expect"]

        got = {"allowed": verdict.allowed}
        if not verdict.allowed:
            got.update(policy=verdict.policy, rule=verdict.rule, citation=verdict.citation)

        if got != expect:
            failures.append(f"{case['direction']}/{case['text'][:40]!r}: expected {expect}, got {got}")

    assert not failures, "guard diverged from the frozen boundary:\n  " + "\n  ".join(failures)


def test_the_corpus_embeds_its_policy_sources():
    """A port must be able to consume this file alone, with no access to the PrismPath tree."""
    data = _load()
    assert data["policy_sources"], "vectors must embed the policy documents"
    for name in data["policy_sources"]:
        parse_policy(data["policy_sources"][name])  # must parse standalone


def test_the_corpus_keeps_meaningful_negatives():
    """Denials alone would let an over-blocking port pass. The allowed cases are normative too."""
    data = _load()
    allowed = [c for c in data["cases"] if c["expect"]["allowed"]]
    denied = [c for c in data["cases"] if not c["expect"]["allowed"]]
    assert len(allowed) >= 20, "too few negative cases to catch over-blocking"
    assert len(denied) >= 20, "too few positive cases to catch under-blocking"
