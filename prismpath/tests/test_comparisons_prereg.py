# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The layer comparison pre registration gate (prismpath/comparisons/PREREGISTRATION.md).

Three things are pinned here. The neutral corpus must be self consistent: every scenario's written
expectation is recomputed from its own policy under the neutral semantics. The freeze hash over
the protocol, the result contract, the corpus format, and every policy must equal the committed
PREREGISTRATION.lock, so any edit after the freeze surfaces here and has to be recorded as an
amendment. And the protocol document must actually name every corpus policy and every dimension,
so the predictions table cannot drift from the corpus.
"""
import re
from pathlib import Path

from prismpath.comparisons import corpus_check as cc

COMP = Path(cc.__file__).resolve().parent


def test_corpus_is_self_consistent():
    errors = cc.check_corpus()
    assert errors == [], "\n".join(errors)


def test_corpus_shape_matches_the_protocol_summary():
    policies = cc.load_corpus()
    assert len(policies) == 6
    n_sc = sum(len(p["scenarios"]) for _, p in policies)
    n_lc = sum(len(p.get("lifecycle", [])) for _, p in policies)
    assert n_sc == 61
    assert n_lc == 5
    level_m = [p["id"] for _, p in policies if p["level_m_claim"]]
    assert sorted(level_m) == ["ai_action_gate", "expense_approval", "network_admission", "sensor_interlock"]


def test_freeze_hash_matches_the_lock():
    locked = cc.read_lock()
    assert locked is not None, "PREREGISTRATION.lock missing; run corpus_check --freeze once, then commit it"
    current = cc.freeze_hash()
    assert current == locked, (
        "a frozen pre registration file changed after the freeze; record an amendment in "
        "PREREGISTRATION.md section 12 and regenerate the lock with corpus_check --freeze"
    )


def test_lock_lists_every_frozen_file():
    lock = (COMP / "PREREGISTRATION.lock").read_text(encoding="utf-8")
    for p in cc.frozen_paths():
        assert p.relative_to(COMP).as_posix() in lock


def test_protocol_names_every_policy_and_dimension():
    doc = (COMP / "PREREGISTRATION.md").read_text(encoding="utf-8")
    for _path, pol in cc.load_corpus():
        assert f"`{pol['id']}`" in doc, f"policy {pol['id']} not named in PREREGISTRATION.md"
    for dim in sorted(cc.DIMENSIONS):
        assert re.search(rf"^\| {dim} \|", doc, re.M), f"no prediction row for {dim}"
        assert re.search(rf"\*\*{dim}\.", doc), f"no dimension definition for {dim}"


def test_neutral_evaluator_semantics():
    pol = {"rules": [
        {"id": "r1", "if": {"cmp": ["x", ">", 5]}, "then": "allow"},
        {"id": "r2", "if": {"any": [{"missing": "flag"}, {"cmp": ["flag", "==", False]}]}, "then": "abstain"},
    ], "fields": {}}
    assert cc.decide(pol, {"x": 6, "flag": True}) == ("allow", "r1")
    assert cc.decide(pol, {"x": 2}) == ("abstain", "r2")          # missing flag
    assert cc.decide(pol, {"flag": True}) == ("no_match", None)    # missing x is unsatisfied, never an error
    assert cc.decide(pol, {"x": True, "flag": True}) == ("no_match", None)  # a bool never orders against an int


def test_rebac_reference_derivation():
    pol = next(p for _, p in cc.load_corpus() if p["id"] == "document_sharing_rebac")
    m = pol["model"]
    assert cc._related(m, "user:alice", "viewer", "doc:d1")      # group -> folder -> doc
    assert cc._related(m, "user:dana", "viewer", "doc:d2")       # folder -> doc
    assert cc._related(m, "user:bob", "viewer", "doc:d2")        # direct
    assert not cc._related(m, "user:bob", "viewer", "doc:d1")
    assert not cc._related(m, "user:carol", "viewer", "doc:d1")


def test_matrix_on_the_committed_results_dir_is_all_untested_or_valid(tmp_path):
    from prismpath.comparisons.matrix import build_matrix
    data = build_matrix(COMP / "results")
    for dim, row in data["matrix"].items():
        for sys_id, cell in row.items():
            assert cell["grade"] in ("UNTESTED", "NATIVE", "WITH-WORK", "NOT")
    assert set(data["verdicts"]) == cc.DIMENSIONS
