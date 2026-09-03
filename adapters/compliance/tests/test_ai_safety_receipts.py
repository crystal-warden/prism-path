# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Real signed, anchored receipts for AI-safety determinations, and the payoff: with a key, the AST-2
and AST-3 facts are MEASURED from actual crypto rather than taken from a declaration."""
import pytest
import compliance_adapter as ca
import ai_safety_receipts as r
import ai_safety as ais
from prismpath import policy_pack as pp


@pytest.fixture
def key(tmp_path):
    return pp.keygen(str(tmp_path), "ai-safety-test")


def _det(vh="v3"):
    return {"control_id": "AST-1", "status": "met", "version_hash": vh, "tested_at": "2026-09-03"}


def test_receipt_sign_verify_roundtrip(key):
    d = _det()
    rec = r.sign_receipt(d, key, "2026-09-03T00:00:00Z")
    assert len(bytes.fromhex(rec["signature"])) == 64        # a real Ed25519 signature
    assert r.verify_receipt(rec, d, key["public"]) is True


def test_receipt_detects_tampered_determination(key):
    d = _det()
    rec = r.sign_receipt(d, key, "2026-09-03T00:00:00Z")
    tampered = dict(d, status="not-met")
    assert r.verify_receipt(rec, tampered, key["public"]) is False


def test_receipt_detects_tampered_signature(key):
    d = _det()
    rec = r.sign_receipt(d, key, "2026-09-03T00:00:00Z")
    rec["signature"] = "00" * 64
    assert r.verify_receipt(rec, d, key["public"]) is False


def test_anchor_verifies_and_detects_edit(key):
    rec = r.sign_receipt(_det(), key, "2026-09-03T00:00:00Z")
    m = r.anchor_receipt(rec)
    assert r.verify_anchor(m) is True
    m["root"] = "deadbeef"
    assert r.verify_anchor(m) is False


def _state(dets, caps=None):
    return {"boundary": "the model", "capabilities": caps or {},
            "versions": [{"version_hash": "v3", "deployed": True, "current": True}],
            "determinations": dets}


def test_measure_all_facts_true_when_signed_and_fingerprinted(key):
    mf = ais.measure(_state([_det("v3")]), key, "2026-09-03T00:00:00Z")["measured_facts"]
    assert all(mf[k] for k in ("determinations_signed", "receipts_anchored",
                               "point_in_time_replayable", "tests_fingerprinted", "stale_tests_refused"))


def test_measure_fingerprint_false_without_version_hash(key):
    d = {"control_id": "AST-1", "status": "met", "tested_at": "x"}   # no version_hash
    mf = ais.measure(_state([d]), key, "2026-09-03T00:00:00Z")["measured_facts"]
    assert mf["tests_fingerprinted"] is False
    assert mf["stale_tests_refused"] is False
    assert mf["determinations_signed"] is True                       # still signable


def test_measured_assessment_beats_a_declaration(key):
    # a pipeline that declares AST-1, AST-2[c/d], AST-3[d], AST-4, but NOT the signing / fingerprint facts
    caps = {"test_suite_defined": True, "model_versions_hashed": True,
            "discrimination_margin_measured": True, "collapsed_margin_abstains": True,
            "continuous_evaluation": True,
            "io_baseline_comparison": True, "drift_abstains_or_escalates": True}

    # without a key: the unsigned/unfingerprinted facts are absent, so AST-2 and AST-3 defer
    declared = ais.assess(_state([_det("v3")], dict(caps)))
    assert "AST-2" in declared["deferred"] and "AST-3" in declared["deferred"]
    assert declared["measured"] == []

    # with a key: those facts are MEASURED from real signed, anchored receipts, so both controls decide met
    measured = ais.assess(_state([_det("v3")], dict(caps)), key=key, signed_at="2026-09-03T00:00:00Z")
    by = {x["control_id"]: x for x in measured["results"]}
    assert by["AST-2"]["status"] == "met"
    assert by["AST-3"]["status"] == "met"
    assert set(measured["measured"]) == {"determinations_signed", "receipts_anchored",
                                         "point_in_time_replayable", "tests_fingerprinted", "stale_tests_refused"}
    assert len(measured["receipts"]) == 1
    assert ca.active_standard() == "nist_800171_r2"                  # standard restored
