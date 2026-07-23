"""Retrieval Translation layer: catalog completeness, objective targeting, and the discovery-loop wiring."""
import json, os
import pytest
import compliance_adapter as ca

CIDS = ["3.1.1", "3.1.2", "3.1.4", "3.1.5", "3.1.7", "3.1.11", "3.1.12", "3.1.22"]


@pytest.mark.parametrize("cid", CIDS)
def test_control_has_evidence_types(cid):
    c = ca.get_control(cid)
    assert c.get("evidence_types"), cid


@pytest.mark.parametrize("cid", CIDS)
def test_every_objective_has_discovery_query(cid):
    c = ca.get_control(cid)
    for o in c["objectives"]:
        assert o.get("discovery_query", "").strip(), (cid, o["id"])


def test_translate_empty_targets_all_objectives():
    c = ca.get_control("3.1.7")
    t = ca.translate_missing(c)
    assert len(t["requests"]) == len(c["objectives"])
    assert t["evidence_types"] == c["evidence_types"]


def test_translate_unmet_subset_only():
    c = ca.get_control("3.1.12")
    t = ca.translate_missing(c, unmet_ids=["3.1.12[b]", "3.1.12[d]"])
    ids = [r["objective_id"] for r in t["requests"]]
    assert ids == ["3.1.12[b]", "3.1.12[d]"]


def test_translate_unknown_objective_ignored():
    c = ca.get_control("3.1.5")
    t = ca.translate_missing(c, unmet_ids=["3.1.5[zzz]"])
    assert t["requests"] == []                                  # unknown ids drop, no crash


def test_defer_for_evidence_generates_from_catalog(iso_defer):
    c = ca.get_control("3.1.7")
    pend = ca.defer_for_evidence(c, {"control_id": "3.1.7", "boundary": "x", "evidence": []})
    req = pend["request"]
    assert pend["status"] == "pending_evidence"
    assert isinstance(req, dict) and len(req["requests"]) == len(c["objectives"])


def test_defer_backward_compat_string(iso_defer):
    c = ca.get_control("3.1.5")
    pend = ca.defer_for_evidence(c, {"evidence": []}, missing="hand-written ask")
    assert pend["request"] == "hand-written ask"


def test_deferred_request_persists(iso_defer):
    c = ca.get_control("3.1.7")
    pend = ca.defer_for_evidence(c, {"control_id": "3.1.7", "boundary": "x", "evidence": []})
    rec = iso_defer.get(pend["unit_id"])
    assert rec is not None and rec["prior_output"]["request"]["control_id"] == "3.1.7"
