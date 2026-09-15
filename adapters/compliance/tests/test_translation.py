# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Retrieval Translation layer: catalog completeness, objective targeting, and the discovery-loop wiring."""
import json, os
import pytest
from adapters.compliance import compliance_adapter as ca

CIDS = ["3.1.1", "3.1.2", "3.1.4", "3.1.5", "3.1.7", "3.1.11", "3.1.12", "3.1.22"]


@pytest.mark.parametrize("cid", CIDS)
def test_control_has_evidence_types(cid):
    control = ca.get_control(cid)
    assert control.get("evidence_types"), cid


@pytest.mark.parametrize("cid", CIDS)
def test_every_objective_has_discovery_query(cid):
    control = ca.get_control(cid)
    for objective in control["objectives"]:
        assert objective.get("discovery_query", "").strip(), (cid, objective["id"])


def test_translate_empty_targets_all_objectives():
    control = ca.get_control("3.1.7")
    translation = ca.translate_missing(control)
    assert len(translation["requests"]) == len(control["objectives"])
    assert translation["evidence_types"] == control["evidence_types"]


def test_translate_unmet_subset_only():
    control = ca.get_control("3.1.12")
    translation = ca.translate_missing(control, unmet_ids=["3.1.12[b]", "3.1.12[d]"])
    ids = [request["objective_id"] for request in translation["requests"]]
    assert ids == ["3.1.12[b]", "3.1.12[d]"]


def test_translate_unknown_objective_ignored():
    control = ca.get_control("3.1.5")
    translation = ca.translate_missing(control, unmet_ids=["3.1.5[zzz]"])
    assert translation["requests"] == []                                  # unknown ids drop, no crash


def test_defer_for_evidence_generates_from_catalog(iso_defer):
    control = ca.get_control("3.1.7")
    pend = ca.defer_for_evidence(control, {"control_id": "3.1.7", "boundary": "x", "evidence": []})
    req = pend["request"]
    assert pend["status"] == "pending_evidence"
    assert isinstance(req, dict) and len(req["requests"]) == len(control["objectives"])


def test_defer_backward_compat_string(iso_defer):
    control = ca.get_control("3.1.5")
    pend = ca.defer_for_evidence(control, {"evidence": []}, missing="hand-written ask")
    assert pend["request"] == "hand-written ask"


def test_deferred_request_persists(iso_defer):
    control = ca.get_control("3.1.7")
    pend = ca.defer_for_evidence(control, {"control_id": "3.1.7", "boundary": "x", "evidence": []})
    rec = iso_defer.get(pend["unit_id"])
    assert rec is not None and rec["prior_output"]["request"]["control_id"] == "3.1.7"
