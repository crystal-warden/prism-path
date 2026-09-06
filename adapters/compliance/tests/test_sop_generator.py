# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The SOP generator: objective-grounded templates, coverage machine-checked against the catalog,
honest TODO markers, no fabrication."""
import copy
import compliance_adapter as ca
import sop_generator as sg


def _ir():
    ca.use_standard("nist_800171_r2")
    return sg.load_spec("incident_response")


FULL_ANSWERS = {
    "org_name": "Crystal Warden Supply Chain Labs LLC",
    "system_name": "PrismPath CUI Enclave",
    "boundary": "the CUI enclave on example-host",
    "cui_description": "controlled technical data under DFARS 252.204-7012",
    "ir_lead_role": "the Security Lead",
    "internal_officials": "the Owner and the Security Lead",
    "external_authorities": "DoD DIBNet within 72 hours of a confirmed CUI incident",
    "preparation": "annual training, an on-call rotation, and maintained runbooks",
    "detection": "endpoint and network monitoring plus user reports",
    "analysis": "a triage and severity-scoring process",
    "containment": "isolating affected hosts from the enclave",
    "recovery": "restoring from verified backups",
    "user_response": "notifying and directing affected users through the Security Lead",
    "tracking_system": "the incident register in the ticketing system",
    "documentation_practice": "a timeline, actions taken, evidence, and disposition per incident",
    "reporting_timeline": "72 hours of confirmation",
    "reporting_method": "the DIBNet portal and direct notification to officials",
    "test_frequency": "annually",
    "test_method": "a tabletop exercise",
}


def test_incident_response_is_listed():
    assert "incident_response" in sg.list_documents()


def test_coverage_complete_against_catalog():
    cov = sg.verify_coverage(_ir())
    assert cov["complete"] is True
    assert cov["n_objectives"] == 14          # 3.6.1[a-g] + 3.6.2[a-f] + 3.6.3[a]
    assert cov["mapped"] == 14
    assert cov["missing"] == []
    assert cov["extra"] == []
    assert cov["duplicated"] == []


def test_intake_covers_profile_and_document_questions():
    items = sg.intake(_ir())
    keys = {i["key"] for i in items}
    assert {"org_name", "system_name", "boundary", "cui_description"} <= keys
    assert {"ir_lead_role", "preparation", "tracking_system", "test_method"} <= keys
    assert any(i["scope"] == "profile" for i in items)
    assert any(i["scope"] == "document" for i in items)


def test_generate_full_has_no_todo():
    res = sg.generate(_ir(), FULL_ANSWERS)
    assert res["unanswered"] == []
    assert "[TODO:" not in res["markdown"]
    assert "Crystal Warden Supply Chain Labs LLC" in res["markdown"]
    assert "# Incident Response Plan" in res["markdown"]
    assert "Appendix A. Control Objective Coverage" in res["markdown"]
    assert "COVERAGE WARNING" not in res["markdown"]
    # the coverage appendix names real objectives
    assert "3.6.1[g]" in res["markdown"] and "3.6.2[e]" in res["markdown"]


def test_generate_partial_marks_todo_and_does_not_fabricate():
    partial = {k: v for k, v in FULL_ANSWERS.items() if k not in ("containment", "test_method")}
    res = sg.generate(_ir(), partial)
    assert set(res["unanswered"]) == {"containment", "test_method"}
    assert "[TODO: " in res["markdown"]
    # the TODO carries the actual question, so the gap is actionable
    assert "How are incidents contained" in res["markdown"]


def test_generate_empty_marks_everything_todo():
    res = sg.generate(_ir(), {})
    every_key = {i["key"] for i in sg.intake(_ir())}
    assert set(res["unanswered"]) == every_key


def test_honest_boundary_notice_present():
    res = sg.generate(_ir(), FULL_ANSWERS)
    assert "not evidence by itself" in res["markdown"]
    assert "retains records that it runs" in res["markdown"]


def test_coverage_detects_a_spec_gap():
    spec = copy.deepcopy(_ir())
    # drop one objective mapping from the capability section -> should be reported missing
    spec["sections"][2]["objectives"].remove("3.6.1[g]")
    cov = sg.verify_coverage(spec)
    assert cov["complete"] is False
    assert "3.6.1[g]" in cov["missing"]


def test_coverage_detects_drift():
    spec = copy.deepcopy(_ir())
    spec["sections"][4]["objectives"].append("3.6.9[z]")   # not a real objective
    cov = sg.verify_coverage(spec)
    assert cov["complete"] is False
    assert "3.6.9[z]" in cov["extra"]
