# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Breadth tests for newly added SOP specification documents."""
import pytest
import sop_generator as sg

NEW_SOP_SPECS = [
    "access_control_policy",
    "configuration_management_plan",
    "media_protection_policy",
    "audit_and_accountability_policy",
]


@pytest.mark.parametrize("doc_id", NEW_SOP_SPECS)
def test_new_sop_specs_verify_coverage_complete(doc_id):
    spec = sg.load_spec(doc_id)
    cov = sg.verify_coverage(spec)
    assert cov["complete"] is True
    assert len(cov["missing"]) == 0
    assert len(cov["extra"]) == 0
    assert len(cov["duplicated"]) == 0


def test_all_sop_specs_are_complete():
    import compliance_adapter as ca
    ca.use_standard("nist_800171_r2")            # default for specs without an explicit 'standard'
    docs = sg.list_documents()
    assert len(docs) >= 4
    for doc_id in docs:
        spec = sg.load_spec(doc_id)
        cov = sg.verify_coverage(spec)           # standard-aware: resolves via spec['standard'] when present
        assert cov["complete"] is True, f"SOP spec {doc_id} failed: missing={cov['missing']} extra={cov['extra']}"


@pytest.mark.parametrize("doc_id", NEW_SOP_SPECS)
def test_new_sop_specs_generate_markdown(doc_id):
    spec = sg.load_spec(doc_id)
    answers = {
        "org_name": "Acme Defense LLC",
        "system_name": "CUI-Cloud-1",
        "boundary": "AWS GovCloud us-gov-west-1 VPC",
        "cui_description": "Controlled Technical Information",
    }
    gen = sg.generate(spec, answers)
    assert gen["title"] == spec["title"]
    assert "Appendix A. Control Objective Coverage" in gen["markdown"]
    assert gen["coverage"]["complete"] is True
