# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Breadth2 tests for newly added SOP specification documents."""
import pytest
import sop_generator as sg

NEW_BREADTH2_SOP_SPECS = [
    "identification_and_authentication_policy",
    "physical_protection_policy",
    "personnel_security_policy",
    "maintenance_policy",
]


@pytest.mark.parametrize("doc_id", NEW_BREADTH2_SOP_SPECS)
def test_breadth2_sop_specs_verify_coverage_complete(doc_id):
    spec = sg.load_spec(doc_id)
    cov = sg.verify_coverage(spec)
    assert cov["complete"] is True
    assert len(cov["missing"]) == 0
    assert len(cov["extra"]) == 0
    assert len(cov["duplicated"]) == 0


@pytest.mark.parametrize("doc_id", NEW_BREADTH2_SOP_SPECS)
def test_breadth2_sop_specs_generate_markdown(doc_id):
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
