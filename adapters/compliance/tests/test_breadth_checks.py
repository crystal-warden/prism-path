# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Breadth tests for expanded machine-checkable technical configuration controls."""
import pytest
import deterministic_checks as dc
import compliance_adapter as ca

NEWLY_COVERED_CONTROLS = [
    "3.5.4",
    "3.5.5",
    "3.5.6",
    "3.5.9",
    "3.5.10",
    "3.5.11",
    "3.13.6",
    "3.13.7",
    "3.13.9",
    "3.13.16",
    "3.14.4",
    "3.14.5",
]

PREVIOUSLY_COVERED_CONTROLS = [
    "3.1.8",
    "3.1.10",
    "3.1.11",
    "3.5.3",
    "3.5.7",
    "3.5.8",
    "3.13.11",
]


def _control(cid):
    ca.use_standard("nist_800171_r2")
    return ca.get_control(cid)


@pytest.mark.parametrize("cid", NEWLY_COVERED_CONTROLS)
def test_newly_covered_controls_are_machine_checkable(cid):
    ctrl = _control(cid)
    assert dc.machine_checkable(ctrl) is True


def test_total_machine_checkable_control_count():
    ca.use_standard("nist_800171_r2")
    cat = ca._catalog()
    checkable = [cid for cid, c in cat["controls"].items() if dc.machine_checkable({"id": cid, **c})]
    assert len(checkable) >= 17
    for cid in NEWLY_COVERED_CONTROLS + PREVIOUSLY_COVERED_CONTROLS:
        assert cid in checkable


def test_deterministic_adjudication_for_new_controls():
    # Test replay-resistant auth (3.5.4)
    facts_354 = {"replay_resistant_auth_enforced": True}
    res_354 = dc.adjudicate_deterministic(_control("3.5.4"), {"facts": facts_354})
    assert res_354 is not None
    assert res_354["status"] == "met"

    # Test inactive identifier disable (3.5.6)
    facts_356 = {"inactive_identifier_disable_days": 90, "inactive_identifier_disable_enforced": True}
    res_356 = dc.adjudicate_deterministic(_control("3.5.6"), {"facts": facts_356})
    assert res_356 is not None
    assert res_356["status"] == "met"

    # Test default deny firewall (3.13.6)
    facts_3136 = {"default_deny_firewall_policy_enforced": True, "firewall_allow_by_exception_enforced": False}
    res_3136 = dc.adjudicate_deterministic(_control("3.13.6"), {"facts": facts_3136})
    assert res_3136 is not None
    assert res_3136["status"] == "partially-met"
    assert res_3136["unmet_objective_ids"] == ["3.13.6[b]"]

    # Test encryption at rest (3.13.16)
    facts_31316 = {"encryption_at_rest_enforced": True}
    res_31316 = dc.adjudicate_deterministic(_control("3.13.16"), {"facts": facts_31316})
    assert res_31316 is not None
    assert res_31316["status"] == "met"
