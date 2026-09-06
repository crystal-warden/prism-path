# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Breadth2 tests for newly added machine-checkable technical configuration controls."""
import pytest
import deterministic_checks as dc
import compliance_adapter as ca

NEWLY_COVERED_CONTROLS_BREADTH2 = [
    "3.1.9",
    "3.1.19",
    "3.3.7",
    "3.8.7",
    "3.8.8",
    "3.13.15",
    "3.14.2",
]


def _control(cid):
    ca.use_standard("nist_800171_r2")
    return ca.get_control(cid)


@pytest.mark.parametrize("cid", NEWLY_COVERED_CONTROLS_BREADTH2)
def test_breadth2_newly_covered_controls_are_machine_checkable(cid):
    ctrl = _control(cid)
    assert dc.machine_checkable(ctrl) is True


def test_breadth2_total_machine_checkable_control_count():
    ca.use_standard("nist_800171_r2")
    cat = ca._catalog()
    checkable = [cid for cid, c in cat["controls"].items() if dc.machine_checkable({"id": cid, **c})]
    assert len(checkable) == 50   # grew from 26 as the check registry was extended (see test_posture_connector.CHECKABLE)
    for cid in NEWLY_COVERED_CONTROLS_BREADTH2:
        assert cid in checkable


def test_breadth2_deterministic_adjudication():
    # Test 3.1.9 (privacy and security notices)
    res_319 = dc.adjudicate_deterministic(_control("3.1.9"), {"facts": {"login_banner_defined": True, "login_banner_enforced": True}})
    assert res_319 is not None
    assert res_319["status"] == "met"

    # Test 3.1.19 (mobile device encryption)
    res_3119 = dc.adjudicate_deterministic(_control("3.1.19"), {"facts": {"mobile_devices_identified": True, "mobile_device_encryption_enforced": True}})
    assert res_3119 is not None
    assert res_3119["status"] == "met"

    # Test 3.3.7 (clock sync)
    res_337 = dc.adjudicate_deterministic(_control("3.3.7"), {"facts": {"audit_timestamps_enabled": True, "ntp_server_configured": True, "ntp_sync_enabled": True}})
    assert res_337 is not None
    assert res_337["status"] == "met"

    # Test 3.8.7 (removable media controlled)
    res_387 = dc.adjudicate_deterministic(_control("3.8.7"), {"facts": {"removable_media_controlled": True}})
    assert res_387 is not None
    assert res_387["status"] == "met"

    # Test 3.8.8 (unowned portable storage prohibited)
    res_388 = dc.adjudicate_deterministic(_control("3.8.8"), {"facts": {"unowned_portable_storage_prohibited": True}})
    assert res_388 is not None
    assert res_388["status"] == "met"

    # Test 3.13.15 (session authenticity)
    res_31315 = dc.adjudicate_deterministic(_control("3.13.15"), {"facts": {"session_authenticity_protected": True}})
    assert res_31315 is not None
    assert res_31315["status"] == "met"

    # Test 3.14.2 (antivirus protection at designated locations)
    res_3142 = dc.adjudicate_deterministic(_control("3.14.2"), {"facts": {"antivirus_locations_identified": True, "antivirus_locations_protected": True}})
    assert res_3142 is not None
    assert res_3142["status"] == "met"
