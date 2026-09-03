# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Lynis scanner adapter: it maps only what Lynis genuinely reports, so it grades a handful of host
controls and honestly DEFERS the ones it cannot establish (MFA, screen lock, password complexity)."""
import compliance_adapter as ca
import scanner as sc
import scan_lynis
import posture_connector as pc

FULLY_GRADED = {"3.1.8", "3.5.8", "3.13.11", "3.13.16", "3.1.9", "3.14.4", "3.13.6"}


def test_lynis_registered():
    assert "lynis" in sc.available()


def test_lynis_maps_only_what_it_reports():
    facts = scan_lynis.parse(sc.load_sample("lynis_linux"))
    assert facts["account_lockout_threshold"] == 5 and facts["account_lockout_enforced"] is True
    assert facts["password_history_count"] == 24 and facts["password_history_enforced"] is True
    assert facts["fips_validated_cryptography"] is True
    assert facts["encryption_at_rest_enforced"] is True
    assert facts["login_banner_defined"] is True and facts["login_banner_enforced"] is True
    assert facts["antivirus_auto_update_enabled"] is True
    assert facts["default_deny_firewall_policy_enforced"] is True
    # honest boundaries: no fanned-out MFA, no screen-lock from an SSH timeout, no length-as-complexity
    for k in ("mfa_local_privileged", "mfa_network_privileged", "privileged_accounts_identified",
              "session_lock_pattern_hiding", "session_lock_enforced", "password_complexity_enforced"):
        assert k not in facts


def test_lynis_default_deny_not_inferred_from_firewall_active():
    # a running firewall is NOT a default-deny policy; without the real signal the fact stays absent
    assert "default_deny_firewall_policy_enforced" not in scan_lynis.parse({"firewall_active": "1"})


def test_lynis_empty_report_yields_no_facts():
    assert scan_lynis.parse({}) == {}


def test_lynis_to_posture_carries_provenance():
    posture = sc.to_posture("lynis", sc.load_sample("lynis_linux"), "the Linux enclave", host="protectli-ubuntu-vm")
    assert posture["provenance"]["source"] == "lynis"
    assert posture["host"] == "protectli-ubuntu-vm"


def test_lynis_end_to_end_grades_reported_controls_and_defers_the_rest():
    ca.use_standard("nist_800171_r2")
    res = pc.assess(sc.to_posture("lynis", sc.load_sample("lynis_linux"), "the Linux enclave"))
    graded = {r["control_id"]: r["status"] for r in res["results"]}
    for cid in FULLY_GRADED:
        assert graded.get(cid) == "met", (cid, graded)
    # MFA and screen lock are NOT gradable from a Lynis scan, so they defer rather than pass on a proxy
    assert "3.5.3" in res["deferred"] and "3.1.10" in res["deferred"]
