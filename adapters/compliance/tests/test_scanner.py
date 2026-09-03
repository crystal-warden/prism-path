# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Scanner adapters: normalize scanner output into a posture, and merge several scanners of one host.
The osquery adapter maps only what osquery reports, so the posture_connector grades what it covers and
defers the rest."""
import pytest
import compliance_adapter as ca
import scanner as sc
import scan_osquery
import posture_connector as pc


def test_osquery_registered():
    assert "osquery" in sc.available()


def test_osquery_parses_session_lock_facts():
    raw = sc.load_sample("osquery_macos")
    facts = scan_osquery.parse(raw)
    assert facts == {"session_lock_enforced": True, "session_lock_pattern_hiding": True,
                     "session_lock_timeout_seconds": 900}


def test_osquery_value_coercion():
    assert scan_osquery.parse({"screenlock": [{"enabled": "0", "grace_period": "300"}]}) == {
        "session_lock_enforced": False, "session_lock_pattern_hiding": False,
        "session_lock_timeout_seconds": 300}
    # missing screenlock -> no facts (deferred downstream), never assumed
    assert scan_osquery.parse({"os_version": [{"name": "macOS"}]}) == {}


def test_osquery_disk_encryption_is_all_or_nothing():
    # every volume encrypted -> CUI at rest protected (3.13.16); one unencrypted volume refutes it
    assert scan_osquery.parse({"disk_encryption": [{"encrypted": "1"}, {"encrypted": "1"}]}) == {
        "encryption_at_rest_enforced": True}
    assert scan_osquery.parse({"disk_encryption": [{"encrypted": "1"}, {"encrypted": "0"}]}) == {
        "encryption_at_rest_enforced": False}


def test_to_posture_carries_source_and_boundary():
    raw = sc.load_sample("osquery_macos")
    posture = sc.to_posture("osquery", raw, "the Mac dev host", host="figue-mac")
    assert posture["provenance"]["source"] == "osquery"
    assert posture["boundary"] == "the Mac dev host"
    assert posture["host"] == "figue-mac"
    assert posture["facts"]["session_lock_timeout_seconds"] == 900


def test_unknown_adapter_raises():
    with pytest.raises(KeyError):
        sc.to_posture("nessus", {}, "x")


def test_end_to_end_osquery_posture_grades_session_lock():
    ca.use_standard("nist_800171_r2")
    posture = sc.to_posture("osquery", sc.load_sample("osquery_macos"), "the Mac dev host")
    res = pc.assess(posture)
    # osquery only supplies the session-lock facts, so 3.1.10 is decided and the rest are deferred
    assert [r["control_id"] for r in res["results"]] == ["3.1.10"]
    assert res["results"][0]["status"] == "met"
    assert "3.13.11" in res["deferred"] and "3.5.3" in res["deferred"]


def test_merge_postures_unions_facts_and_flags_conflicts():
    osq = sc.to_posture("osquery", sc.load_sample("osquery_macos"), "host", host="mac")
    manual = sc.build_posture({"fips_validated_cryptography": True}, "host", "manual-export")
    merged = sc.merge_postures([osq, manual])
    assert merged["facts"]["session_lock_enforced"] is True
    assert merged["facts"]["fips_validated_cryptography"] is True
    assert merged["provenance"]["merged_from"] == ["osquery", "manual-export"]
    assert "conflicts" not in merged["provenance"]

    conflicting = sc.build_posture({"session_lock_enforced": False}, "host", "other")
    merged2 = sc.merge_postures([osq, conflicting])
    assert merged2["facts"]["session_lock_enforced"] is False   # later source wins
    assert merged2["provenance"]["conflicts"][0]["fact"] == "session_lock_enforced"
