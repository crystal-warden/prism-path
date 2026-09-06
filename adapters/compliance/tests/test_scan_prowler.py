# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Prowler scanner adapter tests — verify exact, honest mapping of AWS findings to posture facts.
Asserts that only mapped facts are produced, MFA/lockout facts remain absent, and posture_connector processes the posture."""
import compliance_adapter as ca
import scanner as sc
import scan_prowler
import posture_connector as pc

FULLY_MAPPED_FACTS = {
    "encryption_at_rest_enforced",
    "default_deny_firewall_policy_enforced",
    "password_history_enforced",
}


def test_prowler_registered():
    assert "prowler" in sc.available()


def test_prowler_maps_only_exact_honest_facts():
    sample = sc.load_sample("prowler_aws")
    facts = scan_prowler.parse(sample)

    assert facts["encryption_at_rest_enforced"] is True
    assert facts["default_deny_firewall_policy_enforced"] is True
    assert facts["password_history_enforced"] is True

    assert set(facts.keys()) == FULLY_MAPPED_FACTS

    for k in (
        "mfa_local_privileged",
        "mfa_network_privileged",
        "mfa_network_nonprivileged",
        "account_lockout_threshold",
        "account_lockout_enforced",
        "session_lock_enforced",
        "fips_validated_cryptography",
    ):
        assert k not in facts


def test_prowler_fail_status_sets_fact_false():
    findings = [
        {"check_id": "ebs_encryption_at_rest_enabled", "status": "FAIL"},
        {"check_id": "s3_bucket_default_encryption", "status": "PASS"},
    ]
    facts = scan_prowler.parse(findings)
    assert facts["encryption_at_rest_enforced"] is False


def test_prowler_prowler_v4_format():
    findings = [
        {"CheckID": "rds_instance_encryption", "StatusCode": "PASS"},
        {"CheckID": "iam_password_policy_reuse", "StatusCode": "MANUAL"},
    ]
    facts = scan_prowler.parse(findings)
    assert facts["encryption_at_rest_enforced"] is True
    assert facts["password_history_enforced"] is True


def test_prowler_empty_and_unmapped_findings_yield_no_facts():
    assert scan_prowler.parse([]) == {}
    unmapped = [
        {"check_id": "iam_user_mfa_enabled_console_access", "status": "FAIL"},
        {"check_id": "cloudtrail_logs_s3_bucket_access_logging_enabled", "status": "PASS"},
    ]
    assert scan_prowler.parse(unmapped) == {}


def test_prowler_to_posture_carries_provenance():
    sample = sc.load_sample("prowler_aws")
    posture = sc.to_posture("prowler", sample, "AWS production account", host="aws-123456789012")
    assert posture["provenance"]["source"] == "prowler"
    assert posture["boundary"] == "AWS production account"
    assert posture["host"] == "aws-123456789012"


def test_prowler_end_to_end_posture_connector():
    ca.use_standard("nist_800171_r2")
    posture = sc.to_posture("prowler", sc.load_sample("prowler_aws"), "AWS cloud enclave")
    res = pc.assess(posture)

    assert res["boundary"] == "AWS cloud enclave"
    assert res["provenance"]["source"] == "prowler"

    graded = {r["control_id"]: r["status"] for r in res["results"]}
    assert graded.get("3.13.16") == "met"

    assert "3.5.3" in res["deferred"]
    assert "3.1.8" in res["deferred"]
