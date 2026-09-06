#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Prowler AWS scanner adapter — map Prowler JSON findings to posture facts.

Input: a list of Prowler finding dicts (Prowler v3 or v4 JSON), each with a check ID under key
`check_id` or `CheckID` and a status under `status` or `StatusCode` ("PASS", "FAIL", "MANUAL").

Coverage is strictly HONEST and limited. Only exact cloud findings for encryption at rest,
security group default deny/restriction policies, and IAM password history reuse are mapped.
All other facts (account lockout, screen lock, FIPS mode, MFA) are left absent so that
posture_connector defers those controls.
"""


def _as_bool(v):
    if isinstance(v, bool):
        return v
    if v is None:
        return None
    s = str(v).strip().lower()
    if s in ("1", "true", "yes", "on", "enabled"):
        return True
    if s in ("0", "false", "no", "off", "disabled", ""):
        return False
    return None


def _matches_encryption(cid_str):
    prefixes = ("ebs_", "s3_bucket_", "rds_", "efs_")
    return any(p in cid_str for p in prefixes) and ("encryption" in cid_str)


def _matches_firewall(cid_str):
    return ("securitygroup" in cid_str) and ("default" in cid_str or "restrict" in cid_str)


def _matches_password_history(cid_str):
    return ("iam_password_policy" in cid_str) and ("reuse" in cid_str)


def parse(raw):
    """Prowler findings (list of dicts) -> facts dict, implementing only honest Prowler mappings."""
    if not isinstance(raw, list):
        raw = []

    facts = {}
    mappings = [
        ("encryption_at_rest_enforced", _matches_encryption),
        ("default_deny_firewall_policy_enforced", _matches_firewall),
        ("password_history_enforced", _matches_password_history),
    ]

    for fact_key, match_fn in mappings:
        matching_statuses = []
        for f in raw:
            if not isinstance(f, dict):
                continue
            cid = f.get("check_id") or f.get("CheckID")
            if not cid:
                continue
            cid_str = str(cid).lower()
            if match_fn(cid_str):
                st = f.get("status") or f.get("StatusCode")
                st_str = str(st).strip().upper() if st is not None else ""
                matching_statuses.append(st_str)

        if matching_statuses:
            if any(st == "FAIL" for st in matching_statuses):
                facts[fact_key] = False
            else:
                facts[fact_key] = True

    return facts
