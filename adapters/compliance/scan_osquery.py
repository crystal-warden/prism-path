#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""osquery scanner adapter — map osquery results to posture facts.

Input: a dict of osquery query results, {query_name: [row, ...]}, as produced by running a pack of
queries with `osqueryi --json` or osquery scheduled results. Each row is a dict of string columns.

Coverage (honest): osquery core cleanly reports OS session-lock state on macOS via the `screenlock`
table, which decides control 3.1.10 (session lock). Facts osquery core does not expose (FIPS mode,
account lockout, MFA) are left absent, so the posture_connector defers those controls rather than
assume them. Extend the mapping as osquery tables/extensions provide more (e.g. Windows
security_profile_info for lockout and password policy).
"""


def _rows(raw, query):
    value = raw.get(query)
    return value if isinstance(value, list) else ([value] if value else [])


def _first(raw, query):
    rows = _rows(raw, query)
    return rows[0] if rows else None


def _as_bool(raw_value):
    if isinstance(raw_value, bool):
        return raw_value
    if raw_value is None:
        return None
    text = str(raw_value).strip().lower()
    if text in ("1", "true", "yes", "on", "enabled"):
        return True
    if text in ("0", "false", "no", "off", "disabled", ""):
        return False
    return None


def _as_int(raw_value):
    try:
        return int(str(raw_value).strip())
    except (TypeError, ValueError):
        return None


def parse(raw):
    """osquery results (dict of query_name -> rows) -> facts dict, mapping only what osquery reports."""
    facts = {}

    # macOS `screenlock` table: columns enabled (0/1) and grace_period (seconds). Decides 3.1.10.
    sl = _first(raw, "screenlock")
    if sl is not None:
        enabled = _as_bool(sl.get("enabled"))
        grace = _as_int(sl.get("grace_period"))
        if enabled is not None:
            facts["session_lock_enforced"] = enabled          # 3.1.10[b]
            # a macOS screen lock conceals the display, so pattern-hiding holds when the lock is on
            facts["session_lock_pattern_hiding"] = enabled     # 3.1.10[c]
        if grace is not None:
            facts["session_lock_timeout_seconds"] = grace      # 3.1.10[a]

    # osquery `disk_encryption` table: column `encrypted` (0/1) per volume. CUI at rest (3.13.16) is
    # protected only when every reported volume is encrypted; a single unencrypted volume refutes it.
    de_rows = _rows(raw, "disk_encryption")
    if de_rows:
        states = [_as_bool(row.get("encrypted")) for row in de_rows]
        if all(state is not None for state in states):
            facts["encryption_at_rest_enforced"] = all(states)  # 3.13.16[a]

    return facts
