#!/usr/bin/env python3
"""Comparator-based Adjudicator for machine-checkable NIST 800-171 objectives (the honest-hybrid seam).

The Adjudicator port does not assume an LLM (ADAPTER_CONTRACT.md: "the FPGA adapter will drive it
with comparators"). This module is that comparator adjudicator for the subset of assessment
objectives that can be decided deterministically from structured configuration facts, with no model
in the loop.

When every objective of a control can be decided from the submitted facts, the determination is a
pure function of those facts, reproducible byte-for-byte. When any objective is not machine-decidable
(no check registered, or its fact is absent or ambiguous) the module ABSTAINS (returns None) and the
caller falls back to the escalation-default LLM adjudicator. That is the honest hybrid: deterministic
where the evidence is machine-checkable, model-judged where it is prose.

Fail-closed: a missing or ambiguous fact is UNKNOWN (None), never assumed satisfied. A control with
any UNKNOWN objective is not decided here.

Evidence facts: the assessment request may carry a `facts` dict of machine-readable configuration
values, e.g. from a config scanner or an IdP / endpoint export:

    {"control_id": "3.1.8", "boundary": "...",
     "facts": {"account_lockout_threshold": 5, "account_lockout_enforced": true}}

Each objective maps to one fact key and one check kind (see CHECK_SPEC). `flag` reads a boolean fact;
`defined` reads a threshold or count (present and > 0 means defined). A check returns True (satisfied),
False (refuted), or None (undeterminable). Extend CHECK_SPEC as connectors learn to emit more facts.
This first cut seeds the canonical technical-configuration controls whose every 800-171A objective is
decidable from configuration; procedural and operational objectives stay with the LLM adjudicator.
"""
from typing import Optional


def _flag(facts, key) -> Optional[bool]:
    """A boolean configuration fact: True/False when present, None (unknown) when absent."""
    v = facts.get(key)
    return None if v is None else bool(v)


def _defined(facts, key) -> Optional[bool]:
    """A 'requirement is defined' fact expressed as a threshold or count: present and > 0 means
    defined (True), present and <= 0 means not defined (False), absent means unknown (None). A
    non-numeric truthy value (e.g. a policy identifier) also counts as defined."""
    v = facts.get(key)
    if v is None:
        return None
    try:
        return int(v) > 0
    except (TypeError, ValueError):
        return bool(v)


_KINDS = {"flag": _flag, "defined": _defined}

# objective id -> (check kind, fact key). Declarative so both the predicate and the fact-key map
# derive from one source. Seeded with technical-configuration controls whose every objective is
# decidable from configuration.
CHECK_SPEC = {
    # 3.13.11 Employ FIPS-validated cryptography to protect the confidentiality of CUI
    "3.13.11[a]": ("flag", "fips_validated_cryptography"),

    # 3.1.8 Limit unsuccessful logon attempts
    "3.1.8[a]": ("defined", "account_lockout_threshold"),
    "3.1.8[b]": ("flag", "account_lockout_enforced"),

    # 3.5.8 Prohibit password reuse for a specified number of generations
    "3.5.8[a]": ("defined", "password_history_count"),
    "3.5.8[b]": ("flag", "password_history_enforced"),

    # 3.1.11 Terminate (automatically) a user session after a defined condition
    "3.1.11[a]": ("flag", "session_termination_conditions_defined"),
    "3.1.11[b]": ("flag", "session_auto_termination_enforced"),

    # 3.1.10 Use session lock with pattern-hiding displays after a period of inactivity
    "3.1.10[a]": ("defined", "session_lock_timeout_seconds"),
    "3.1.10[b]": ("flag", "session_lock_enforced"),
    "3.1.10[c]": ("flag", "session_lock_pattern_hiding"),

    # 3.5.7 Enforce a minimum password complexity and change of characters
    "3.5.7[a]": ("flag", "password_complexity_defined"),
    "3.5.7[b]": ("flag", "password_change_of_char_defined"),
    "3.5.7[c]": ("flag", "password_complexity_enforced"),
    "3.5.7[d]": ("flag", "password_change_of_char_enforced"),

    # 3.5.3 Multifactor authentication for local/network access to privileged accounts and network
    # access to non-privileged accounts
    "3.5.3[a]": ("flag", "privileged_accounts_identified"),
    "3.5.3[b]": ("flag", "mfa_local_privileged"),
    "3.5.3[c]": ("flag", "mfa_network_privileged"),
    "3.5.3[d]": ("flag", "mfa_network_nonprivileged"),

    # 3.5.4 Employ replay-resistant authentication mechanisms
    "3.5.4[a]": ("flag", "replay_resistant_auth_enforced"),

    # 3.5.5 Prevent reuse of identifiers for a defined period
    "3.5.5[a]": ("defined", "identifier_reuse_prohibited_days"),
    "3.5.5[b]": ("flag", "identifier_reuse_prevention_enforced"),

    # 3.5.6 Disable identifiers after a defined period of inactivity
    "3.5.6[a]": ("defined", "inactive_identifier_disable_days"),
    "3.5.6[b]": ("flag", "inactive_identifier_disable_enforced"),

    # 3.5.9 Require immediate change of temporary passwords
    "3.5.9[a]": ("flag", "force_change_temp_password_enforced"),

    # 3.5.10 Store and transmit only cryptographically-protected passwords
    "3.5.10[a]": ("flag", "password_storage_encrypted"),
    "3.5.10[b]": ("flag", "password_transit_encrypted"),

    # 3.5.11 Obscure feedback of authentication information
    "3.5.11[a]": ("flag", "auth_feedback_obscured"),

    # 3.13.6 Deny network communications traffic by default and allow by exception
    "3.13.6[a]": ("flag", "default_deny_firewall_policy_enforced"),
    "3.13.6[b]": ("flag", "firewall_allow_by_exception_enforced"),

    # 3.13.7 Prevent remote devices from simultaneously establishing non-remote connections
    "3.13.7[a]": ("flag", "split_tunneling_prohibited"),

    # 3.13.9 Terminate network connections after inactivity or session end
    "3.13.9[a]": ("defined", "network_session_timeout_seconds"),
    "3.13.9[b]": ("flag", "network_session_termination_on_end"),
    "3.13.9[c]": ("flag", "network_session_timeout_enforced"),

    # 3.13.16 Protect confidentiality of CUI at rest
    "3.13.16[a]": ("flag", "encryption_at_rest_enforced"),

    # 3.14.4 Update malicious code protection mechanisms
    "3.14.4[a]": ("flag", "antivirus_auto_update_enabled"),

    # 3.14.5 Perform periodic and real-time malicious code scans
    "3.14.5[a]": ("defined", "antivirus_scan_frequency_days"),
    "3.14.5[b]": ("flag", "antivirus_periodic_scan_enforced"),
    "3.14.5[c]": ("flag", "antivirus_realtime_scan_enforced"),

    # 3.1.9 Provide privacy and security notices
    "3.1.9[a]": ("flag", "login_banner_defined"),
    "3.1.9[b]": ("flag", "login_banner_enforced"),

    # 3.1.19 Encrypt CUI on mobile devices and mobile computing platforms
    "3.1.19[a]": ("flag", "mobile_devices_identified"),
    "3.1.19[b]": ("flag", "mobile_device_encryption_enforced"),

    # 3.3.7 Provide a system capability that compares and synchronizes internal system clocks
    "3.3.7[a]": ("flag", "audit_timestamps_enabled"),
    "3.3.7[b]": ("flag", "ntp_server_configured"),
    "3.3.7[c]": ("flag", "ntp_sync_enabled"),

    # 3.8.7 Control the use of removable media on system components
    "3.8.7[a]": ("flag", "removable_media_controlled"),

    # 3.8.8 Prohibit the use of portable storage devices when such devices have no identifiable owner
    "3.8.8[a]": ("flag", "unowned_portable_storage_prohibited"),

    # 3.13.15 Protect the authenticity of communications sessions
    "3.13.15[a]": ("flag", "session_authenticity_protected"),

    # 3.14.2 Provide protection from malicious code at designated locations
    "3.14.2[a]": ("flag", "antivirus_locations_identified"),
    "3.14.2[b]": ("flag", "antivirus_locations_protected"),

    # --- AI Safety Testing catalog (standard 'ai_safety_testing') ---
    # AST-1 Retest on every model change
    "AST-1[a]": ("flag", "test_suite_defined"),
    "AST-1[b]": ("flag", "model_versions_hashed"),
    "AST-1[c]": ("flag", "safety_determination_for_current_version"),   # computed by ai_safety.version_binding
    "AST-1[d]": ("flag", "no_unretested_deployed_versions"),            # computed by ai_safety.version_binding
    # AST-2 Detect stale tests
    "AST-2[a]": ("flag", "tests_fingerprinted"),
    "AST-2[b]": ("flag", "stale_tests_refused"),
    "AST-2[c]": ("flag", "discrimination_margin_measured"),
    "AST-2[d]": ("flag", "collapsed_margin_abstains"),
    # AST-3 Continuous point-in-time proof
    "AST-3[a]": ("flag", "determinations_signed"),
    "AST-3[b]": ("flag", "receipts_anchored"),
    "AST-3[c]": ("flag", "point_in_time_replayable"),
    "AST-3[d]": ("flag", "continuous_evaluation"),
    # AST-4 Runtime input and output monitoring
    "AST-4[a]": ("flag", "io_baseline_comparison"),
    "AST-4[b]": ("flag", "drift_abstains_or_escalates"),

    # --- AI Governance catalog (standard 'ai_governance') ---
    # The inventory / register objectives are decidable from an AI-use register (ai_register connector);
    # the policy and operating objectives stay with the SOP generator, the task records, and the LLM.
    "MP-1[a]": ("flag", "ai_user_inventory_exists"),
    "MP-1[b]": ("flag", "ai_process_inventory_exists"),
    "MP-2[a]": ("flag", "approved_ai_tools_list_exists"),
    "MP-2[b]": ("flag", "unapproved_ai_tool_use_controlled"),
    "MP-3[a]": ("flag", "ai_data_inventory_exists"),
    "MP-3[c]": ("flag", "ai_prohibited_data_controls_enforced"),
    "MP-4[a]": ("flag", "ai_vendor_inventory_exists"),
    "MP-5[a]": ("flag", "ai_decision_impact_classified"),
    "MP-5[b]": ("flag", "ai_high_risk_uses_tiered"),
    "MS-1[c]": ("flag", "ai_evidence_integrity_protected"),
}


def _make_check(kind, key):
    fn = _KINDS[kind]
    return lambda facts: fn(facts, key)


# objective id -> predicate(facts) -> True | False | None
CHECKS = {oid: _make_check(kind, key) for oid, (kind, key) in CHECK_SPEC.items()}
# objective id -> the fact key it reads (what a scanner adapter must supply)
FACT_KEYS = {oid: key for oid, (_kind, key) in CHECK_SPEC.items()}


def machine_checkable(control) -> bool:
    """True when every objective of the control has a registered deterministic check."""
    objs = control.get("objectives", [])
    return bool(objs) and all(o["id"] in CHECKS for o in objs)


def check_objectives(control, facts) -> dict:
    """Per-objective config verdicts for the objectives this module can decide from `facts`. Returns
    {objective_id: bool} for decided objectives only, skipping those with no check or a missing fact.
    Unlike adjudicate_deterministic (all-or-defer), this is the partial view the unified adjudicator
    merges with the other mechanisms."""
    facts = facts or {}
    out = {}
    for o in control.get("objectives", []):
        fn = CHECKS.get(o["id"])
        if fn is None:
            continue
        r = fn(facts)
        if r is None:
            continue
        out[o["id"]] = bool(r)
    return out


def adjudicate_deterministic(control, req) -> Optional[dict]:
    """Return a determination decided purely from configuration facts, or None to defer to the LLM.

    None (fail-closed) is returned whenever any objective has no registered check or its fact is
    absent or ambiguous — the control is decided here only when EVERY objective is decidable.
    The determination matches the flat adapter schema plus a `method` marker for provenance.
    """
    facts = (req or {}).get("facts") or {}
    objs = control.get("objectives", [])
    if not objs:
        return None
    results = {}
    for o in objs:
        oid = o["id"]
        fn = CHECKS.get(oid)
        if fn is None:
            return None
        r = fn(facts)
        if r is None:
            return None
        results[oid] = r
    unmet = sorted(oid for oid, ok in results.items() if not ok)
    if not unmet:
        status, gap = "met", "all %d objectives satisfied by configuration facts" % len(results)
    elif len(unmet) < len(results):
        status, gap = "partially-met", "unsatisfied by configuration facts: " + ", ".join(unmet)
    else:
        status, gap = "not-met", "no objectives satisfied by configuration facts"
    return {"status": status, "unmet_objective_ids": unmet, "gap_summary": gap,
            "method": "deterministic"}
