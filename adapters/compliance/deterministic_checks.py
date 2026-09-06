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

    # 3.3.1 Create and retain audit logs. Only [c] "audit records are created" is config-decidable
    # (a running audit daemon generates records); the event-selection, content, and retention objectives
    # are organization-defined and stay with the documented and operational mechanisms.
    "3.3.1[c]": ("flag", "audit_logging_enabled"),

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

    # --- NIST 800-171 R2 config-coverage extension ---
    # Objectives an OS/network scan can decide from real configuration. Each fact is emitted by a
    # connector only after verifying it reflects actual enforcement; the companion identify/define
    # objectives stay with the documented (policy) mechanism, and objectives that need network
    # boundary monitoring (e.g. 3.13.1[c][d]) are intentionally NOT claimed until that is in place.
    "3.1.1[d]": ("flag", "access_enforcement_configured"),
    "3.1.1[e]": ("flag", "access_enforcement_configured"),
    "3.1.1[f]": ("flag", "access_enforcement_configured"),
    "3.1.2[b]": ("flag", "least_privilege_enforced"),
    "3.5.1[a]": ("flag", "unique_identification_configured"),
    "3.5.1[b]": ("flag", "unique_identification_configured"),
    "3.5.1[c]": ("flag", "unique_identification_configured"),
    "3.4.2[b]": ("flag", "config_baseline_enforced"),
    "3.13.1[e]": ("flag", "boundary_control_enforced"),
    "3.13.1[f]": ("flag", "boundary_control_enforced"),
    "3.13.1[g]": ("flag", "boundary_protection_enforced"),
    "3.13.1[h]": ("flag", "boundary_protection_enforced"),
    "3.14.1[b]": ("flag", "flaw_remediation_automated"),
    "3.14.1[f]": ("flag", "flaw_remediation_automated"),
    "3.3.2[b]": ("flag", "audit_trace_to_user"),
    "3.8.2[a]": ("flag", "cui_media_access_limited"),
    # (3.8.8[a] is correctly mapped above to unowned_portable_storage_prohibited, not re-mapped here)
    # define/identify objectives evidenced by the actual system config (the ruleset IS the definition):
    "3.1.1[a]": ("flag", "unique_identification_configured"),
    "3.1.1[b]": ("flag", "unique_identification_configured"),
    "3.1.1[c]": ("flag", "unique_identification_configured"),
    "3.1.2[a]": ("flag", "least_privilege_enforced"),
    "3.3.1[a]": ("flag", "audit_events_defined"),
    "3.3.1[b]": ("flag", "audit_events_defined"),
    "3.3.1[e]": ("flag", "audit_retention_defined"),
    "3.3.2[a]": ("flag", "audit_events_defined"),
    "3.4.2[a]": ("flag", "config_baseline_established"),
    "3.13.1[a]": ("flag", "boundary_defined"),
    "3.13.1[b]": ("flag", "boundary_defined"),
    "3.14.1[a]": ("flag", "flaw_remediation_automated"),
    # remote access, transmission, unauthorized-use monitoring (enforce objectives; define go to policy):
    "3.1.12[c]": ("flag", "remote_access_controlled"),
    "3.1.12[d]": ("flag", "remote_access_controlled"),
    "3.1.13[b]": ("flag", "remote_access_encrypted"),
    "3.13.8[c]": ("flag", "transmission_confidentiality_enforced"),
    "3.14.7[b]": ("flag", "unauthorized_use_monitored"),
    # audit-family + access-model enforce objectives (verified config; define go to policy):
    "3.1.6[b]": ("flag", "nonprivileged_use_enforced"),
    "3.1.7[c]": ("flag", "privileged_execution_controlled"),
    "3.1.7[d]": ("flag", "privileged_execution_controlled"),
    "3.3.4[c]": ("flag", "audit_failure_alerting"),
    "3.3.6[a]": ("flag", "audit_reduction_reporting"),
    "3.3.6[b]": ("flag", "audit_reduction_reporting"),
    "3.3.8[a]": ("flag", "audit_info_protected"),
    "3.3.8[b]": ("flag", "audit_info_protected"),
    "3.3.8[c]": ("flag", "audit_info_protected"),
    "3.3.8[d]": ("flag", "audit_info_protected"),
    "3.3.8[e]": ("flag", "audit_info_protected"),
    "3.3.8[f]": ("flag", "audit_info_protected"),
    "3.3.9[b]": ("flag", "audit_management_restricted"),
    "3.13.3[c]": ("flag", "nonprivileged_use_enforced"),
    "3.13.4[a]": ("flag", "shared_resource_isolation"),
    "3.13.5[a]": ("flag", "no_public_components"),
    "3.13.5[b]": ("flag", "no_public_components"),
    "3.4.9[b]": ("flag", "user_software_controlled"),
    "3.4.9[c]": ("flag", "user_software_controlled"),
    # flow control, remote-access routing, external connections, key mgmt, mobile code, remote maint:
    "3.1.3[e]": ("flag", "cui_flow_enforced"),
    "3.1.14[a]": ("flag", "remote_access_controlled"),
    "3.1.14[b]": ("flag", "remote_access_controlled"),
    "3.1.15[c]": ("flag", "remote_access_controlled"),
    "3.1.20[c]": ("flag", "external_connections_controlled"),
    "3.1.20[e]": ("flag", "external_connections_controlled"),
    "3.1.20[f]": ("flag", "external_connections_controlled"),
    "3.13.10[a]": ("flag", "crypto_keys_managed"),
    "3.13.10[b]": ("flag", "crypto_keys_managed"),
    "3.13.13[a]": ("flag", "mobile_code_controlled"),
    "3.13.13[b]": ("flag", "mobile_code_controlled"),
    "3.7.5[a]": ("flag", "remote_access_controlled"),
    "3.7.5[b]": ("flag", "session_auto_termination_enforced"),
    # least functionality (3.4.6/3.4.7): define objectives credit from the documented
    # essential-capabilities baseline; enforce objectives require nonessential services off.
    "3.4.6[a]": ("flag", "essential_capabilities_defined"),
    "3.4.6[b]": ("flag", "least_functionality_enforced"),
    "3.4.7[a]": ("flag", "essential_capabilities_defined"),
    "3.4.7[b]": ("flag", "essential_capabilities_defined"),
    "3.4.7[c]": ("flag", "least_functionality_enforced"),
    "3.4.7[d]": ("flag", "essential_capabilities_defined"),
    "3.4.7[e]": ("flag", "essential_capabilities_defined"),
    "3.4.7[f]": ("flag", "least_functionality_enforced"),
    "3.4.7[g]": ("flag", "essential_capabilities_defined"),
    "3.4.7[h]": ("flag", "essential_capabilities_defined"),
    "3.4.7[i]": ("flag", "least_functionality_enforced"),
    "3.4.7[j]": ("flag", "essential_capabilities_defined"),
    "3.4.7[k]": ("flag", "essential_capabilities_defined"),
    "3.4.7[l]": ("flag", "least_functionality_enforced"),
    "3.4.7[m]": ("flag", "essential_capabilities_defined"),
    "3.4.7[n]": ("flag", "essential_capabilities_defined"),
    "3.4.7[o]": ("flag", "least_functionality_enforced"),
    # software execution control (3.4.8): allow/deny policy documented; enforcement via
    # signed-repo-only installs, non-privileged users, AppArmor, and noexec shared memory.
    "3.4.8[a]": ("flag", "software_execution_policy_defined"),
    "3.4.8[b]": ("flag", "software_execution_policy_defined"),
    "3.4.8[c]": ("flag", "unauthorized_software_prevented"),
    # boundary + attack monitoring (Zeek sensor on the enclave segment -> Wazuh SIEM):
    "3.13.1[c]": ("flag", "boundary_monitoring_enforced"),
    "3.13.1[d]": ("flag", "boundary_monitoring_enforced"),
    "3.14.6[a]": ("flag", "attack_monitoring_enforced"),
    "3.14.6[b]": ("flag", "attack_monitoring_enforced"),
    "3.14.6[c]": ("flag", "attack_monitoring_enforced"),
    # baseline + inventory establishment (maintenance objectives [c][f] come from operational review):
    "3.4.1[a]": ("flag", "config_baseline_established"),
    "3.4.1[b]": ("flag", "config_baseline_established"),
    "3.4.1[d]": ("flag", "system_inventory_established"),
    "3.4.1[e]": ("flag", "system_inventory_established"),
    # defined audit-review process ([b][c] come from operational audit-log-review):
    "3.3.3[a]": ("flag", "audit_review_process_defined"),
    # vulnerability identification ([b] remediation comes from operational flaw-remediation):
    "3.11.3[a]": ("flag", "vuln_identification_enforced"),
    # publicly-accessible content control ([d] review comes from operational public-content-review):
    "3.1.22[a]": ("flag", "public_content_controlled"),
    "3.1.22[b]": ("flag", "public_content_controlled"),
    "3.1.22[c]": ("flag", "public_content_controlled"),
    "3.1.22[e]": ("flag", "public_content_controlled"),
    # authentication (3.5.2): users via MFA, processes via authenticated user context,
    # devices via console-only management (no network device access path):
    "3.5.2[a]": ("flag", "user_authentication_enforced"),
    "3.5.2[b]": ("flag", "process_authentication_verified"),
    "3.5.2[c]": ("flag", "network_device_access_disabled"),
    # security architecture + engineering (3.13.2): documented designs/techniques/principles employed
    "3.13.2[a]": ("flag", "security_architecture_employed"),
    "3.13.2[b]": ("flag", "security_architecture_employed"),
    "3.13.2[c]": ("flag", "security_architecture_employed"),
    "3.13.2[d]": ("flag", "security_architecture_employed"),
    "3.13.2[e]": ("flag", "security_architecture_employed"),
    "3.13.2[f]": ("flag", "security_architecture_employed"),
    # flaw-remediation report/correct timeframes (3.14.1[a][b][f] already covered):
    "3.14.1[c]": ("flag", "flaw_timeframes_defined"),
    "3.14.1[d]": ("flag", "flaws_reported_enforced"),
    "3.14.1[e]": ("flag", "flaw_timeframes_defined"),
    # security alerts/advisories (3.14.3): [b] monitored via operational security-advisories-review
    "3.14.3[a]": ("flag", "security_advisory_response_defined"),
    "3.14.3[c]": ("flag", "security_advisory_actions_taken"),
    # media sanitization (3.8.3): LUKS cryptographic erase per NIST SP 800-88
    "3.8.3[a]": ("flag", "media_sanitization_defined"),
    "3.8.3[b]": ("flag", "media_sanitization_defined"),
    # personnel action / access termination + transfer protection (3.9.2)
    "3.9.2[a]": ("flag", "personnel_action_process_defined"),
    "3.9.2[b]": ("flag", "personnel_action_process_defined"),
    "3.9.2[c]": ("flag", "personnel_action_process_defined"),
}


def _make_check(kind, key):
    fn = _KINDS[kind]
    return lambda facts: fn(facts, key)


# objective id -> predicate(facts) -> True | False | None
CHECKS = {oid: _make_check(kind, key) for oid, (kind, key) in CHECK_SPEC.items()}
# objective id -> the fact key it reads (what a scanner adapter must supply)
FACT_KEYS = {oid: key for oid, (_kind, key) in CHECK_SPEC.items()}

# --- Evidence provenance (the cause-code layer, ported from the fabric receipt) ---
# A deterministic verdict is only as trustworthy as HOW its fact was evidenced. Every fact carries an
# evidence class so a determination receipt discloses its provenance, the way the interpreter fabric
# stamps a cause byte per evaluate (supporting-evidence #129/#130). Two classes here:
#   "scanned"  - a tool/command reads the running configuration (services, ports, PAM, crypto, firewall,
#                kernel, processes). Independently verifiable; the strongest deterministic evidence.
#   "attested" - the organization asserts the fact, backed by a policy/plan/register/inventory that a
#                scanner cannot read. Deterministic given the posture, but an assessor must verify the
#                backing document. NOT tool-verifiable, and the receipt says so.
# (Operational evidence - a recurring task actually performed - is the control_tasks mechanism, not here.)
# Default is "scanned"; the ATTESTED set below is the honest minority that rests on documentation.
ATTESTED_FACTS = frozenset({
    # organizational programs, plans, and architecture (documented, not scannable)
    "security_architecture_employed", "personnel_action_process_defined", "media_sanitization_defined",
    "essential_capabilities_defined", "software_execution_policy_defined", "config_baseline_established",
    "system_inventory_established", "audit_review_process_defined", "flaw_timeframes_defined",
    "security_advisory_response_defined", "security_advisory_actions_taken", "public_content_controlled",
    "identifier_reuse_prohibited_days", "identifier_reuse_prevention_enforced", "flaws_reported_enforced",
    "session_termination_conditions_defined", "crypto_keys_managed", "mobile_code_controlled",
    "no_public_components", "shared_resource_isolation",
    # AI-governance inventories and classifications (org-maintained records, not scannable)
    "ai_data_inventory_exists", "ai_process_inventory_exists", "ai_user_inventory_exists",
    "ai_vendor_inventory_exists", "ai_decision_impact_classified", "ai_high_risk_uses_tiered",
    "ai_prohibited_data_controls_enforced", "approved_ai_tools_list_exists",
    "unapproved_ai_tool_use_controlled",
})


def evidence_class(objective_id) -> Optional[str]:
    """The evidence class of the fact backing an objective's check: 'scanned' (tool-verifiable) or
    'attested' (documentation-backed). None if the objective has no registered check."""
    key = FACT_KEYS.get(objective_id)
    if key is None:
        return None
    return "attested" if key in ATTESTED_FACTS else "scanned"


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


def check_objectives_typed(control, facts) -> dict:
    """Like check_objectives but each decided objective carries its evidence provenance:
    {objective_id: {"met": bool, "evidence": "scanned"|"attested"}}."""
    return {oid: {"met": met, "evidence": evidence_class(oid)}
            for oid, met in check_objectives(control, facts).items()}


def _evidence_rollup(objective_ids) -> dict:
    """Summarize the evidence provenance across a determination's objectives: the per-class objective
    lists and a single rollup class (weakest-link: 'attested' if any objective rests on attestation)."""
    by_class = {}
    for oid in objective_ids:
        by_class.setdefault(evidence_class(oid) or "unknown", []).append(oid)
    if "attested" in by_class and len(by_class) > 1:
        rollup = "mixed"
    elif "attested" in by_class:
        rollup = "attested"
    else:
        rollup = "scanned"
    return {"class": rollup, "by_class": {k: sorted(v) for k, v in by_class.items()}}


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
            "method": "deterministic", "evidence": _evidence_rollup(results.keys())}
