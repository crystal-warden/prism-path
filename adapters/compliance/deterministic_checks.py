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
