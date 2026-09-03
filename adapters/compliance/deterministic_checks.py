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

Each check is a pure predicate over that dict returning True (objective satisfied), False (refuted),
or None (undeterminable). Extend CHECKS as connectors learn to emit more facts. This first cut seeds
the canonical technical-configuration controls whose every 800-171A objective is decidable from
configuration; procedural and operational objectives stay with the LLM adjudicator.
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


# objective id -> predicate(facts) -> True | False | None
CHECKS = {
    # 3.13.11 Employ FIPS-validated cryptography to protect the confidentiality of CUI
    "3.13.11[a]": lambda f: _flag(f, "fips_validated_cryptography"),

    # 3.1.8 Limit unsuccessful logon attempts
    "3.1.8[a]": lambda f: _defined(f, "account_lockout_threshold"),
    "3.1.8[b]": lambda f: _flag(f, "account_lockout_enforced"),

    # 3.5.8 Prohibit password reuse for a specified number of generations
    "3.5.8[a]": lambda f: _defined(f, "password_history_count"),
    "3.5.8[b]": lambda f: _flag(f, "password_history_enforced"),

    # 3.1.11 Terminate (automatically) a user session after a defined condition
    "3.1.11[a]": lambda f: _flag(f, "session_termination_conditions_defined"),
    "3.1.11[b]": lambda f: _flag(f, "session_auto_termination_enforced"),

    # 3.1.10 Use session lock with pattern-hiding displays after a period of inactivity
    "3.1.10[a]": lambda f: _defined(f, "session_lock_timeout_seconds"),
    "3.1.10[b]": lambda f: _flag(f, "session_lock_enforced"),
    "3.1.10[c]": lambda f: _flag(f, "session_lock_pattern_hiding"),

    # 3.5.7 Enforce a minimum password complexity and change of characters
    "3.5.7[a]": lambda f: _flag(f, "password_complexity_defined"),
    "3.5.7[b]": lambda f: _flag(f, "password_change_of_char_defined"),
    "3.5.7[c]": lambda f: _flag(f, "password_complexity_enforced"),
    "3.5.7[d]": lambda f: _flag(f, "password_change_of_char_enforced"),

    # 3.5.3 Multifactor authentication for local/network access to privileged accounts and network
    # access to non-privileged accounts
    "3.5.3[a]": lambda f: _flag(f, "privileged_accounts_identified"),
    "3.5.3[b]": lambda f: _flag(f, "mfa_local_privileged"),
    "3.5.3[c]": lambda f: _flag(f, "mfa_network_privileged"),
    "3.5.3[d]": lambda f: _flag(f, "mfa_network_nonprivileged"),
}


def machine_checkable(control) -> bool:
    """True when every objective of the control has a registered deterministic check."""
    objs = control.get("objectives", [])
    return bool(objs) and all(o["id"] in CHECKS for o in objs)


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
