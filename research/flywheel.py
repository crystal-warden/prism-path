#!/usr/bin/env python3
"""Learning flywheel (task #38): wire AUTHORITATIVE reference dispositions into the prefilter cache
and propose suppression rules from repeated benign patterns — the mechanical basis for "gets cheaper
and better as it runs."

SAFETY (load-bearing): learn ONLY the REFERENCE disposition (human in pilot / authoritative oracle),
NEVER PrismPath's own — feeding self-labels reinforces the over-call bias the paper's prefilter guards
against. Dry-run / second-opinion feeds NOTHING. Never auto-promotes to HARD suppression — proposes
CONTEXT rules only; a human promotes. Two consumers: the prefilter cache (demand lever) and the
per-tenant suppression layer (#44) via suppression.propose_rule().
"""
import sys
sys.path.insert(0, "/home/cwadmin/cwprojects")
from prismpath import suppression  # NOTE: `suppression` was not migrated from the pre-rename codebase; port it before running this script

AUTHORITATIVE = {"human", "authoritative_oracle"}
BENIGN = {"ignore", "watch"}

def _doc(a):
    return (f"description: {a.get('description','')} | agent: {a.get('agent','')} | "
            f"srcip: {a.get('srcip') or 'none'} | mitre: {a.get('mitre') or 'n/a'} | rule_id: {a.get('rule_id','')}")
def _key(a):
    return f"{a.get('rule_id','')}|{a.get('agent','')}|{a.get('srcip') or 'none'}"

def learn(alert, disposition, source, confidence, cache, policy_hash=None,
          pattern_state=None, suppress_after=5, propose_sink=None):
    """Wire ONE authoritative disposition into the flywheel.
    -> {learned, proposed_rule, refused}."""
    if source not in AUTHORITATIVE:
        return {"learned": False, "proposed_rule": None,
                "refused": f"non-authoritative source '{source}' — never learn self/dry-run labels"}
    cache.learn(_doc(alert), disposition, float(confidence),
                key=_key(alert), description=alert.get("description",""), policy_hash=policy_hash)
    proposed = None
    if pattern_state is not None and disposition in BENIGN:
        pat = (str(alert.get("rule_id")), alert.get("agent") or "*")
        pattern_state[pat] = pattern_state.get(pat, 0) + 1
        if pattern_state[pat] == suppress_after:   # propose once, at the threshold
            proposed = suppression.propose_rule(
                pat[0], disposition,
                note=f"auto-proposed: {source} dispositioned this benign {suppress_after}x",
                agent=(None if pat[1] == "*" else pat[1]), kind="context")
            if propose_sink is not None:
                propose_sink(proposed)
    return {"learned": True, "proposed_rule": proposed, "refused": None}
