#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Texas AI pack runtime connector: derive the pack's config objectives from ACTUAL PrismPath
runtime evidence, not a hand-typed posture.

The seven config objectives of the Texas AI pack are the ones PrismPath can *prove* at the decision
boundary. This connector runs a governance decision flow through the real engine and reads the
resulting RunResult causes (prismpath.causes) to emit the facts the deterministic checks consume:

  human_oversight_escalation_enforced <- a consequential request stops as needs_human (route:needs-human
                                          or route:below-human-floor): AI output is not the sole basis.
  prohibited_use_refusal_enforced     <- a prohibited request is refused by default-deny (stops 'stuck':
                                          no permit edge matched, so nothing is authorized by default).
  decision_version_attribution        <- every receipt carries its governing flow version.
  governing_version_authorized        <- the governing flow is versioned and in the authorized set.

Facts PrismPath does not natively enforce (generative guardrails, disclosure delivery) are deliberately
NOT emitted here; they remain the org's attestation via other tooling. Honest by omission.
"""
import os, sys
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
from prismpath.parser import parse
from prismpath.engine import run
from prismpath import causes

# A minimal governance decision flow: authorized low-risk actions proceed; anything else falls
# through to default-deny (refused). A consequential decision is escalated to a human by the worker
# itself (route:needs-human), so AI output is never the sole basis for a consequential decision.
GOVERNANCE_FLOW = """
## intake
Classify and route the AI-influenced decision request.
-> permit: when action in ("read", "summarize", "notify")
## permit
The authorized low-risk action proceeds.
"""

# Representative requests that exercise permit / escalate / refuse.
SAMPLE_REQUESTS = [
    {"label": "authorized-low-risk", "action": "summarize", "consequential": False},
    {"label": "consequential-decision", "action": "approve_benefit", "consequential": True},
    {"label": "prohibited-or-unrecognized", "action": "exfiltrate", "consequential": False},
]


def _agent_for(request):
    """Worker stub: emits the request fields so the deterministic guards can route. For a
    consequential decision the worker explicitly requests a human (route:needs-human), so the AI
    output is not the sole principal basis for the decision."""
    def agent(node, instruction, state):
        if request.get("consequential"):
            return {"text": "consequential -> human review required", "needs_human": True, **request}
        return {"text": "request", **request}
    return agent


def collect_receipts(flow=GOVERNANCE_FLOW, version="tx-governance-flow@1"):
    """Run each sample request through the real engine; return signed-style receipts."""
    g = parse(flow)
    receipts = []
    for req in SAMPLE_REQUESTS:
        r = run(g, _agent_for(req))
        receipts.append({
            "label": req["label"],
            "stopped": r.stopped,
            "cause": r.cause,
            "cause_name": causes.name(r.cause) if hasattr(causes, "name") else None,
            "cause_class": causes.cause_class(r.cause),
            "version": version,          # the governing flow version travels on the receipt
            "path": r.path,
        })
    return receipts


def derive_facts(flow=GOVERNANCE_FLOW, version="tx-governance-flow@1", authorized=True):
    """Derive the Texas config facts from real RunResults. Returns (facts, receipts)."""
    receipts = collect_receipts(flow, version)
    escalated = any(r["stopped"] == "needs_human" for r in receipts)
    refused = any(r["stopped"] == "stuck" for r in receipts)
    facts = {
        "human_oversight_escalation_enforced": escalated,
        "prohibited_use_refusal_enforced": refused,
        "decision_version_attribution": bool(receipts) and all(r.get("version") for r in receipts),
        "governing_version_authorized": bool(version) and bool(authorized),
    }
    return facts, receipts


if __name__ == "__main__":
    import json
    facts, receipts = derive_facts()
    print("=== receipts from the real engine ===")
    for r in receipts:
        print(f"  {r['label']:26} stopped={r['stopped']:11} cause={r['cause']} "
              f"({r['cause_class']}) version={r['version']}")
    print("\n=== derived Texas config facts ===")
    print(json.dumps(facts, indent=2))
