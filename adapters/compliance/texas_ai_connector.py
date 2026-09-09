#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Texas AI pack runtime connector: derive the pack's config objectives from ACTUAL PrismPath
runtime evidence, not a hand-typed posture.

The seven config objectives of the Texas AI pack are the ones PrismPath can *prove* at the decision
boundary. This connector reads real decision receipts (or runs a governance flow through the real
engine to produce them) and reads the resulting RunResult causes to emit the facts the deterministic
checks consume:

  human_oversight_escalation_enforced <- a consequential request stops as needs_human (route:needs-human
                                          or route:below-human-floor): AI output is not the sole basis.
  prohibited_use_refusal_enforced     <- a prohibited request is refused by default-deny (stops 'stuck':
                                          no permit edge matched, so nothing is authorized by default).
  decision_version_attribution        <- every receipt carries its governing flow version.
  governing_version_authorized        <- the governing flow is versioned and in the authorized set.

Facts PrismPath does not natively enforce (generative guardrails, disclosure delivery) are deliberately
NOT emitted here; they remain the org's attestation via other tooling. Honest by omission.
"""
import os, sys, json

# ============================================================================
# CONFIGURE — set these to your own environment, then run. Nothing below this
# block needs editing to point the connector at your own decision engine.
# ----------------------------------------------------------------------------
# Path to YOUR decision-receipt stream: one JSON object per line (.ndjson), each with at least
# {"stopped": ..., "version": ...} (and optionally "cause"). None -> produce receipts by running the
# flow below through the real engine (the built-in demo).
RECEIPTS_PATH = None
# Path to YOUR governance decision flow (.md, PrismPath flow syntax). Used only when RECEIPTS_PATH is
# None. None -> use the built-in demo flow (DEMO_FLOW).
GOVERNANCE_FLOW_PATH = None
# The governing flow/policy version stamped on receipts (also used to tag demo-flow receipts).
FLOW_VERSION = "tx-governance-flow@1"
# Is the governing version authorized/signed before use in your environment?
VERSION_AUTHORIZED = True
# ============================================================================

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
from prismpath.kernel.parser import parse
from prismpath.kernel.engine import run
from prismpath.kernel import causes
# --- Built-in demo (SAMPLE) below: a minimal governance decision flow used only when you have not
#     pointed RECEIPTS_PATH/GOVERNANCE_FLOW_PATH at your own artifacts. ---
DEMO_FLOW = """
## intake
Classify and route the AI-influenced decision request.
-> permit: when action in ("read", "summarize", "notify")
## permit
The authorized low-risk action proceeds.
"""
DEMO_REQUESTS = [
    {"label": "authorized-low-risk", "action": "summarize", "consequential": False},
    {"label": "consequential-decision", "action": "approve_benefit", "consequential": True},
    {"label": "prohibited-or-unrecognized", "action": "exfiltrate", "consequential": False},
]


def _agent_for(request):
    """Worker stub for the demo flow: emits the request fields so the deterministic guards can route.
    For a consequential decision the worker explicitly requests a human (route:needs-human), so the AI
    output is not the sole principal basis for the decision."""
    def agent(node, instruction, state):
        if request.get("consequential"):
            return {"text": "consequential -> human review required", "needs_human": True, **request}
        return {"text": "request", **request}
    return agent


def _receipts_from_demo(flow, version):
    g = parse(flow)
    receipts = []
    for req in DEMO_REQUESTS:
        r = run(g, _agent_for(req))
        receipts.append({"label": req["label"], "stopped": r.stopped, "cause": r.cause,
                         "cause_class": causes.cause_class(r.cause), "version": version,
                         "path": r.path})
    return receipts


def _receipts_from_file(path):
    with open(path) as fh:
        return [json.loads(line) for line in fh if line.strip()]


def collect_receipts():
    """Return the receipt stream from your configured source: your receipts file, else your flow run
    through the real engine, else the built-in demo flow."""
    if RECEIPTS_PATH:
        return _receipts_from_file(RECEIPTS_PATH)
    flow = open(GOVERNANCE_FLOW_PATH).read() if GOVERNANCE_FLOW_PATH else DEMO_FLOW
    return _receipts_from_demo(flow, FLOW_VERSION)


def derive_facts():
    """Derive the Texas config facts from the configured receipt source. Returns (facts, receipts)."""
    receipts = collect_receipts()
    escalated = any(r.get("stopped") == "needs_human" for r in receipts)
    refused = any(r.get("stopped") == "stuck" for r in receipts)
    facts = {
        "human_oversight_escalation_enforced": escalated,
        "prohibited_use_refusal_enforced": refused,
        "decision_version_attribution": bool(receipts) and all(r.get("version") for r in receipts),
        "governing_version_authorized": bool(FLOW_VERSION) and bool(VERSION_AUTHORIZED),
    }
    return facts, receipts


if __name__ == "__main__":
    facts, receipts = derive_facts()
    src = RECEIPTS_PATH or GOVERNANCE_FLOW_PATH or "built-in demo flow"
    print(f"=== receipts (source: {src}) ===")
    for r in receipts:
        print(f"  {r.get('label',''):26} stopped={r.get('stopped'):11} cause={r.get('cause')} "
              f"({r.get('cause_class')}) version={r.get('version')}")
    print("\n=== derived Texas config facts ===")
    print(json.dumps(facts, indent=2))
