#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Texas AI Governance Pack demo, end to end: the config facts are DERIVED from real PrismPath
engine runs (texas_ai_connector), not a hand-typed posture. Shows, for two actors:

  1. The release notice (review assistance, not validated).
  2. Real engine receipts and the config facts they prove (oversight escalation, prohibited-use
     refusal by default-deny, version attribution, version authorization).
  3. Applicability scoping: a commercial deployer is graded against far fewer controls than a
     governmental entity, with the rest Not Applicable and justified.
  4. Which config objectives PrismPath PROVES at the boundary vs. which remain org-attested.

Run:  python adapters/compliance/demo_texas_ai.py
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import compliance_adapter as ca
import deterministic_checks as dc
import texas_ai_connector as tx


def _config_objs(control):
    return [o["id"] for o in control["objectives"] if o["mechanism"] == "config"]


def print_actor(actor, facts):
    appl = ca.applicability_determination(actor)
    print(f"\n{'='*76}\nACTOR: {actor}   applicable={appl['counts']['applicable']}  "
          f"N/A(out of scope)={appl['counts']['not_applicable']}")
    if appl["not_applicable"]:
        ex = appl["not_applicable"][0]
        print(f"  e.g. {ex['control_id']}: {ex['reason']}")
    proven, attested = [], []
    for cid in appl["applicable"]:
        c = ca.get_control(cid)
        decided = dc.check_objectives(c, facts)
        for oid in _config_objs(c):
            (proven if decided.get(oid) is True else attested).append(oid)
    print(f"  config objectives ENGINE-PROVEN: {proven}")
    print(f"  config objectives still ORG-ATTESTED (outside the decision control plane): {attested}")


if __name__ == "__main__":
    n = ca.use_standard("texas_ai") and None
    notice = ca.standard_notice()
    print("#" * 76)
    print(notice["notice"])
    print("#" * 76)

    facts, receipts = tx.derive_facts()
    print("\n=== real engine receipts (governance decision flow) ===")
    for r in receipts:
        print(f"  {r['label']:26} stopped={r['stopped']:11} cause={r['cause']}({r['cause_class']}) "
              f"ver={r['version']}")
    print("\n=== config facts derived from those receipts ===")
    for k, v in facts.items():
        print(f"  {k} = {v}")
    print("  (generative_guardrails_enforced, *_ai_disclosure_delivered are NOT engine-derived:")
    print("   they are outside the decision control plane and remain org-attested.)")

    for actor in ("commercial", "government"):
        print_actor(actor, facts)

    print(f"\n{'='*76}")
    print("End to end: engine run -> RunResult causes -> config facts -> applicability + assessment.")
    print("The four proven objectives are PrismPath enforcing governance at the decision boundary;")
    print("the rest of the pack resolves via documented policy and operational records.")
