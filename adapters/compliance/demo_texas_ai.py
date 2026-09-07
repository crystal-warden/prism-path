#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Texas AI Governance Pack demo: the same statute, two actors, two very different obligations.

Shows the pack's headline behavior:
  1. Applicability scoping - a commercial deployer is graded against far fewer controls than a
     governmental entity, and the rest are Not Applicable WITH a written justification (no actor is
     graded against provisions that do not bind it).
  2. The config-enforced differentiators - the objectives PrismPath can prove at the decision
     boundary (abstain/escalate, version-authorized, disclosure delivered), classed 'scanned',
     versus the documented/operational objectives every GRC tool can only describe.

Run:  python adapters/compliance/demo_texas_ai.py
No LLM required; this demo exercises the deterministic + applicability layers only.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import compliance_adapter as ca
import deterministic_checks as dc

# A sample runtime posture: the seven config facts the enforcement layer + signed receipts expose.
POSTURE = {
    "prohibited_use_refusal_enforced": True,
    "generative_guardrails_enforced": True,
    "healthcare_ai_disclosure_delivered": True,
    "consumer_ai_disclosure_delivered": True,
    "human_oversight_escalation_enforced": True,
    "governing_version_authorized": True,
    "decision_version_attribution": True,
}


def _obj_mechanisms(control):
    return [(o["id"], o["mechanism"]) for o in control["objectives"]]


def assess_actor(actor):
    ca.use_standard("texas_ai")
    appl = ca.applicability_determination(actor)
    rows = []
    for cid in appl["applicable"]:
        c = ca.get_control(cid)
        mechs = _obj_mechanisms(c)
        config_objs = [oid for oid, m in mechs if m == "config"]
        decided = dc.check_objectives(c, POSTURE)  # only config objectives resolve here
        enforced = [oid for oid in config_objs if decided.get(oid) is True]
        rows.append({
            "control": cid, "title": c["title"],
            "n_documented": sum(1 for _, m in mechs if m == "documented"),
            "n_operational": sum(1 for _, m in mechs if m == "operational"),
            "n_config": len(config_objs),
            "config_enforced": enforced,
        })
    return appl, rows


def print_actor(actor):
    appl, rows = assess_actor(actor)
    print(f"\n{'='*74}\nACTOR: {actor}   (standard: texas_ai)")
    print(f"  Applicable controls: {appl['counts']['applicable']}   "
          f"Not Applicable (out of statutory scope): {appl['counts']['not_applicable']}")
    if appl["not_applicable"]:
        ex = appl["not_applicable"][0]
        print(f"  e.g. N/A {ex['control_id']}: {ex['reason']}")
    tot_cfg = sum(r["n_config"] for r in rows)
    enf = sum(len(r["config_enforced"]) for r in rows)
    print(f"  Config (runtime-enforced) objectives in scope: {tot_cfg}   proven by posture: {enf}")
    print(f"  {'control':14}{'cfg':>4}{'op':>4}{'doc':>4}  runtime-enforced (proven at the boundary)")
    for r in rows:
        star = "  <-- differentiator" if r["config_enforced"] else ""
        print(f"  {r['control']:14}{r['n_config']:>4}{r['n_operational']:>4}{r['n_documented']:>4}  "
              f"{','.join(r['config_enforced']) or '-'}{star}")


if __name__ == "__main__":
    print("Texas AI Governance Pack - one statute, two actors, two obligation sets")
    for actor in ("commercial", "government"):
        print_actor(actor)
    print(f"\n{'='*74}")
    print("Takeaway: applicability is enforced (commercial is not graded on governmental provisions),")
    print("and the config objectives are the ones PrismPath proves at runtime, not just documents.")
    print("Documented/operational objectives resolve via the LLM adjudicator and task records; the")
    print("config objectives resolve deterministically from the enforcement layer + signed receipts.")
