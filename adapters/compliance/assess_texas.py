#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Complete Texas AI Governance Pack assessment: the whole pack working across all three planes,
for a commercial deployer and a governmental entity.

  applicability  -> which controls bind this actor (the rest N/A, justified)
  config plane   -> facts DERIVED from real PrismPath engine runs (texas_ai_connector)
  operational    -> performed-task records (sample below)
  documented     -> the pack's policy templates, generated for the org

Every objective is scored by its declared mechanism, and its evidence provenance is reported
(engine-proven / operational-record / policy-provided). Output is a per-actor verdict tally plus the
review-assistance notice. Nothing here is a legal determination; see the notice.

Run:  python adapters/compliance/assess_texas.py
"""
import os, sys, json, glob
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import compliance_adapter as ca
import deterministic_checks as dc
import sop_generator as sg
import texas_ai_connector as tx

ORG = {"org_name": "Example Org", "system_name": "the AI decision service",
       "boundary": "the AI decision boundary"}

# A sample record of operational objectives this org has performed and evidenced. Deliberately not
# exhaustive: a couple are left open so the assessment shows honest partials, not all-green.
OPERATIONAL_PERFORMED = {
    "TX-PROHIB-2[b]", "TX-INV-1[b]", "TX-RISK-1[d]", "TX-RISK-2[b]",
    "TX-ACCT-1[b]", "TX-ACCT-2[b]", "TX-VEND-1[b]", "TX-SAFE-1[b]", "TX-OVS-1[c]",
    # left OPEN (not yet performed): TX-DISC-3[b], TX-CHG-1[b], TX-SAFE-2[b]
}


def documented_coverage():
    """Controls covered by a generated policy template (the documented plane)."""
    covered = set()
    for f in glob.glob(os.path.join(os.path.dirname(os.path.abspath(__file__)), "sop_specs", "texas_*.json")):
        covered |= set(json.load(open(f))["controls"])
    return covered


def assess_control(cid, config_facts, documented, operational):
    c = ca.get_control(cid)
    objs = {}
    for o in c["objectives"]:
        oid, mech = o["id"], o["mechanism"]
        if mech == "config":
            m = dc.check_objectives(c, config_facts).get(oid)
            ev = "engine-proven" if m is True else ("engine-refuted" if m is False else "not-derived(attested)")
        elif mech == "operational":
            m = oid in operational
            ev = "operational-record" if m else "no-record"
        else:
            m = cid in documented
            ev = "policy-provided" if m else "policy-needed"
        objs[oid] = (m, ev)
    vals = [m for m, _ in objs.values()]
    status = "met" if all(v is True for v in vals) else ("partially-met" if any(v is True for v in vals) else "not-met")
    return status, objs


def assess_actor(actor, config_facts, documented):
    ca.use_standard("texas_ai")
    appl = ca.applicability_determination(actor)
    tally = {"met": 0, "partially-met": 0, "not-met": 0, "not-applicable": appl["counts"]["not_applicable"]}
    rows = []
    for cid in appl["applicable"]:
        status, objs = assess_control(cid, config_facts, documented, OPERATIONAL_PERFORMED)
        tally[status] += 1
        rows.append((cid, status, objs))
    return appl, tally, rows


def main():
    ca.use_standard("texas_ai")
    notice = ca.standard_notice()
    print("#" * 78); print(notice["notice"]); print("#" * 78)

    # documented plane: confirm the policy templates actually generate for this org
    documented = documented_coverage()
    print(f"\nDocumented plane: {len(documented)} controls covered by generated policy templates "
          f"{sorted(documented)}")
    sample = sg.generate(json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
             "sop_specs", "texas_material_change_policy.json"))),
             {**ORG, "material_change_criteria": "a model version change, a new data source, or an "
              "expanded decision scope", "reassessment_owner": "the AI system owner"})
    print(f"  (sample generated policy '{sample['markdown'].splitlines()[0]}', "
          f"{len(sample['markdown'].splitlines())} lines, unanswered={sample['unanswered']})")

    # config plane: derive from the real engine
    config_facts, receipts = tx.derive_facts()
    print(f"\nConfig plane (engine-derived): {sum(1 for v in config_facts.values() if v)} facts proven "
          f"from {len(receipts)} real engine receipts")

    for actor in ("commercial", "government"):
        appl, tally, rows = assess_actor(actor, config_facts, documented)
        print(f"\n{'='*78}\nACTOR: {actor}")
        print(f"  {tally}")
        for cid, status, objs in rows:
            prov = ",".join(sorted({ev for _, ev in objs.values()}))
            print(f"    {cid:14} {status:14} [{prov}]")
    print(f"\n{'='*78}\nReview assistance only. Documented objectives shown as policy-provided still "
          "require\nLLM/human adjudication of the policy content in production; counsel review is the gate.")


if __name__ == "__main__":
    main()
