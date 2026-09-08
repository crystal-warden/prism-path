#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Complete Texas AI Governance Pack assessment across all three planes, for the actor(s) you choose.

  applicability  -> which controls bind this actor (the rest N/A, justified)
  config plane   -> facts DERIVED from real PrismPath engine runs / your receipts (texas_ai_connector)
  operational    -> your performed-task records
  documented     -> the pack's policy templates, generated for your org

Every objective is scored by its declared mechanism, and its evidence provenance is reported. Output
is a per-actor verdict tally plus the review-assistance notice. Nothing here is a legal determination.

Run:  python adapters/compliance/assess_texas.py
"""
import os, sys, json, glob

# ============================================================================
# CONFIGURE — set these to your organization, then run. To point the config plane
# at your own decision engine, edit the CONFIGURE block in texas_ai_connector.py.
# ----------------------------------------------------------------------------
# Your organization profile (fills the generated policy templates).
ORG = {"org_name": "Example Org",
       "system_name": "the AI decision service",
       "boundary": "the AI decision boundary"}
# Path to YOUR operational-completions file: a JSON list of performed operational objective ids,
# e.g. ["TX-INV-1[b]", "TX-RISK-1[d]", ...]. None -> use the built-in SAMPLE set below.
OPERATIONAL_COMPLETIONS_PATH = None
# Which actor(s) to assess. Choose from the pack's actor types (commercial / healthcare /
# government / gov_vendor).
ACTORS = ("commercial", "government")
# Built-in SAMPLE operational record (used only when OPERATIONAL_COMPLETIONS_PATH is None).
# Deliberately not exhaustive, so the sample assessment shows honest partials rather than all-green.
SAMPLE_OPERATIONAL_PERFORMED = [
    "TX-PROHIB-2[b]", "TX-INV-1[b]", "TX-RISK-1[d]", "TX-RISK-2[b]",
    "TX-ACCT-1[b]", "TX-ACCT-2[b]", "TX-VEND-1[b]", "TX-SAFE-1[b]", "TX-OVS-1[c]",
]
# ============================================================================

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import compliance_adapter as ca
import deterministic_checks as dc
import sop_generator as sg
import texas_ai_connector as tx

_HERE = os.path.dirname(os.path.abspath(__file__))


def operational_performed():
    if OPERATIONAL_COMPLETIONS_PATH:
        return set(json.load(open(OPERATIONAL_COMPLETIONS_PATH)))
    return set(SAMPLE_OPERATIONAL_PERFORMED)


def documented_coverage():
    """Controls covered by a generated policy template (the documented plane)."""
    covered = set()
    for f in glob.glob(os.path.join(_HERE, "sop_specs", "texas_*.json")):
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


def assess_actor(actor, config_facts, documented, operational):
    ca.use_standard("texas_ai")
    appl = ca.applicability_determination(actor)
    tally = {"met": 0, "partially-met": 0, "not-met": 0, "not-applicable": appl["counts"]["not_applicable"]}
    rows = []
    for cid in appl["applicable"]:
        status, objs = assess_control(cid, config_facts, documented, operational)
        tally[status] += 1
        rows.append((cid, status, objs))
    return appl, tally, rows


def main():
    ca.use_standard("texas_ai")
    notice = ca.standard_notice()
    print("#" * 78); print(notice["notice"]); print("#" * 78)

    documented = documented_coverage()
    operational = operational_performed()
    print(f"\nDocumented plane: {len(documented)} controls covered by generated policy templates")
    print(f"Operational plane: {len(operational)} performed objective(s) "
          f"({'your file' if OPERATIONAL_COMPLETIONS_PATH else 'built-in sample'})")

    config_facts, receipts = tx.derive_facts()
    print(f"Config plane (engine-derived): {sum(1 for v in config_facts.values() if v)} facts proven "
          f"from {len(receipts)} receipt(s)")

    for actor in ACTORS:
        appl, tally, rows = assess_actor(actor, config_facts, documented, operational)
        print(f"\n{'='*78}\nACTOR: {actor}   {tally}")
        for cid, status, objs in rows:
            prov = ",".join(sorted({ev for _, ev in objs.values()}))
            print(f"    {cid:14} {status:14} [{prov}]")
    print(f"\n{'='*78}\nReview assistance only. Documented objectives shown as policy-provided still "
          "require\nadjudication of the policy content in production; counsel review is the gate.")


if __name__ == "__main__":
    main()
