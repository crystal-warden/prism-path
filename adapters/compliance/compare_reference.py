#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Differential: gemma's dispositions vs agy's independent determinations on the IDENTICAL bundles.
Agreement validates the adjudicator; disagreements (esp. gemma stricter than agy) are the calibration
boundary and route to the HITL review queue. Neither is ground truth — this is a model-vs-model
differential, which is the honest signal available without a credentialed human assessor."""
import os, json, collections
HERE = os.path.dirname(os.path.abspath(__file__))
from adapters.compliance import compliance_adapter as ca

STAT = ["met", "partially-met", "not-met"]
REF = os.path.join(HERE, "efficacy", "reference", "verdicts")


def main():
    gem = {row["control"]: row["disposition"] for row in
           json.load(open(os.path.join(HERE, "efficacy", "company_report.json")))["rows"]}
    if not os.path.isdir(REF) or not os.listdir(REF):
        print(json.dumps({"error": "no agy verdicts yet in " + REF})); return
    agy = {}
    for filename in os.listdir(REF):
        if filename.endswith(".json"):
            result = json.load(open(os.path.join(REF, filename)))
            agy[result["control_id"]] = result
    rows, conf, disagree = [], collections.Counter(), []
    for cid in sorted(gem):
        gemma_status = gem[cid]
        agy_status = agy.get(cid, {}).get("status", "MISSING")
        conf[(gemma_status, agy_status)] += 1
        agree = gemma_status == agy_status
        row = {"control": cid, "gemma": gemma_status, "agy": agy_status, "agree": agree,
               "agy_rationale": agy.get(cid, {}).get("rationale", "")}
        rows.append(row)
        if not agree:
            disagree.append(row)
    row_count = len(rows); agreed = sum(row["agree"] for row in rows)
    # "gemma stricter" = gemma not-met/partial where agy is more lenient
    order = {"not-met": 0, "partially-met": 1, "met": 2}
    gemma_stricter = [row for row in disagree if order.get(row["gemma"], 0) < order.get(row["agy"], 0)]
    report = {
        "n": row_count, "agreement": round(agreed / row_count, 3),
        "gemma_distribution": dict(collections.Counter(gem.values())),
        "agy_distribution": dict(collections.Counter(result["status"] for result in agy.values())),
        "confusion_gemma_x_agy": {f"g:{gemma_status}|a:{agy_status}": conf[(gemma_status, agy_status)]
                                  for gemma_status in STAT for agy_status in STAT
                                  if conf[(gemma_status, agy_status)]},
        "n_disagreements": len(disagree),
        "n_gemma_stricter": len(gemma_stricter),
        "disagreements": disagree,
        "interpretation": ("If agy's distribution ~ gemma's (both mostly not-met citing the same "
                           "draft/thin evidence), the adjudicator is corroborated. If agy is materially "
                           "more lenient (gemma_stricter high), that is a real over-strictness calibration "
                           "gap; those controls are the HITL review queue. Model-vs-model, not certified."),
    }
    json.dump(report, open(os.path.join(HERE, "efficacy", "reference", "comparison.json"), "w"), indent=1)
    # close the loop: send disagreements to the HITL/Deferral port
    ca.use_standard("nist_800171_r2")
    for disagreement in disagree:
        try:
            control = ca.get_control(disagreement["control"])
            ca.defer_for_review(control, {"control_id": disagreement["control"], "boundary": "Meridian", "evidence": []},
                                {"status": disagreement["gemma"], "unmet_objective_ids": [], "gap_summary": "efficacy differential"},
                                reason=f"gemma={disagreement['gemma']} vs agy={disagreement['agy']}")
        except Exception:
            pass
    print(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
