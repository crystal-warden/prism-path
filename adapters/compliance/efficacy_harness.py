#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Efficacy harness (#72): run the gemma adjudicator against the agy-generated held-out corpus and
measure AGREEMENT with agy's reference labels — by difficulty and by method profile — then route every
disagreement into the HITL/Deferral review queue.

HONEST FRAMING: agy's label is a PROXY oracle (an independent, stronger model), NOT human-certified
ground truth. This measures gemma-vs-agy agreement, which is a differential/difficulty signal and a
human-review trigger — not a certification of correctness. A ~100% agreement is a RED FLAG (corpus too
easy or leakage); the expected, healthy shape is high on 'easy', lower on 'hard'.
"""
import os, json, collections
HERE = os.path.dirname(os.path.abspath(__file__))
from adapters.compliance import compliance_adapter as ca

ca.use_standard("nist_800171_r2")
CORPUS = os.path.join(HERE, "efficacy", "corpus")
STATUSES = ["met", "partially-met", "not-met"]


def load_bundles():
    out = []
    for filename in sorted(os.listdir(CORPUS)):
        if filename.endswith(".json") and not filename.startswith("_"):
            try:
                bundle = json.load(open(os.path.join(CORPUS, filename)))
                if bundle.get("control_id") and bundle.get("_label", {}).get("status"):
                    bundle["_file"] = filename
                    out.append(bundle)
            except Exception as error:
                print("skip malformed", filename, error)
    return out


def main():
    bundles = load_bundles()
    if not bundles:
        print(json.dumps({"error": "no corpus bundles found in " + CORPUS})); return
    rows, confusion = [], collections.Counter()
    by_diff = collections.defaultdict(lambda: [0, 0])       # difficulty -> [agree, total]
    by_prof = collections.defaultdict(lambda: [0, 0])
    disagreements = []
    for bundle in bundles:
        control = ca.get_control(bundle["control_id"])
        det = ca.adjudicate(control, bundle)
        ref = bundle["_label"]["status"]
        diff = bundle["_label"].get("difficulty", "?")
        prof = ca._method_profile(control)
        gem = det["status"] if det else "ERROR"
        agree = (gem == ref)
        confusion[(ref, gem)] += 1
        by_diff[diff][0] += int(agree); by_diff[diff][1] += 1
        by_prof[prof][0] += int(agree); by_prof[prof][1] += 1
        row = {"file": bundle["_file"], "control": bundle["control_id"], "difficulty": diff, "profile": prof,
               "agy_ref": ref, "gemma": gem, "agree": agree, "trap": bundle["_label"].get("trap", "")}
        rows.append(row)
        if not agree and det is not None:
            # close the loop: a disagreement is exactly what the HITL/Deferral port is for
            ca.defer_for_review(control, bundle, det, reason=f"efficacy disagreement: agy_ref={ref} gemma={gem}")
            disagreements.append({**row, "agy_rationale": bundle["_label"].get("rationale", ""),
                                  "decisive_objective": bundle["_label"].get("decisive_objective_id", "")})

    row_count = len(rows); agreed = sum(row["agree"] for row in rows)
    report = {
        "n_bundles": row_count,
        "overall_agreement": round(agreed / row_count, 3),
        "agreement_by_difficulty": {difficulty: {"agree": agree_count, "total": total_count, "rate": round(agree_count / total_count, 3)}
                                    for difficulty, (agree_count, total_count) in sorted(by_diff.items())},
        "agreement_by_profile": {profile: {"agree": agree_count, "total": total_count, "rate": round(agree_count / total_count, 3)}
                                 for profile, (agree_count, total_count) in sorted(by_prof.items())},
        "confusion_ref_x_gemma": {f"{reference_status}->{gemma_status}": confusion[(reference_status, gemma_status)]
                                  for reference_status in STATUSES for gemma_status in STATUSES
                                  if confusion[(reference_status, gemma_status)]},
        "n_disagreements_routed_to_hitl": len(disagreements),
        "caveat": ("Agreement with agy PROXY labels (independent model), not human-certified accuracy. "
                   "Disagreements are routed to the HITL/Deferral review queue, not scored as gemma-wrong."),
    }
    os.makedirs(os.path.join(HERE, "efficacy"), exist_ok=True)
    json.dump({"report": report, "rows": rows}, open(os.path.join(HERE, "efficacy", "report.json"), "w"), indent=1)
    json.dump(disagreements, open(os.path.join(HERE, "efficacy", "review_queue.json"), "w"), indent=1)
    print(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
