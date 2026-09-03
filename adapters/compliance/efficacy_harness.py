#!/usr/bin/env python3
"""Efficacy harness (#72): run the gemma adjudicator against the agy-generated held-out corpus and
measure AGREEMENT with agy's reference labels — by difficulty and by method profile — then route every
disagreement into the HITL/Deferral review queue.

HONEST FRAMING: agy's label is a PROXY oracle (an independent, stronger model), NOT human-certified
ground truth. This measures gemma-vs-agy agreement, which is a differential/difficulty signal and a
human-review trigger — not a certification of correctness. A ~100% agreement is a RED FLAG (corpus too
easy or leakage); the expected, healthy shape is high on 'easy', lower on 'hard'.
"""
import os, sys, json, collections
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import compliance_adapter as ca

ca.use_standard("nist_800171_r2")
CORPUS = os.path.join(HERE, "efficacy", "corpus")
STATUSES = ["met", "partially-met", "not-met"]


def load_bundles():
    out = []
    for f in sorted(os.listdir(CORPUS)):
        if f.endswith(".json") and not f.startswith("_"):
            try:
                b = json.load(open(os.path.join(CORPUS, f)))
                if b.get("control_id") and b.get("_label", {}).get("status"):
                    b["_file"] = f
                    out.append(b)
            except Exception as e:
                print("skip malformed", f, e)
    return out


def main():
    bundles = load_bundles()
    if not bundles:
        print(json.dumps({"error": "no corpus bundles found in " + CORPUS})); return
    rows, confusion = [], collections.Counter()
    by_diff = collections.defaultdict(lambda: [0, 0])       # difficulty -> [agree, total]
    by_prof = collections.defaultdict(lambda: [0, 0])
    disagreements = []
    for b in bundles:
        c = ca.get_control(b["control_id"])
        det = ca.adjudicate(c, b)
        ref = b["_label"]["status"]
        diff = b["_label"].get("difficulty", "?")
        prof = ca._method_profile(c)
        gem = det["status"] if det else "ERROR"
        agree = (gem == ref)
        confusion[(ref, gem)] += 1
        by_diff[diff][0] += int(agree); by_diff[diff][1] += 1
        by_prof[prof][0] += int(agree); by_prof[prof][1] += 1
        row = {"file": b["_file"], "control": b["control_id"], "difficulty": diff, "profile": prof,
               "agy_ref": ref, "gemma": gem, "agree": agree, "trap": b["_label"].get("trap", "")}
        rows.append(row)
        if not agree and det is not None:
            # close the loop: a disagreement is exactly what the HITL/Deferral port is for
            ca.defer_for_review(c, b, det, reason=f"efficacy disagreement: agy_ref={ref} gemma={gem}")
            disagreements.append({**row, "agy_rationale": b["_label"].get("rationale", ""),
                                  "decisive_objective": b["_label"].get("decisive_objective_id", "")})

    n = len(rows); agreed = sum(r["agree"] for r in rows)
    report = {
        "n_bundles": n,
        "overall_agreement": round(agreed / n, 3),
        "agreement_by_difficulty": {d: {"agree": a, "total": t, "rate": round(a / t, 3)}
                                    for d, (a, t) in sorted(by_diff.items())},
        "agreement_by_profile": {p: {"agree": a, "total": t, "rate": round(a / t, 3)}
                                 for p, (a, t) in sorted(by_prof.items())},
        "confusion_ref_x_gemma": {f"{r}->{g}": confusion[(r, g)] for r in STATUSES for g in STATUSES
                                  if confusion[(r, g)]},
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
