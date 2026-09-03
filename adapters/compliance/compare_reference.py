#!/usr/bin/env python3
"""Differential: gemma's dispositions vs agy's independent verdicts on the IDENTICAL bundles.
Agreement validates the adjudicator; disagreements (esp. gemma stricter than agy) are the calibration
boundary and route to the HITL review queue. Neither is ground truth — this is a model-vs-model
differential, which is the honest signal available without a credentialed human assessor."""
import os, sys, json, collections
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import compliance_adapter as ca

STAT = ["met", "partially-met", "not-met"]
REF = os.path.join(HERE, "efficacy", "reference", "verdicts")


def main():
    gem = {r["control"]: r["disposition"] for r in
           json.load(open(os.path.join(HERE, "efficacy", "company_report.json")))["rows"]}
    if not os.path.isdir(REF) or not os.listdir(REF):
        print(json.dumps({"error": "no agy verdicts yet in " + REF})); return
    agy = {}
    for f in os.listdir(REF):
        if f.endswith(".json"):
            v = json.load(open(os.path.join(REF, f)))
            agy[v["control_id"]] = v
    rows, conf, disagree = [], collections.Counter(), []
    for cid in sorted(gem):
        g = gem[cid]
        a = agy.get(cid, {}).get("status", "MISSING")
        conf[(g, a)] += 1
        agree = g == a
        row = {"control": cid, "gemma": g, "agy": a, "agree": agree,
               "agy_rationale": agy.get(cid, {}).get("rationale", "")}
        rows.append(row)
        if not agree:
            disagree.append(row)
    n = len(rows); agreed = sum(r["agree"] for r in rows)
    # "gemma stricter" = gemma not-met/partial where agy is more lenient
    order = {"not-met": 0, "partially-met": 1, "met": 2}
    gemma_stricter = [r for r in disagree if order.get(r["gemma"], 0) < order.get(r["agy"], 0)]
    report = {
        "n": n, "agreement": round(agreed / n, 3),
        "gemma_distribution": dict(collections.Counter(gem.values())),
        "agy_distribution": dict(collections.Counter(v["status"] for v in agy.values())),
        "confusion_gemma_x_agy": {f"g:{g}|a:{a}": conf[(g, a)] for g in STAT for a in STAT if conf[(g, a)]},
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
    for r in disagree:
        try:
            c = ca.get_control(r["control"])
            ca.defer_for_review(c, {"control_id": r["control"], "boundary": "Meridian", "evidence": []},
                                {"status": r["gemma"], "unmet_objective_ids": [], "gap_summary": "efficacy differential"},
                                reason=f"gemma={r['gemma']} vs agy={r['agy']}")
        except Exception:
            pass
    print(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
