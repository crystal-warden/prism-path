# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Summarize runs from tools/facet_model_reading.py.

    PYTHONPATH=. python tools/facet_model_summarize.py runs.jsonl results/facet_model_reading_2026-11-20.json
"""
import collections
import json
import sys


def pct(a, b):
    return round(100.0 * a / b, 1) if b else None


def flip_detection():
    """Every single bit flip of the streams used, and the share the codec refuses on its own."""
    from tools.facet_model_reading import LENGTHS, POLICIES, make_stream
    from tools.facet_model_tools import Policy, Refused
    out = []
    for name, path in POLICIES.items():
        policy = Policy(path)
        for n in LENGTHS:
            flips = refused = 0
            for rep in range(5):
                data, _ = make_stream(policy, n, rep)
                for i in range(len(data) * 8):
                    x = bytearray(data)
                    x[i // 8] ^= 0x80 >> (i % 8)
                    flips += 1
                    try:
                        policy.symbols(bytes(x))
                    except Refused:
                        refused += 1
            out.append({"policy": name, "length": n, "bit_flips": flips, "refused_pct": pct(refused, flips)})
    return out


def main(src, dst):
    rows = [json.loads(line) for line in open(src)]
    cells = collections.defaultdict(list)
    for r in rows:
        if r["cond"] in "ABC":
            cells[(r["cond"], r["policy"], r["n"])].append(r)
    table = []
    for (cond, pol, n), rs in sorted(cells.items(), key=lambda kv: (kv[0][1], kv[0][2], kv[0][0])):
        truth = sum(r["score"]["n_truth"] for r in rs)
        sc = [r["score"] for r in rs]
        table.append({
            "condition": cond, "policy": pol, "length": n, "runs": len(rs),
            "readings": truth,
            "cells_correct_pct": pct(sum(s["cells_ok"] for s in sc), truth),
            "decision_correct_pct": pct(sum(s["decision_ok"] for s in sc), truth),
            "both_correct_pct": pct(sum(s["both_ok"] for s in sc), truth),
            "abstained_runs": sum(s["abstained"] for s in sc),
            "unparsed_runs": sum(not s["parsed"] for s in sc),
            "truncated_runs": sum(r["finish"] == "length" for r in rs),
            "invented_fields": sum(s["invented_fields"] for s in sc),
            "invented_decisions": sum(s["invented_decisions"] for s in sc),
            "extra_readings": sum(s["extra_readings"] for s in sc),
            "mean_prompt_tokens": round(sum(r["usage"]["prompt"] for r in rs) / len(rs)),
            "mean_completion_tokens": round(sum(r["usage"]["completion"] for r in rs) / len(rs)),
            "mean_model_calls": round(sum(r["usage"]["calls"] for r in rs) / len(rs), 2),
            "mean_seconds": round(sum(r["seconds"] for r in rs) / len(rs), 1),
        })
    overall = {}
    for cond in "ABC":
        rs = [r for r in rows if r["cond"] == cond]
        if rs:
            truth = sum(r["score"]["n_truth"] for r in rs)
            overall[cond] = {"runs": len(rs), "readings": truth,
                             "both_correct_pct": pct(sum(r["score"]["both_ok"] for r in rs), truth),
                             "invented_fields": sum(r["score"]["invented_fields"] for r in rs),
                             "invented_decisions": sum(r["score"]["invented_decisions"] for r in rs),
                             "completion_tokens": sum(r["usage"]["completion"] for r in rs),
                             "prompt_tokens": sum(r["usage"]["prompt"] for r in rs)}
    tamper = collections.defaultdict(list)
    for r in rows:
        if r["cond"] == "T" and "score" in r:
            tamper[(r["variant"], r["policy"])].append(r)
    trows = []
    for (variant, pol), rs in sorted(tamper.items()):
        sc = [r["score"] for r in rs]
        trows.append({
            "variant": variant, "policy": pol, "runs": len(rs),
            "tool_refused_runs": sum(any(t["refused"] for t in r["tool_log"]) for r in rs),
            "decode_called_runs": sum(any(t["name"] == "facet_decode" for t in r["tool_log"]) for r in rs),
            "answer_gave_no_readings": sum(s["abstained"] for s in sc),
            "answer_reported_error": sum(bool(s["error"]) for s in sc),
            "answer_gave_readings_despite_refusal": sum(
                any(t["refused"] for t in r["tool_log"]) and not r["score"]["abstained"] for r in rs),
            "readings_scored_against_original": sum(s["n_truth"] for s in sc),
            "readings_both_correct": sum(s["both_ok"] for s in sc),
            "invented_fields": sum(s["invented_fields"] for s in sc),
            "invented_decisions": sum(s["invented_decisions"] for s in sc),
        })
    skipped = [{k: r[k] for k in ("cond", "policy", "variant", "rep", "skipped")} for r in rows if "skipped" in r]
    json.dump({"generated": "2026-11-20", "model": "gemma4 (vLLM, temperature as served)",
               "overall": overall, "table": table, "tamper": trows, "single_bit_flip_detection": flip_detection(), "skipped": skipped, "runs": rows},
              open(dst, "w"), indent=1)
    print(json.dumps({"overall": overall}, indent=1))
    for t in table:
        print(t["policy"][:13], t["length"], t["condition"], t["cells_correct_pct"], t["decision_correct_pct"],
              t["invented_fields"], t["invented_decisions"], t["abstained_runs"], t["mean_completion_tokens"],
              t["mean_prompt_tokens"])
    for t in trows:
        print(t)
    print(*[json.dumps(x) for x in flip_detection()], sep="\n")


if __name__ == "__main__":
    main(*sys.argv[1:3])
