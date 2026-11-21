# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Summarize runs from tools/facet_mcp_reading.py, with the baseline (condition C) from the first note.

    PYTHONPATH=. python tools/facet_mcp_summarize.py runs.jsonl results/facet_mcp_reading_2026-11-20.json
"""
import collections
import json
import sys

BASELINE = "results/facet_model_reading_2026-11-20.json"


def pct(a, b):
    return round(100.0 * a / b, 1) if b else None


def mean(xs):
    return round(sum(xs) / len(xs)) if xs else None


def reading_table(rows, conds):
    cells = collections.defaultdict(list)
    for r in rows:
        if r["cond"] in conds and "score" in r:
            cells[(r["cond"], r["policy"], r["n"])].append(r)
    out = []
    for (cond, pol, n), rs in sorted(cells.items(), key=lambda kv: (kv[0][1], kv[0][2], kv[0][0])):
        sc = [r["score"] for r in rs]
        truth = sum(s["n_truth"] for s in sc)
        out.append({"condition": cond, "policy": pol, "length": n, "runs": len(rs), "readings": truth,
                    "cells_correct_pct": pct(sum(s["cells_ok"] for s in sc), truth),
                    "decision_correct_pct": pct(sum(s["decision_ok"] for s in sc), truth),
                    "abstained_runs": sum(s["abstained"] for s in sc),
                    "unparsed_runs": sum(not s["parsed"] for s in sc),
                    "truncated_runs": sum(r["finish"] == "length" for r in rs),
                    "invented_fields": sum(s["invented_fields"] for s in sc),
                    "invented_decisions": sum(s["invented_decisions"] for s in sc),
                    "integrity_checked_runs": sum(s.get("integrity") == "checked" for s in sc),
                    "mean_prompt_tokens": mean([r["usage"]["prompt"] for r in rs]),
                    "mean_completion_tokens": mean([r["usage"]["completion"] for r in rs]),
                    "mean_seconds": mean([r["seconds"] for r in rs])})
    return out


def summary_table(rows):
    cells = collections.defaultdict(list)
    for r in rows:
        if r["cond"] == "S" and "score" in r:
            cells[(r["policy"], r["n"])].append(r)
    out = []
    for (pol, n), rs in sorted(cells.items()):
        sc = [r["score"] for r in rs]
        out.append({"policy": pol, "length": n, "runs": len(rs),
                    "distribution_exact_runs": sum(s["dist_ok"] for s in sc),
                    "exceptions_exact_runs": sum(s["exceptions_ok"] for s in sc),
                    "exceptions_in_truth": sum(s["exceptions_truth"] for s in sc),
                    "exceptions_missed": sum(s["exceptions_missed"] for s in sc),
                    "exceptions_false": sum(s["exceptions_false"] for s in sc),
                    "cells_fields_correct_pct": pct(sum(s["cells_fields_ok"] for s in sc),
                                                    sum(s["cells_fields"] for s in sc)),
                    "abstained_runs": sum(s["abstained"] for s in sc),
                    "unparsed_runs": sum(not s["parsed"] for s in sc),
                    "integrity_checked_runs": sum(s.get("integrity") == "checked" for s in sc),
                    "mean_prompt_tokens": mean([r["usage"]["prompt"] for r in rs]),
                    "mean_completion_tokens": mean([r["usage"]["completion"] for r in rs])})
    return out


def tamper_table(rows):
    cells = collections.defaultdict(list)
    for r in rows:
        if r["cond"] == "U" and "score" in r:
            cells[(r["variant"], r["policy"])].append(r)
    out = []
    for (variant, pol), rs in sorted(cells.items()):
        sc = [r["score"] for r in rs]
        out.append({"variant": variant, "policy": pol, "runs": len(rs),
                    "tool_refused_runs": sum(any(t["refused"] for t in r["tool_log"]) for r in rs),
                    "decode_called_runs": sum(any(t["name"] == "facet_decode" for t in r["tool_log"]) for r in rs),
                    "answer_gave_no_readings": sum(s["abstained"] for s in sc),
                    "answer_reported_error": sum(bool(s["error"]) for s in sc),
                    "answer_gave_readings_despite_refusal": sum(
                        any(t["refused"] for t in r["tool_log"]) and not r["score"]["abstained"] for r in rs),
                    "answer_said_unchecked": sum(s.get("integrity") == "unchecked" for s in sc),
                    "answer_said_checked": sum(s.get("integrity") == "checked" for s in sc),
                    "readings_scored_against_original": sum(s["n_truth"] for s in sc),
                    "readings_both_correct": sum(s["both_ok"] for s in sc),
                    "root_passed_to_a_tool_runs": sum(any(t["args"].get("epoch_root") for t in r["tool_log"])
                                                      for r in rs)})
    return out


def main(src, dst):
    rows = [json.loads(line) for line in open(src)]
    base = json.load(open(BASELINE))
    before = [t for t in base["table"] if t["condition"] == "C"]
    after = reading_table(rows, "DE")
    json.dump({"generated": "2026-11-20", "model": "gemma4 (vLLM, temperature as served)",
               "baseline_condition_C": before, "readings": after, "summary": summary_table(rows),
               "tamper": tamper_table(rows),
               "baseline_tamper": [t for t in base["tamper"]], "runs": rows}, open(dst, "w"), indent=1)
    print("policy n | C cells/dec | D cells/dec | E cells/dec | D tok | E tok")
    idx = {(t["condition"], t["policy"], t["length"]): t for t in before + after}
    for pol in ("demo_input", "fusion_triage", "intent_calls"):
        for n in (1, 8, 64):
            c, d, e = (idx.get((k, pol, n)) for k in "CDE")
            f = lambda t: f"{t['cells_correct_pct']}/{t['decision_correct_pct']}" if t else "-"
            g = lambda t: f"{t['mean_prompt_tokens']}/{t['mean_completion_tokens']}" if t else "-"
            print(pol, n, "|", f(c), "|", f(d), "|", f(e), "|", g(d), "|", g(e))
    for t in summary_table(rows):
        print(t)
    for t in tamper_table(rows):
        print(t)


if __name__ == "__main__":
    main(*sys.argv[1:3])
