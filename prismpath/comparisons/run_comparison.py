"""run_comparison.py — the Area-5 head-to-head, measured (not vibed).

Scores the four baselines on the labeled routing suite (`benchmark/routing_bench.jsonl`), the same
outcomes the papers report, so routing accuracy is *scored against ground truth*. For each baseline
it reports:

    accuracy               fraction of transitions routed to the labeled edge
    llm_calls_per_1k       model calls per 1,000 transitions (prismpath escalates only on doubt)
    latency median / p95   wall-clock seconds per routing decision (includes framework machinery)
    determinism            fraction of cases whose decision was identical across every repeat

Run (from the repo root, in the dedicated venv):

    # from the directory that contains the prismpath package (repo root):
    PYTHONPATH=. prismpath/comparisons/.venv/bin/python -m prismpath.comparisons.run_comparison --repeats 3

Writes `comparisons/results.json` and prints the markdown table pasted into the README + papers.
Baselines whose framework isn't installed are skipped with a note (so the prismpath / LLM-router
numbers regenerate even without LangGraph/CrewAI present).
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FLOWS = os.path.join(ROOT, "flows")
DATA = os.path.join(ROOT, "benchmark", "routing_bench.jsonl")


def load_cases():
    """Return [(case_dict, instruction, outcome, edges)] for every labeled transition."""
    from prismpath.parser import parse_file
    graphs, out = {}, []
    for line in open(DATA, encoding="utf-8"):
        if not line.strip():
            continue
        c = json.loads(line)
        g = graphs.setdefault(c["flow"], parse_file(os.path.join(FLOWS, f"{c['flow']}.md")))
        node = g.nodes[c["node"]]
        edges = list(node.edges)
        out.append((c, node.instruction, c["outcome"], edges))
    return out


def _pct(x):
    return f"{100 * x:5.1f}%"


def run_baseline(bl, cases, repeats):
    """Return metrics dict for one baseline over `repeats` passes of the suite."""
    per_case_decisions = [[] for _ in cases]
    latencies, total_calls, correct_last = [], 0, 0
    for r in range(repeats):
        for i, (c, instr, outcome, edges) in enumerate(cases):
            target, calls, dt = bl.decide(instr, outcome, edges)
            per_case_decisions[i].append(target)
            total_calls += calls
            if len(edges) > 1:                 # only real decisions carry latency/accuracy weight
                latencies.append(dt)
    # accuracy: score the final repeat's decision against the label
    decisions_last = [d[-1] for d in per_case_decisions]
    correct = sum(int(dec == c[0]["label"]) for dec, c in zip(decisions_last, cases))
    # determinism: identical decision across every repeat
    stable = sum(int(len(set(d)) == 1) for d in per_case_decisions)
    n_decisions = sum(1 for _, _, _, e in cases if len(e) > 1)
    transitions = n_decisions * repeats
    return {
        "name": bl.name,
        "n_cases": len(cases),
        "n_decisions": n_decisions,
        "repeats": repeats,
        "accuracy": correct / len(cases),
        "llm_calls_per_1k": (1000.0 * total_calls / transitions) if transitions else 0.0,
        "latency_median_s": statistics.median(latencies) if latencies else 0.0,
        "latency_p95_s": (sorted(latencies)[int(0.95 * (len(latencies) - 1))]
                          if latencies else 0.0),
        "determinism": stable / len(cases),
    }


def markdown_table(rows):
    order = ["prismpath", "langgraph", "llm_router", "crewai"]
    rows = sorted(rows, key=lambda r: order.index(r["name"]) if r["name"] in order else 99)
    head = "| metric | " + " | ".join(r["name"] for r in rows) + " |"
    sep = "|" + "---|" * (len(rows) + 1)

    def line(label, fn):
        return "| " + label + " | " + " | ".join(fn(r) for r in rows) + " |"

    return "\n".join([
        head, sep,
        line("routing accuracy (hard suite)", lambda r: _pct(r["accuracy"])),
        line("LLM calls / 1k transitions", lambda r: f"{r['llm_calls_per_1k']:.0f}"),
        line("median latency / transition", lambda r: f"{r['latency_median_s'] * 1000:.0f} ms"),
        line("p95 latency / transition", lambda r: f"{r['latency_p95_s'] * 1000:.0f} ms"),
        line("determinism (identical across repeats)", lambda r: _pct(r["determinism"])),
    ])


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--margin", type=float, default=0.05, help="prismpath escalation margin (delta)")
    ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument("--only", default="", help="comma list to restrict baselines")
    args = ap.parse_args(argv)

    from prismpath.comparisons.baselines import all_baselines
    cases = load_cases()
    print(f"loaded {len(cases)} labeled transitions "
          f"({sum(1 for _,_,_,e in cases if len(e) > 1)} are real >1-edge decisions), "
          f"repeats={args.repeats}\n")

    only = {s for s in args.only.split(",") if s}
    rows, skipped = [], []
    for bl in all_baselines(margin=args.margin, temperature=args.temperature):
        if only and bl.name not in only:
            continue
        if not bl.available:
            skipped.append(bl.name)
            continue
        print(f"running {bl.name} ...", flush=True)
        bl.warm(cases)
        rows.append(run_baseline(bl, cases, args.repeats))

    if skipped:
        print(f"\n(skipped, framework not importable: {', '.join(skipped)})")

    table = markdown_table(rows)
    print("\n" + table + "\n")
    out = {"config": vars(args), "rows": rows}
    with open(os.path.join(HERE, "results.json"), "w") as f:
        json.dump(out, f, indent=2)
    with open(os.path.join(HERE, "results_table.md"), "w") as f:
        f.write(table + "\n")
    print(f"wrote {os.path.join('comparisons', 'results.json')} and results_table.md")
    return out


if __name__ == "__main__":
    sys.exit(0 if main() else 0)
