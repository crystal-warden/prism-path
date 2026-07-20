"""Routing-accuracy mini-evals for the new example flows.

For each flow we hand-label realistic agent outcomes with the SEMANTIC edge they should take
(deterministic `when` edges are exact by construction, so they're excluded from the accuracy
number — we only score the genuinely-semantic transitions the router has to judge). We report
EmbeddingRouter accuracy per flow, and optionally HybridRouter accuracy if a local LLM is
available (skipped by default to keep the eval cheap/CPU-only).

  EMBED_DEVICE=cpu python prismpath/eval_flows.py            # embed-only
  PRISMPATH_EVAL_HYBRID=1 python prismpath/eval_flows.py                              # +hybrid (LLM)
"""
from __future__ import annotations

import os
from collections import defaultdict

from prismpath.parser import parse_file
from prismpath.predicates import is_deterministic
from prismpath.router import EmbeddingRouter

# flow file -> [(node, outcome_text, expected_target), ...]; only nodes whose chosen edge is
# SEMANTIC are scored (a labeled target that is reached via a deterministic edge is dropped).
CASES = {
    "prismpath/flows/triage_support.md": [
        ("classify", "The app crashes with a 500 every time I click save.", "bug_report"),
        ("classify", "I was charged twice for my subscription this month.", "billing"),
        ("classify", "Could you add a dark mode to the dashboard?", "feature_request"),
        ("classify", "How do I export my data to CSV?", "general_question"),
        ("bug_report", "I found the cause and gave the customer a working workaround.", "resolve"),
        ("bug_report", "This needs a backend engineer to dig into the database state.", "escalate"),
        ("billing", "The charge was a duplicate, I issued the refund.", "resolve"),
        ("billing", "Approving this refund is above my limit, a manager must sign off.", "escalate"),
    ],
    "prismpath/flows/pr_review.md": [
        ("human_review", "The implementation is clean and the logic is correct.", "approve"),
        ("human_review", "There's a bug in the error path; the author needs to fix it.", "request_changes"),
        ("human_review", "We should debate whether to break the public API here first.", "needs_discussion"),
        ("needs_discussion", "We agreed to keep the API stable; the code can be reviewed again.", "human_review"),
        ("request_changes", "The author closed the PR and won't continue.", "closed"),
    ],
    "prismpath/flows/data_pipeline.md": [
        ("validate", "Records have a few mis-formatted dates the repair rules can normalize.", "clean"),
        ("validate", "The file is truncated and the columns are garbled beyond repair.", "quarantine"),
    ],
    "prismpath/flows/release.md": [
        ("staging", "Staging is healthy and latency is stable across all regions.", "production"),
        ("staging", "Staging is throwing 5xx errors and latency regressed badly.", "rollback"),
    ],
}


def _semantic_edges(node):
    return [(t, c) for t, c in node.edges if not is_deterministic(c)]


def main():
    use_hybrid = os.environ.get("PRISMPATH_EVAL_HYBRID", "0") not in ("0", "", "false")
    embed = EmbeddingRouter()
    hybrid = None
    if use_hybrid:
        from prismpath.router import HybridRouter, LLMRouter
        from prismpath import llm_local
        hybrid = HybridRouter(LLMRouter(llm_local.generate))

    grand = [0, 0]
    for flow_path, cases in CASES.items():
        g = parse_file(flow_path)
        probs = g.validate()
        print(f"\n=== {g.name} ({flow_path}) ===")
        if probs:
            print("  structural problems:", probs)
        ok_e = ok_h = total = 0
        esc = 0
        fails = []
        for node, outcome, expected in cases:
            sem = _semantic_edges(g.nodes[node])
            if len(sem) < 2:
                # not a genuinely-semantic decision (1 or 0 semantic edges) -> skip scoring
                continue
            total += 1
            de = embed.route(outcome, sem, g.nodes[node].instruction)
            ok_e += de.target == expected
            if de.target != expected:
                fails.append((node, outcome, expected, de.target, "embed"))
            if hybrid is not None:
                dh = hybrid.route(outcome, sem, g.nodes[node].instruction)
                ok_h += dh.target == expected
                esc += int(dh.info.get("escalated", False))
        grand[0] += ok_e
        grand[1] += total
        line = f"  embed: {ok_e}/{total} = {ok_e/total:.2f}" if total else "  (no scorable cases)"
        if hybrid is not None and total:
            line += f"   |   hybrid: {ok_h}/{total} = {ok_h/total:.2f} ({esc} LLM escalations)"
        print(line)
        for node, outcome, exp, got, who in fails:
            print(f"    [{who} miss @ {node}] {outcome!r}\n        expected={exp} got={got}")

    if grand[1]:
        print(f"\n=== OVERALL embed accuracy: {grand[0]}/{grand[1]} = "
              f"{grand[0]/grand[1]:.2f} on semantic edges across {len(CASES)} flows ===")


if __name__ == "__main__":
    main()
