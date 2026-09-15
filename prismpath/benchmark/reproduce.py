# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""reproduce.py — regenerate the routing-benchmark numbers with one command (Area 4).

    python prismpath/benchmark/reproduce.py

Loads the labeled dataset (routing_bench.jsonl) and the flows it references, then scores the
model-free **lexical** baseline and the **embedding** router per stratum — the split that motivates
the routing spectrum (embeddings near-perfect on intent, fragile on polarity/abstraction). Every
number the papers report on this suite is regenerable here; a `<flow>.lock` (if present) makes the
embedding numbers bit-for-bit reproducible.

Honest scope: N=301 across 8 flows (17 hand-crafted gold + 284 gated by an independent blind
second-labeler, IAA 0.979 AI-vs-AI). A HUMAN annotator + Cohen's κ remains gate zero — the tooling is
`prismpath annotate` + `prismpath kappa` (see benchmark/README.md).
"""
from __future__ import annotations

import json
import os
import re
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
FLOWS = os.path.join(os.path.dirname(HERE), "flows")


def _lexical(outcome, edges):
    ow = set(re.findall(r"[a-z]+", outcome.lower()))
    best, pick = -1, edges[0][0]
    for target, cond in edges:
        overlap = len(ow & set(re.findall(r"[a-z]+", cond.lower())))
        if overlap > best:
            best, pick = overlap, target
    return pick


def main(dataset=None) -> dict:
    import numpy as np
    from prismpath.routing import embedder
    from prismpath.kernel import predicates
    from prismpath.kernel.parser import parse_file

    dataset = dataset or os.path.join(HERE, "routing_bench.jsonl")
    cases = [json.loads(line) for line in open(dataset, encoding="utf-8") if line.strip()]
    graphs = {}

    per = defaultdict(lambda: {"n": 0, "embed": 0, "lexical": 0})
    for case in cases:
        flow = case["flow"]
        if flow not in graphs:
            graphs[flow] = parse_file(os.path.join(FLOWS, f"{flow}.md"))
        node = graphs[flow].nodes[case["node"]]
        sem = [(target, cond) for target, cond in node.edges if predicates.is_semantic(cond)]
        cond_embs = embedder.embed([cond for _, cond in sem], is_query=False)
        qe = embedder.embed([case["outcome"]], is_query=True)
        embed_pick = sem[int(np.argmax(embedder.cosine(qe, cond_embs)[0]))][0]
        lex_pick = _lexical(case["outcome"], sem)
        for key in (case["stratum"], "ALL"):
            per[key]["n"] += 1
            per[key]["embed"] += int(embed_pick == case["label"])
            per[key]["lexical"] += int(lex_pick == case["label"])

    print(f"routing benchmark — {len(cases)} labeled cases\n")
    print(f"  {'stratum':<12} {'n':>3}  {'embed':>7}  {'lexical':>7}")
    for key in sorted(per, key=lambda stratum: (stratum != "ALL", stratum)):
        counts = per[key]
        print(f"  {key:<12} {counts['n']:>3}  {counts['embed']/counts['n']:>6.2f}  {counts['lexical']/counts['n']:>6.2f}")
    return dict(per)


if __name__ == "__main__":
    main()
