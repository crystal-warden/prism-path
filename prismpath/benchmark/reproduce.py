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
    for t, cond in edges:
        s = len(ow & set(re.findall(r"[a-z]+", cond.lower())))
        if s > best:
            best, pick = s, t
    return pick


def main(dataset=None) -> dict:
    import numpy as np
    from prismpath import embedder, predicates
    from prismpath.parser import parse_file

    dataset = dataset or os.path.join(HERE, "routing_bench.jsonl")
    cases = [json.loads(l) for l in open(dataset, encoding="utf-8") if l.strip()]
    graphs = {}

    per = defaultdict(lambda: {"n": 0, "embed": 0, "lexical": 0})
    for c in cases:
        flow = c["flow"]
        if flow not in graphs:
            graphs[flow] = parse_file(os.path.join(FLOWS, f"{flow}.md"))
        node = graphs[flow].nodes[c["node"]]
        sem = [(t, cond) for t, cond in node.edges if predicates.is_semantic(cond)]
        cond_embs = embedder.embed([cond for _, cond in sem], is_query=False)
        qe = embedder.embed([c["outcome"]], is_query=True)
        embed_pick = sem[int(np.argmax(embedder.cosine(qe, cond_embs)[0]))][0]
        lex_pick = _lexical(c["outcome"], sem)
        for key in (c["stratum"], "ALL"):
            per[key]["n"] += 1
            per[key]["embed"] += int(embed_pick == c["label"])
            per[key]["lexical"] += int(lex_pick == c["label"])

    print(f"routing benchmark — {len(cases)} labeled cases\n")
    print(f"  {'stratum':<12} {'n':>3}  {'embed':>7}  {'lexical':>7}")
    for key in sorted(per, key=lambda k: (k != "ALL", k)):
        s = per[key]
        print(f"  {key:<12} {s['n']:>3}  {s['embed']/s['n']:>6.2f}  {s['lexical']/s['n']:>6.2f}")
    return dict(per)


if __name__ == "__main__":
    main()
