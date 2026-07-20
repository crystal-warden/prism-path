"""The make-or-break test: does embedding routing pick the RIGHT edge?

For the bugfix flow we hand-label realistic agent outcomes with the edge they SHOULD take,
including the hard logical-polarity cases ("all tests pass" vs "some tests still fail") that
are topically near-identical. We compare:
  (1) EMBED   — cosine(outcome, edge-condition) argmax  (the proposal)
  (2) LEXICAL — token-overlap argmax                     (a trivial baseline)
and report accuracy + every failure, so we can see exactly where embeddings break.
"""
from __future__ import annotations

import re
from collections import defaultdict

import numpy as np

from prismpath.parser import parse_file
from prismpath import embedder

# (current_node, outcome_text, expected_target)
CASES = [
    # --- triage: intent/topic distinctions (embeddings should do well) ---
    ("triage", "I reproduced the crash; it's a null dereference in parse_config().", "implement"),
    ("triage", "Found the root cause: an off-by-one in the loop bound.", "implement"),
    ("triage", "I can't reproduce this with the steps provided.", "gather_info"),
    ("triage", "I need the user's OS version and the full stack trace to proceed.", "gather_info"),
    ("triage", "This is a duplicate of issue #412, already fixed.", "close"),
    ("triage", "Not a bug — the reported behavior is actually correct per the spec.", "close"),
    # --- implement: LOGICAL POLARITY — the hard part for embeddings ---
    ("implement", "Applied the fix and the entire test suite passes.", "review"),
    ("implement", "The patch is done; all 240 tests are green.", "review"),
    ("implement", "I changed the fix but three tests are still failing.", "implement"),
    ("implement", "Still broken — two unit tests fail after my change.", "implement"),
    ("implement", "I'm blocked: should we change the public API signature or keep it?", "triage"),
    ("implement", "Need a design call on whether to support the legacy format.", "triage"),
    # --- review: polarity again ---
    ("review", "The diff looks correct and is ready to merge.", "done"),
    ("review", "LGTM, no issues, ship it.", "done"),
    ("review", "The review found a race condition that needs fixing.", "implement"),
    ("review", "Found problems — the error handling is wrong, needs changes.", "implement"),
    # --- gather_info ---
    ("gather_info", "The reporter sent logs and repro steps; we can investigate now.", "triage"),
]


def lexical_route(outcome, edges):
    ow = set(re.findall(r"[a-z]+", outcome.lower()))
    best, bi = -1, 0
    for i, (_, cond) in enumerate(edges):
        cw = set(re.findall(r"[a-z]+", cond.lower()))
        score = len(ow & cw)
        if score > best:
            best, bi = score, i
    return edges[bi][0]


def embed_route(outcome, edges, cond_embs):
    qe = embedder.embed([outcome], is_query=True)
    sims = embedder.cosine(qe, cond_embs)[0]
    return edges[int(np.argmax(sims))][0], sims


def main():
    g = parse_file("prismpath/flows/bugfix.md")
    print("flow:", g.name, "| nodes:", list(g.nodes), "| start:", g.start)
    print("validate:", g.validate() or "ok")

    # precompute edge-condition embeddings per node
    cond_embs = {name: embedder.embed([c for _, c in n.edges], is_query=False)
                 for name, n in g.nodes.items() if n.edges}

    n_ok_e = n_ok_l = 0
    per_node = defaultdict(lambda: [0, 0])  # node -> [embed_ok, total]
    fails = []
    for node, outcome, expected in CASES:
        edges = g.nodes[node].edges
        pe, sims = embed_route(outcome, edges, cond_embs[node])
        pl = lexical_route(outcome, edges)
        n_ok_e += pe == expected
        n_ok_l += pl == expected
        per_node[node][0] += pe == expected
        per_node[node][1] += 1
        if pe != expected:
            ranked = sorted(zip([t for t, _ in edges], sims), key=lambda x: -x[1])
            fails.append((node, outcome, expected, pe,
                          ", ".join(f"{t}={s:.2f}" for t, s in ranked)))

    N = len(CASES)
    print(f"\n=== routing accuracy on {N} labeled cases ===")
    print(f"  EMBED  (cosine):       {n_ok_e}/{N} = {n_ok_e/N:.2f}")
    print(f"  LEXICAL (token-overlap): {n_ok_l}/{N} = {n_ok_l/N:.2f}")
    print("  per-node (embed):", {k: f"{v[0]}/{v[1]}" for k, v in per_node.items()})
    print(f"\n=== embed failures ({len(fails)}) ===")
    for node, outcome, exp, got, ranked in fails:
        print(f"  [{node}] {outcome!r}\n     expected={exp} got={got} | sims: {ranked}")


if __name__ == "__main__":
    main()
