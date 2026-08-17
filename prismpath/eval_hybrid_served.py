# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""3-arm routing eval (EMBED vs LLM vs HYBRID frontier), LLM = the already-served Gemma
endpoint (no local model load, no GPU-memory risk). Reuses the real CASES + routers."""
import requests
from prismpath.parser import parse_file
from prismpath.router import EmbeddingRouter, LLMRouter
from prismpath.eval_routing import CASES

def served_generate(prompt):
    r = requests.post("http://127.0.0.1:8888/v1/chat/completions",
        json={"model":"gemma4","temperature":0,"max_tokens":8,
              "messages":[{"role":"user","content":prompt}]}, timeout=90)
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]

g = parse_file("prismpath/flows/bugfix.md")
embed = EmbeddingRouter(); llm = LLMRouter(served_generate)
recs = []
for node, outcome, expected in CASES:
    edges = g.nodes[node].edges; instr = g.nodes[node].instruction
    ed = embed.route(outcome, edges, instr)
    lt = llm.route(outcome, edges, instr).target if len(edges) > 1 else ed.target
    recs.append((node, outcome, expected, ed.target, ed.info["margin"], lt, len(edges)))

N = len(recs); multi = [r for r in recs if r[6] > 1]
print(f"=== arms on {N} cases ({len(multi)} multi-edge) | LLM=served gemma4 ===")
print(f"  EMBED-only : acc={sum(r[3]==r[2] for r in recs)/N:.2f}  (0 LLM calls)")
print(f"  LLM-only   : acc={sum(r[5]==r[2] for r in recs)/N:.2f}  ({len(multi)} LLM calls)")
print("\n=== HYBRID frontier (escalate to gemma when margin < δ) ===")
print(f"  {'delta':>6s} {'acc':>5s} {'LLMcalls':>8s} {'LLMrate':>7s}")
for d in (0.03,0.05,0.08,0.12,0.20,0.30):
    ok=calls=0
    for (_n,_o,exp,et,margin,lt,ne) in recs:
        pick = lt if (ne>1 and margin<d) else et
        if ne>1 and margin<d: calls+=1
        ok += pick==exp
    print(f"  {d:6.2f} {ok/N:5.2f} {calls:8d} {calls/len(multi):7.0%}")
