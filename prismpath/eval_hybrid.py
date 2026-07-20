"""3-arm routing eval: EMBED vs LLM vs HYBRID, with a confidence-threshold frontier.

We compute, once per labeled case, the embedding decision (+ its top1↔top2 margin) and the LLM
decision. Then we simulate the hybrid at several margin thresholds: take the embedding pick when
confident (margin >= δ), else the LLM pick. Reports accuracy AND LLM-call rate per δ, so we can
see whether hybrid reaches reliable accuracy while keeping the LLM rare.
"""
from __future__ import annotations

from prismpath.parser import parse_file
from prismpath.router import EmbeddingRouter, LLMRouter
from prismpath import llm_local
from prismpath.eval_routing import CASES


def main():
    g = parse_file("prismpath/flows/bugfix.md")
    embed = EmbeddingRouter()
    llm = LLMRouter(llm_local.generate)

    recs = []  # (expected, embed_target, margin, score, llm_target, n_edges)
    for node, outcome, expected in CASES:
        edges = g.nodes[node].edges
        instr = g.nodes[node].instruction
        ed = embed.route(outcome, edges, instr)
        if len(edges) > 1:
            ld = llm.route(outcome, edges, instr)
            llm_t = ld.target
        else:
            llm_t = ed.target
        recs.append((node, outcome, expected, ed.target, ed.info["margin"],
                     ed.info["score"], llm_t, len(edges)))

    N = len(recs)
    multi = [r for r in recs if r[7] > 1]
    a_embed = sum(r[3] == r[2] for r in recs) / N
    a_llm = sum(r[6] == r[2] for r in recs) / N
    print(f"=== arms on {N} cases ({len(multi)} multi-edge) ===")
    print(f"  EMBED-only : acc={a_embed:.2f}   (0 LLM calls)")
    print(f"  LLM-only   : acc={a_llm:.2f}   ({len(multi)} LLM calls)")

    print("\n=== HYBRID frontier (escalate when margin < δ) ===")
    print(f"  {'δ':>5s}  {'acc':>5s}  {'LLM calls':>9s}  {'LLM rate':>8s}")
    for delta in (0.03, 0.05, 0.08, 0.12, 0.20, 0.30):
        ok = calls = 0
        for (_n, _o, exp, et, margin, score, lt, ne) in recs:
            if ne > 1 and margin < delta:
                pick = lt; calls += 1
            else:
                pick = et
            ok += pick == exp
        print(f"  {delta:5.2f}  {ok/N:5.2f}  {calls:9d}  {calls/len(multi):8.0%}")

    # detail at a sensible δ
    delta = 0.12
    print(f"\n=== detail at δ={delta} (which cases escalate / get fixed) ===")
    for (n, o, exp, et, margin, score, lt, ne) in recs:
        if ne > 1 and margin < delta:
            verdict = "LLM✓" if lt == exp else "LLM✗"
            print(f"  ESCALATE [{n}] margin={margin:.2f} embed={et}({'ok' if et==exp else 'X'})"
                  f" -> llm={lt} {verdict}  | {o[:50]!r}")
        elif et != exp:
            print(f"  MISS(no-escalate) [{n}] margin={margin:.2f} embed={et} exp={exp} | {o[:50]!r}")


if __name__ == "__main__":
    main()
