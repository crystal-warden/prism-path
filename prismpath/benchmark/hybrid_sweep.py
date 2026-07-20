"""hybrid_sweep.py — the two launch-gating measurements the reviewer asked for, in one harness:

  (1) RE-DERIVE the δ frontier at N=301 (the "knee near δ≈0.05" claim was measured at N=17 and
      must not be inherited): hybrid-over-ZERO-SHOT accuracy + escalation rate as δ sweeps.
  (2) THE MISSING CELL: hybrid-over-CENTROIDS — the same LLM-on-doubt escalation stacked on the
      CentroidRouter's 5-fold predictions. Centroids alone hit 0.83 at zero calls; if escalation
      on top lands near the LLM arms at a modest call rate, that's the new headline configuration.

One LLM pass serves both sweeps: the LLM's per-case choice is independent of WHICH embed tier
escalated to it, so we ask the model once per decision (same prompt builder as the measured
head-to-head — comparisons.gemma.routing_prompt — so numbers are comparable) and cache to
llm_choices.json. Everything else is offline vector math over the same fold split as
centroid.cross_validate (i % folds), so the centroid numbers are exactly reproducible.

Run (needs sentence-transformers + a live gemma endpoint):
    comparisons/.venv/bin/python benchmark/hybrid_sweep.py
"""
from __future__ import annotations

import json
import os
import sys
import time

import numpy as np
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from prismpath import embedder                                          # noqa: E402
from prismpath.centroid import _decision_items, _unit, load_graphs      # noqa: E402
from prismpath.comparisons.gemma import routing_prompt                  # noqa: E402
from prismpath.comparisons.baselines import _parse_choice               # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.join(HERE, "routing_bench.jsonl")
LLM_CACHE = os.path.join(HERE, "llm_choices.json")
OUT = os.path.join(HERE, "hybrid_sweep.json")
ENDPOINT = os.environ.get("SWEEP_ENDPOINT", "http://127.0.0.1:8888/v1/chat/completions")
MODEL = os.environ.get("SWEEP_MODEL", "gemma4")
FOLDS, PRIOR = 5, 4.0
DELTAS = [0.0, 0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.08, 0.10, 0.12, 0.15, 0.20, 0.30, 0.50]


def llm_choice(prompt: str, n_edges: int) -> int:
    r = requests.post(ENDPOINT, json={
        "model": MODEL, "temperature": 0.0, "max_tokens": 8,
        "messages": [{"role": "user", "content": prompt}]}, timeout=120)
    r.raise_for_status()
    return _parse_choice(r.json()["choices"][0]["message"]["content"], n_edges)


def main() -> None:
    records = [json.loads(l) for l in open(BENCH, encoding="utf-8") if l.strip()]
    graphs = load_graphs(records)
    items = _decision_items(records, graphs)
    n = len(items)
    print(f"decisions: {n}")

    outs = [it[0]["outcome"] for it in items]
    oq = embedder.embed(outs, is_query=True)
    op = embedder.embed(outs, is_query=False)
    conds = sorted({c for _, sem, _ in items for _, c in sem})
    cvec = {c: np.asarray(v, dtype="float32")
            for c, v in zip(conds, embedder.embed(conds, is_query=False))}

    # ---- the one LLM pass (cached; keyed by item index — the bench file is frozen) ----
    cache = json.load(open(LLM_CACHE)) if os.path.exists(LLM_CACHE) else {}
    t0 = time.time()
    for i, (rec, sem, ci) in enumerate(items):
        k = str(i)
        if k in cache:
            continue
        instr = graphs[rec["flow"]].nodes[rec["node"]].instruction
        cache[k] = llm_choice(routing_prompt(instr, rec["outcome"], sem), len(sem))
        if i % 25 == 0:
            json.dump(cache, open(LLM_CACHE, "w"))
            print(f"  llm {i}/{n}  ({time.time()-t0:.0f}s)")
    json.dump(cache, open(LLM_CACHE, "w"))
    llm_pick = [cache[str(i)] for i in range(n)]
    print(f"llm pass done ({time.time()-t0:.0f}s)")

    # ---- per-item picks + margins for both embed tiers ----
    strata = [it[0].get("stratum", "?") for it in items]
    correct = [ci for _, _, ci in items]
    zs_pick, zs_margin = [], []
    cen_pick, cen_margin = [None] * n, [0.0] * n
    for i, (rec, sem, ci) in enumerate(items):
        ec = [c for _, c in sem]
        s = embedder.cosine(oq[i], np.asarray([cvec[c] for c in ec]))[0]
        top = np.argsort(s)[::-1]
        zs_pick.append(int(top[0]))
        zs_margin.append(float(s[top[0]] - s[top[1]]) if len(s) > 1 else 1.0)

    for f in range(FOLDS):                                # identical split to centroid.cross_validate
        train = [i for i in range(n) if i % FOLDS != f]
        test = [i for i in range(n) if i % FOLDS == f]
        by_cond: dict = {}
        for i in train:
            _r, sem, ci = items[i]
            by_cond.setdefault(sem[ci][1], []).append(op[i])
        cen = {c: _unit(np.mean(vs, axis=0)) for c, vs in by_cond.items()}
        cnt = {c: len(vs) for c, vs in by_cond.items()}
        for i in test:
            _r, sem, _ci = items[i]
            ec = [c for _, c in sem]
            eff = [(_unit(cvec[c]) if cnt.get(c, 0) == 0
                    else _unit((PRIOR * cvec[c] + cnt[c] * cen[c]) / (PRIOR + cnt[c])))
                   for c in ec]
            s = embedder.cosine(op[i], np.asarray(eff))[0]
            top = np.argsort(s)[::-1]
            cen_pick[i] = int(top[0])
            cen_margin[i] = float(s[top[0]] - s[top[1]]) if len(s) > 1 else 1.0

    # ---- the sweeps (pure post-processing) ----
    def sweep(pick, margin):
        rows = []
        for d in DELTAS:
            esc = [m < d for m in margin]
            final = [llm_pick[i] if esc[i] else pick[i] for i in range(n)]
            acc = {}
            for key in sorted(set(strata)) + ["ALL"]:
                idx = [i for i in range(n) if key == "ALL" or strata[i] == key]
                acc[key] = round(sum(final[i] == correct[i] for i in idx) / len(idx), 4)
            rows.append({"delta": d, "escalation": round(sum(esc) / n, 4), **acc})
        return rows

    result = {
        "config": {"n": n, "folds": FOLDS, "prior_weight": PRIOR, "model": MODEL,
                   "embedder": embedder.MODEL_NAME, "deltas": DELTAS},
        "llm_only": round(sum(llm_pick[i] == correct[i] for i in range(n)) / n, 4),
        "zero_shot_only": round(sum(zs_pick[i] == correct[i] for i in range(n)) / n, 4),
        "centroid_only_cv": round(sum(cen_pick[i] == correct[i] for i in range(n)) / n, 4),
        "hybrid_over_zero_shot": sweep(zs_pick, zs_margin),
        "hybrid_over_centroids": sweep(cen_pick, cen_margin),
    }
    json.dump(result, open(OUT, "w"), indent=1)
    print(json.dumps({k: v for k, v in result.items() if not k.startswith("hybrid")}, indent=1))
    print(f"\nwrote {OUT}")
    print("\nδ      | zs-acc  esc%   | cen-acc  esc%")
    for a, b in zip(result["hybrid_over_zero_shot"], result["hybrid_over_centroids"]):
        print(f"{a['delta']:<6} | {a['ALL']:.3f}  {a['escalation']*100:5.1f}%  | "
              f"{b['ALL']:.3f}  {b['escalation']*100:5.1f}%")


if __name__ == "__main__":
    main()
