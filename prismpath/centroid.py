# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""centroid.py — prototype routing: the escalation tier as a teacher (roadmap item 2).

A zero-shot embedding router scores an outcome against the AUTHOR'S condition phrase and hopes real
outcomes land near it. But every labeled decision — from `prismpath test` fixtures, `prismpath label`, and
especially the LLM escalations the hybrid router already logs — is an (outcome, correct-edge) example.
So route against the **centroid of historical correct outcomes per edge**, shrinking toward the
condition-string prior when history is thin. With zero history a `CentroidRouter` IS the EmbeddingRouter
(pure prior); as the corpus grows it gets more accurate AND escalates less — the router teaches itself
to not need the LLM. It attacks the confident-error class directly: "correct per spec → close" fails
zero-shot on the word "correct", but a centroid built from real closures captures it.

This is pure data machinery: centroids are unit vectors, serializable/lockable exactly like the routing
lockfile's condition vectors, and rebuilt OFFLINE from the corpus (the engine stays pure).

Everything is in PASSAGE space (`is_query=False`) so it is a symmetric outcome-vs-{centroid,condition}
comparison — the natural "does this new outcome look like the outcomes that took this edge?" test.
"""
from __future__ import annotations

import os
from typing import Dict, List, Optional, Tuple

import numpy as np

from prismpath import embedder, predicates
from prismpath.router import EmbeddingRouter


def _unit(v: np.ndarray) -> np.ndarray:
    n = float(np.linalg.norm(v))
    return v / n if n else v


class CentroidRouter(EmbeddingRouter):
    """EmbeddingRouter variant: each edge's target vector is the shrunk mean of historical correct
    outcomes for that edge, falling back to the condition-string prior when history is thin. Drops into
    `HybridRouter(..., embed=CentroidRouter(...))` as the embed tier."""

    def __init__(self, centroids: Dict[str, np.ndarray], counts: Dict[str, int],
                 prior_weight: float = 4.0):
        super().__init__()
        self._centroids = centroids          # {condition_text: unit mean-outcome vector}
        self._counts = counts                # {condition_text: n examples}
        self._prior = float(prior_weight)    # pseudo-count weight on the condition prior (shrinkage)

    def scores(self, outcome, edges):
        qe = embedder.embed([outcome], is_query=False)[0]     # passage space (symmetric with centroids)
        return embedder.cosine(qe, self._cond_embs(edges))[0]

    def _cond_embs(self, edges):
        conds = [c for _, c in edges]
        priors = embedder.embed(conds, is_query=False)        # condition prior per edge (passage space)
        out = []
        for prior, cond in zip(priors, conds):
            n = self._counts.get(cond, 0)
            if n == 0:
                out.append(_unit(np.asarray(prior, dtype="float32")))
            else:                                             # James–Stein-style shrink toward the prior
                blended = (self._prior * prior + n * self._centroids[cond]) / (self._prior + n)
                out.append(_unit(blended))
        return np.asarray(out, dtype="float32")

    @classmethod
    def from_labeled(cls, records: List[dict], graphs: Optional[dict] = None,
                     flows_dir: Optional[str] = None, prior_weight: float = 4.0) -> "CentroidRouter":
        graphs = graphs if graphs is not None else load_graphs(records, flows_dir)
        centroids, counts = build_centroids(records, graphs)
        return cls(centroids, counts, prior_weight)


_FLOWS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flows")


def load_graphs(records: List[dict], flows_dir: Optional[str] = None) -> dict:
    from prismpath.parser import parse_file
    flows_dir = flows_dir or _FLOWS
    graphs = {}
    for r in records:
        f = r.get("flow")
        if f and f not in graphs:
            graphs[f] = parse_file(os.path.join(flows_dir, f"{f}.md"))
    return graphs


def record_condition(rec: dict, graphs: dict) -> Optional[str]:
    """The condition string of the edge a labeled record took. Handles records that carry the condition
    or `candidates` directly (routelog), else resolves node -> label-target -> condition via the flow."""
    if rec.get("condition"):
        return rec["condition"]
    label = rec.get("label") or rec.get("chosen")
    for cand in rec.get("candidates", []):
        if cand.get("target") == label:
            return cand.get("condition")
    g = graphs.get(rec.get("flow"))
    node = g.nodes.get(rec.get("node")) if g else None
    if node is not None:
        for t, c in node.edges:
            if t == label:
                return c
    return None


def _decision_items(records: List[dict], graphs: dict):
    """Keep records that are real semantic decisions (node has >=2 semantic edges, label is one of
    them). Returns [(record, sem_edges, correct_index)]."""
    items = []
    for rec in records:
        g = graphs.get(rec.get("flow"))
        node = g.nodes.get(rec.get("node")) if g else None
        if node is None:
            continue
        sem = [(t, c) for t, c in node.edges if predicates.is_semantic(c)]
        targets = [t for t, _ in sem]
        if len(sem) >= 2 and rec.get("label") in targets:
            items.append((rec, sem, targets.index(rec["label"])))
    return items


def cross_validate(records: List[dict], graphs: Optional[dict] = None, flows_dir: Optional[str] = None,
                   folds: int = 5, prior_weight: float = 4.0) -> dict:
    """Honest measurement: k-fold CV comparing the zero-shot EmbeddingRouter (query-outcome vs
    passage-condition) against the CentroidRouter (trained on the other folds), per stratum. Centroids
    are built ONLY from the train split, so there is no leakage. All embeddings are computed once."""
    from collections import defaultdict
    graphs = graphs if graphs is not None else load_graphs(records, flows_dir)
    items = _decision_items(records, graphs)
    if not items:
        return {}
    outs = [it[0]["outcome"] for it in items]
    oq = embedder.embed(outs, is_query=True)              # baseline outcome space (query)
    op = embedder.embed(outs, is_query=False)             # centroid outcome space (passage)
    conds = sorted({c for _, sem, _ in items for _, c in sem})
    cvec = {c: np.asarray(v, dtype="float32") for c, v in zip(conds, embedder.embed(conds, is_query=False))}

    tally = defaultdict(lambda: {"n": 0, "baseline": 0, "centroid": 0})
    for f in range(folds):
        train = [i for i in range(len(items)) if i % folds != f]
        test = [i for i in range(len(items)) if i % folds == f]
        by_cond = defaultdict(list)
        for i in train:                                   # centroid = mean train outcome for the correct edge
            _rec, sem, ci = items[i]
            by_cond[sem[ci][1]].append(op[i])
        cen = {c: _unit(np.mean(vs, axis=0)) for c, vs in by_cond.items()}
        cnt = {c: len(vs) for c, vs in by_cond.items()}
        for i in test:
            rec, sem, ci = items[i]
            ec = [c for _, c in sem]
            b_pick = int(np.argmax(embedder.cosine(oq[i], np.asarray([cvec[c] for c in ec]))[0]))
            eff = [(_unit(cvec[c]) if cnt.get(c, 0) == 0
                    else _unit((prior_weight * cvec[c] + cnt[c] * cen[c]) / (prior_weight + cnt[c])))
                   for c in ec]
            c_pick = int(np.argmax(embedder.cosine(op[i], np.asarray(eff))[0]))
            for key in (rec.get("stratum", "?"), "ALL"):
                tally[key]["n"] += 1
                tally[key]["baseline"] += int(b_pick == ci)
                tally[key]["centroid"] += int(c_pick == ci)

    out = {k: {"n": v["n"], "baseline": round(v["baseline"] / v["n"], 4),
               "centroid": round(v["centroid"] / v["n"], 4),
               "delta": round((v["centroid"] - v["baseline"]) / v["n"], 4)}
           for k, v in tally.items()}
    out["config"] = {"folds": folds, "prior_weight": prior_weight, "n_decisions": len(items)}
    return out


def build_centroids(records: List[dict], graphs: dict) -> Tuple[Dict[str, np.ndarray], Dict[str, int]]:
    """{condition: unit mean-outcome vector}, {condition: n} over labeled records. Only SEMANTIC
    conditions get centroids (deterministic/error/event edges don't route by embedding)."""
    by_cond: Dict[str, List[str]] = {}
    for rec in records:
        cond = record_condition(rec, graphs)
        outcome = rec.get("outcome") or rec.get("outcome_text")
        if cond and outcome and predicates.is_semantic(cond):
            by_cond.setdefault(cond, []).append(outcome)
    centroids, counts = {}, {}
    for cond, outs in by_cond.items():
        vecs = embedder.embed(outs, is_query=False)
        centroids[cond] = _unit(np.mean(vecs, axis=0).astype("float32"))
        counts[cond] = len(outs)
    return centroids, counts
