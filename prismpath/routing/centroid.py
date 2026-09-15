# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""centroid.py - prototype routing: the escalation tier as a teacher (roadmap item 2).

A zero-shot embedding router scores an outcome against the AUTHOR'S condition phrase and hopes real
outcomes land near it. But every labeled decision - from `prismpath test` fixtures, `prismpath label`, and
especially the LLM escalations the hybrid router already logs - is an (outcome, correct-edge) example.
So route against the **centroid of historical correct outcomes per edge**, shrinking toward the
condition-string prior when history is thin. With zero history a `CentroidRouter` IS the EmbeddingRouter
(pure prior); as the corpus grows it gets more accurate AND escalates less - the router teaches itself
to not need the LLM. It attacks the confident-error class directly: "correct per spec -> close" fails
zero-shot on the word "correct", but a centroid built from real closures captures it.

This is pure data machinery: centroids are unit vectors, serializable/lockable exactly like the routing
lockfile's condition vectors, and rebuilt OFFLINE from the corpus (the engine stays pure).

Everything is in PASSAGE space (`is_query=False`) so it is a symmetric outcome-vs-{centroid,condition}
comparison - the natural "does this new outcome look like the outcomes that took this edge?" test.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Tuple

from prismpath.routing import embedder
from prismpath.kernel import predicates
from prismpath.routing.router import EmbeddingRouter


def _unit(vec):
    import numpy as np
    norm = float(np.linalg.norm(vec))
    return vec / norm if norm else vec


class CentroidRouter(EmbeddingRouter):
    """EmbeddingRouter variant: each edge's target vector is the shrunk mean of historical correct
    outcomes for that edge, falling back to the condition-string prior when history is thin. Drops into
    `HybridRouter(..., embed=CentroidRouter(...))` as the embed tier."""

    def __init__(self, centroids: Dict[str, Any], counts: Dict[str, int],
                 prior_weight: float = 4.0):
        super().__init__()
        self._centroids = centroids          # {condition_text: unit mean-outcome vector}
        self._counts = counts                # {condition_text: n examples}
        self._prior = float(prior_weight)    # pseudo-count weight on the condition prior (shrinkage)

    def scores(self, outcome, edges):
        qe = embedder.embed([outcome], is_query=False)[0]     # passage space (symmetric with centroids)
        return embedder.cosine(qe, self._cond_embs(edges))[0]

    def _cond_embs(self, edges):
        import numpy as np
        conds = [condition for _, condition in edges]
        priors = embedder.embed(conds, is_query=False)        # condition prior per edge (passage space)
        out = []
        for prior, condition in zip(priors, conds):
            count_val = self._counts.get(condition, 0)
            if count_val == 0:
                out.append(_unit(np.asarray(prior, dtype="float32")))
            else:                                             # James-Stein-style shrink toward the prior
                blended = (self._prior * prior + count_val * self._centroids[condition]) / (self._prior + count_val)
                out.append(_unit(blended))
        return np.asarray(out, dtype="float32")

    @classmethod
    def from_labeled(cls, records: List[dict], graphs: Optional[dict] = None,
                     flows_dir: Optional[str] = None, prior_weight: float = 4.0) -> "CentroidRouter":
        graphs = graphs if graphs is not None else load_graphs(records, flows_dir)
        centroids, counts = build_centroids(records, graphs)
        return cls(centroids, counts, prior_weight)


_FLOWS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "flows")


def load_graphs(records: List[dict], flows_dir: Optional[str] = None) -> dict:
    from prismpath.kernel.parser import parse_file
    flows_dir = flows_dir or _FLOWS
    graphs = {}
    for record in records:
        flow_name = record.get("flow")
        if flow_name and flow_name not in graphs:
            graphs[flow_name] = parse_file(os.path.join(flows_dir, f"{flow_name}.md"))
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
    graph = graphs.get(rec.get("flow"))
    node = graph.nodes.get(rec.get("node")) if graph else None
    if node is not None:
        for target, condition in node.edges:
            if target == label:
                return condition
    return None


def _decision_items(records: List[dict], graphs: dict):
    """Keep records that are real semantic decisions (node has >=2 semantic edges, label is one of
    them). Returns [(record, sem_edges, correct_index)]."""
    items = []
    for record in records:
        graph = graphs.get(record.get("flow"))
        node = graph.nodes.get(record.get("node")) if graph else None
        if node is None:
            continue
        sem = [(target, condition) for target, condition in node.edges if predicates.is_semantic(condition)]
        targets = [target for target, _ in sem]
        if len(sem) >= 2 and record.get("label") in targets:
            items.append((record, sem, targets.index(record["label"])))
    return items


def cross_validate(records: List[dict], graphs: Optional[dict] = None, flows_dir: Optional[str] = None,
                   folds: int = 5, prior_weight: float = 4.0) -> dict:
    """Honest measurement: k-fold CV comparing the zero-shot EmbeddingRouter (query-outcome vs
    passage-condition) against the CentroidRouter (trained on the other folds), per stratum. Centroids
    are built ONLY from the train split, so there is no leakage. All embeddings are computed once."""
    from collections import defaultdict
    import numpy as np
    graphs = graphs if graphs is not None else load_graphs(records, flows_dir)
    items = _decision_items(records, graphs)
    if not items:
        return {}
    outs = [item[0]["outcome"] for item in items]
    outcome_query_vecs = embedder.embed(outs, is_query=True)              # baseline outcome space (query)
    outcome_passage_vecs = embedder.embed(outs, is_query=False)             # centroid outcome space (passage)
    conds = sorted({condition for _, sem, _ in items for _, condition in sem})
    condition_vecs = {condition: np.asarray(vec, dtype="float32") for condition, vec in zip(conds, embedder.embed(conds, is_query=False))}

    tally = defaultdict(lambda: {"n": 0, "baseline": 0, "centroid": 0})
    for fold in range(folds):
        train = [index for index in range(len(items)) if index % folds != fold]
        test = [index for index in range(len(items)) if index % folds == fold]
        by_cond = defaultdict(list)
        for index in train:                                   # centroid = mean train outcome for the correct edge
            _rec, sem, correct_index = items[index]
            by_cond[sem[correct_index][1]].append(outcome_passage_vecs[index])
        train_centroids = {condition: _unit(np.mean(vecs, axis=0)) for condition, vecs in by_cond.items()}
        train_counts = {condition: len(vecs) for condition, vecs in by_cond.items()}
        for index in test:
            record, sem, correct_index = items[index]
            edge_conditions = [condition for _, condition in sem]
            baseline_choice = int(np.argmax(embedder.cosine(outcome_query_vecs[index], np.asarray([condition_vecs[condition] for condition in edge_conditions]))[0]))
            shrunk_vecs = [(_unit(condition_vecs[condition]) if train_counts.get(condition, 0) == 0
                            else _unit((prior_weight * condition_vecs[condition] + train_counts[condition] * train_centroids[condition]) / (prior_weight + train_counts[condition])))
                           for condition in edge_conditions]
            centroid_choice = int(np.argmax(embedder.cosine(outcome_passage_vecs[index], np.asarray(shrunk_vecs))[0]))
            for key in (record.get("stratum", "?"), "ALL"):
                tally[key]["n"] += 1
                tally[key]["baseline"] += int(baseline_choice == correct_index)
                tally[key]["centroid"] += int(centroid_choice == correct_index)

    out = {key: {"n": val["n"], "baseline": round(val["baseline"] / val["n"], 4),
                 "centroid": round(val["centroid"] / val["n"], 4),
                 "delta": round((val["centroid"] - val["baseline"]) / val["n"], 4)}
           for key, val in tally.items()}
    out["config"] = {"folds": folds, "prior_weight": prior_weight, "n_decisions": len(items)}
    return out


def build_centroids(records: List[dict], graphs: dict) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """{condition: unit mean-outcome vector}, {condition: n} over labeled records. Only SEMANTIC
    conditions get centroids (deterministic/error/event edges don't route by embedding)."""
    import numpy as np
    by_cond: Dict[str, List[str]] = {}
    for record in records:
        condition = record_condition(record, graphs)
        outcome = record.get("outcome") or record.get("outcome_text")
        if condition and outcome and predicates.is_semantic(condition):
            by_cond.setdefault(condition, []).append(outcome)
    centroids, counts = {}, {}
    for condition, outs in by_cond.items():
        vecs = embedder.embed(outs, is_query=False)
        centroids[condition] = _unit(np.mean(vecs, axis=0).astype("float32"))
        counts[condition] = len(outs)
    return centroids, counts
