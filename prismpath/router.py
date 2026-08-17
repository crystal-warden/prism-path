# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Routers for prismpath: Embedding (cheap), LLM (accurate), Hybrid (embed-first, LLM-on-doubt).

A router maps (outcome, edges, instruction) -> RouteDecision(target, info). The Hybrid router
is the point of this design: embeddings settle the confident transitions for free, and a
one-shot LLM is consulted ONLY when the embedding decision is low-confidence (small top-1↔top-2
margin or low absolute score) — keeping LLM calls rare while fixing the cases embeddings get
wrong (negation, abstraction mismatch, near-ties).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Tuple

import numpy as np

from prismpath import embedder


@dataclass
class RouteDecision:
    target: str
    info: dict = field(default_factory=dict)


class EmbeddingRouter:
    def __init__(self):
        self._cache: Dict[tuple, np.ndarray] = {}

    def _cond_embs(self, edges):
        key = tuple(c for _, c in edges)
        if key not in self._cache:
            self._cache[key] = embedder.embed(list(key), is_query=False)
        return self._cache[key]

    def scores(self, outcome, edges):
        qe = embedder.embed([outcome], is_query=True)
        return embedder.cosine(qe, self._cond_embs(edges))[0]

    def route(self, outcome, edges, instruction="") -> RouteDecision:
        if not edges:
            raise ValueError("route() called with no edges")
        sims = self.scores(outcome, edges)
        order = np.argsort(-sims)
        top1 = int(order[0])
        margin = float(sims[order[0]] - sims[order[1]]) if len(order) > 1 else 1.0
        return RouteDecision(edges[top1][0], {
            "used": "embed", "score": float(sims[top1]), "margin": margin,
            "sims": {t: float(s) for (t, _), s in zip(edges, sims)}})


class LockedEmbeddingRouter(EmbeddingRouter):
    """EmbeddingRouter that routes conditions against **committed vectors from a routing lockfile**
    instead of embedding them live — so the condition side of every decision is bit-for-bit
    reproducible across machines, installs, and embedder versions. The outcome is still embedded by
    the local embedder (which the lock's fingerprint verifies), and the recorded `margin`/`score`
    therefore reproduce exactly whenever the embedder matches the lock. See `prismpath.lockfile`."""
    def __init__(self, conditions: Dict[str, np.ndarray]):
        super().__init__()
        self._locked = conditions      # {condition_text: unit-normalized np.ndarray}

    def _cond_embs(self, edges):
        out = []
        for _, c in edges:
            v = self._locked.get(c)
            if v is None:
                raise KeyError(f"condition not in lock: {c!r} — the flow changed; re-run `prismpath lock`")
            out.append(v)
        return np.asarray(out, dtype="float32")

    def route(self, outcome, edges, instruction="") -> RouteDecision:
        d = super().route(outcome, edges, instruction)
        d.info["locked"] = True
        return d


class LLMRouter:
    def __init__(self, generate_fn: Callable[[str], str]):
        self.generate = generate_fn

    def route(self, outcome, edges, instruction="") -> RouteDecision:
        opts = "\n".join(f"{i+1}. {cond}" for i, (_, cond) in enumerate(edges))
        prompt = (
            "You route a workflow. Given the current step and the outcome of the work, pick "
            "the ONE option that best matches what should happen next.\n\n"
            f"Current step: {instruction}\n"
            f"Outcome of the work: {outcome}\n\n"
            f"Options:\n{opts}\n\n"
            "Reply with ONLY the number of the best option.")
        raw = self.generate(prompt)
        m = re.search(r"\d+", raw)
        idx = (int(m.group()) - 1) if m else 0
        idx = max(0, min(idx, len(edges) - 1))
        return RouteDecision(edges[idx][0],
                             {"used": "llm", "raw": raw, "picked": idx + 1})


class HybridRouter:
    def __init__(self, llm_router: LLMRouter, margin: float = 0.05, min_score: float = 0.0,
                 embed=None):
        self.embed = embed if embed is not None else EmbeddingRouter()
        self.llm = llm_router
        self.margin = margin
        self.min_score = min_score

    def route(self, outcome, edges, instruction="") -> RouteDecision:
        if len(edges) == 1:
            # One target, so there is nothing for the LLM to disambiguate — but we still SCORE the
            # lone edge (absolute similarity) so a `human_floor` can suspend a barely-matching
            # outcome instead of blindly taking the only edge. `used="single"` records the tier.
            d = self.embed.route(outcome, edges, instruction)
            d.info["used"] = "single"
            return d
        d = self.embed.route(outcome, edges, instruction)
        confident = d.info["margin"] >= self.margin and d.info["score"] >= self.min_score
        if confident:
            d.info["escalated"] = False
            return d
        # low confidence -> consult the LLM
        ld = self.llm.route(outcome, edges, instruction)
        ld.info.update({"escalated": True, "embed_would_pick": d.target,
                        "embed_margin": d.info["margin"], "embed_score": d.info["score"]})
        return ld
