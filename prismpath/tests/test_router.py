# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Router tests — exercise LLMRouter / HybridRouter WITHOUT loading any real model.

ORIGIN: the swarm (Qwen2.5-Coder-7B) authored the first version; it had the right structure
(stub embed router, fake generate_fn) but mis-modeled the real API: it defined the fake
generate with zero args (LLMRouter calls generate(prompt)) and passed `margin` as a route()
keyword (margin is a HybridRouter constructor arg, not a route() arg). This is the post-loop
CORRECTION: same intent, fixed to the real router contract. No sentence-transformers / torch.
"""
import pytest

from prismpath.routing.router import LLMRouter, HybridRouter, RouteDecision


class StubEmbedRouter:
    """Stand-in for EmbeddingRouter: returns a controllable margin/score so we can drive the
    HybridRouter's escalate / no-escalate branches deterministically."""
    def __init__(self, pick=0, margin=1.0, score=1.0):
        self.pick, self.margin, self.score = pick, margin, score

    def route(self, outcome, edges, instruction=''):
        return RouteDecision(edges[self.pick][0],
                             {"used": "embed", "score": self.score, "margin": self.margin})


def make_hybrid(margin_thresh, embed_pick=0, embed_margin=1.0, llm_returns="1"):
    router = HybridRouter(LLMRouter(lambda prompt: llm_returns), margin=margin_thresh)
    router.embed = StubEmbedRouter(pick=embed_pick, margin=embed_margin)   # inject the stub
    return router


EDGES2 = [("a", "cond a"), ("b", "cond b")]


def test_llmrouter_parses_number():
    router = LLMRouter(lambda prompt: "2")
    decision = router.route("outcome", EDGES2)
    assert isinstance(decision, RouteDecision)
    assert decision.target == "b"            # picked option 2 -> index 1
    assert decision.info["used"] == "llm"


def test_llmrouter_clamps_out_of_range():
    router = LLMRouter(lambda prompt: "99")   # out of range -> clamps to last valid edge
    decision = router.route("outcome", EDGES2)
    assert decision.target == "b"
    r2 = LLMRouter(lambda prompt: "no number here")  # no digit -> defaults to index 0
    d2 = r2.route("outcome", EDGES2)
    assert d2.target == "a"


def test_hybridrouter_single_edge():
    # one edge -> returns it with used=='single', never calling the LLM (nothing to disambiguate),
    # but it IS scored (absolute similarity) so a human_floor can still suspend a barely-matching
    # outcome instead of blindly taking the only edge. Scoring the lone edge embeds the outcome, so
    # this path needs the optional embedder — skip on a light (no-`[embeddings]`) install.
    pytest.importorskip("sentence_transformers")
    called = {"llm": False}
    router = HybridRouter(LLMRouter(lambda prompt: called.__setitem__("llm", True) or "1"))
    decision = router.route("outcome", [("only", "cond")])
    assert decision.target == "only"
    assert decision.info["used"] == "single"
    assert called["llm"] is False
    assert "score" in decision.info                      # scored, so human_floor can apply to a lone edge


def test_hybridrouter_no_escalate():
    # embed margin (0.5) >= threshold (0.08) -> use the embed pick, do NOT escalate.
    router = make_hybrid(margin_thresh=0.08, embed_pick=0, embed_margin=0.5)
    decision = router.route("outcome", EDGES2)
    assert decision.target == "a"
    assert decision.info["used"] == "embed"
    assert decision.info["escalated"] is False


def test_hybridrouter_escalate():
    # embed margin (0.01) < threshold (0.08) -> escalate to the LLM, which returns "2" -> 'b'.
    router = make_hybrid(margin_thresh=0.08, embed_pick=0, embed_margin=0.01, llm_returns="2")
    decision = router.route("outcome", EDGES2)
    assert decision.info["used"] == "llm"
    assert decision.info["escalated"] is True
    assert decision.target == "b"
    assert decision.info["embed_would_pick"] == "a"   # records what embed would have chosen
