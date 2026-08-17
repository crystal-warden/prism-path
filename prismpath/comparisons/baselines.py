# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The four Area-5 routing baselines, each making its decision the way that stack idiomatically does.

Every baseline exposes:
    .name        short id for the table
    .available   True iff its framework imported
    .warm(cases) optional cache warmup (prismpath embeds the conditions once)
    .decide(instruction, outcome, edges) -> (target, n_llm_calls, wallclock_seconds)

They all consult the SAME gemma endpoint with the SAME `routing_prompt`, so accuracy differences
are the *strategy's* (embed-first-then-LLM-on-doubt vs LLM-every-hop) and latency differences include
each framework's real machinery — not a prompt or model advantage on one side.

Faithfulness of the mapping (documented, per the Area-5 plan):
  - LLM-router  : one model call per transition. The naive "just ask the model" baseline.
  - LangGraph   : a real StateGraph; the semantic decision is an LLM call *inside the routing
                  function* — exactly how a LangGraph user writes a content-based branch.
  - CrewAI      : a real Flow; the decision is an LLM call *inside an @router method* — CrewAI's
                  only conditional-branch mechanism. Structurally identical to LangGraph (control
                  flow in Python), which is the point the comparison makes.
  - prismpath      : the hybrid router — embeddings settle confident hops for free, the LLM is consulted
                  ONLY when the embedding margin is under delta (=0.05).
"""
from __future__ import annotations

import re
import time

from prismpath.comparisons.gemma import BASE, KEY, MODEL, Gemma, routing_prompt


def _parse_choice(raw: str, n: int) -> int:
    m = re.search(r"\d+", raw or "")
    idx = (int(m.group()) - 1) if m else 0
    return max(0, min(idx, n - 1))


# --------------------------------------------------------------------------- prismpath
class PrismPathBaseline:
    name = "prismpath"
    available = True

    def __init__(self, margin: float = 0.05, temperature: float = 0.0):
        from prismpath.router import EmbeddingRouter, HybridRouter, LLMRouter
        self.gemma = Gemma(temperature=temperature)
        self._embed = EmbeddingRouter()
        self.router = HybridRouter(LLMRouter(self.gemma.generate), margin=margin, embed=self._embed)

    def warm(self, cases):
        for c in cases:
            edges = c[-1]
            if len(edges) > 1:
                self._embed._cond_embs(edges)   # populate the condition-embedding cache

    def decide(self, instruction, outcome, edges):
        self.gemma.calls = 0
        t = time.perf_counter()
        d = self.router.route(outcome, edges, instruction)
        return d.target, self.gemma.calls, time.perf_counter() - t


# --------------------------------------------------------------------------- LLM-router
class LLMRouterBaseline:
    name = "llm_router"
    available = True

    def __init__(self, temperature: float = 0.0):
        from prismpath.router import LLMRouter
        self.gemma = Gemma(temperature=temperature)
        self.router = LLMRouter(self.gemma.generate)

    def warm(self, cases):
        pass

    def decide(self, instruction, outcome, edges):
        if len(edges) == 1:
            return edges[0][0], 0, 0.0
        self.gemma.calls = 0
        t = time.perf_counter()
        d = self.router.route(outcome, edges, instruction)
        return d.target, self.gemma.calls, time.perf_counter() - t


# --------------------------------------------------------------------------- LangGraph
class LangGraphBaseline:
    """A real StateGraph. One entry node fans out via a conditional-edge function whose body is an
    LLM call (langchain-openai ChatOpenAI) — the idiomatic way a LangGraph user branches on content.
    We invoke the graph once per decision and read back the landed target."""
    name = "langgraph"

    def __init__(self, temperature: float = 0.0):
        self.available = False
        self._calls = 0
        try:
            from langchain_openai import ChatOpenAI
            from langgraph.graph import END, StateGraph
        except Exception:
            return
        self._llm = ChatOpenAI(base_url=BASE, api_key=KEY, model=MODEL,
                               temperature=temperature, max_tokens=16)
        self._StateGraph, self._END = StateGraph, END
        self.available = True

    _calls = 0
    _last_target = None

    def warm(self, cases):
        pass

    def _build(self, instruction, outcome, edges):
        StateGraph, END = self._StateGraph, self._END
        targets = [t for t, _ in edges]
        uniq = list(dict.fromkeys(targets))          # dedupe, keep order
        prompt = routing_prompt(instruction, outcome, edges)

        def route_fn(state):                          # the conditional edge: an LLM call in code
            raw = self._llm.invoke(prompt).content
            self._calls += 1
            self._last_target = targets[_parse_choice(raw, len(targets))]
            return self._last_target

        g = StateGraph(dict)
        g.add_node("entry", lambda s: s)
        for t in uniq:
            g.add_node(t, lambda s: s)
            g.add_edge(t, END)
        g.set_entry_point("entry")
        g.add_conditional_edges("entry", route_fn, {t: t for t in uniq})
        return g.compile()

    def decide(self, instruction, outcome, edges):
        if len(edges) == 1:
            return edges[0][0], 0, 0.0
        app = self._build(instruction, outcome, edges)
        self._calls = 0
        t = time.perf_counter()
        app.invoke({"outcome": outcome}, {"recursion_limit": 5})
        dt = time.perf_counter() - t
        return self._last_target, self._calls, dt


# --------------------------------------------------------------------------- CrewAI
# CrewAI Flows register @start/@router at class-definition time and round-trip state only through a
# typed `Flow[State]` model (see comparisons/bugfix_crewai.py). So the flow class is module-level and
# reads its dependencies from a context the baseline sets before each kickoff.
_CREW_CTX: dict = {}


def _make_crew_flow():
    from crewai.flow.flow import Flow, router, start
    from pydantic import BaseModel

    class _RState(BaseModel):
        pass

    class RouteFlow(Flow[_RState]):
        # NB: method names must NOT start with "_" — crewai's Flow metaclass skips private methods,
        # so an underscore-prefixed @start/@router silently never registers as a flow step.
        @start()
        def begin(self):
            return "go"

        @router(begin)
        def route(self):
            ctx = _CREW_CTX
            prompt = routing_prompt(ctx["instruction"], ctx["outcome"], ctx["edges"])
            raw = ctx["llm"].call(prompt)                 # the LLM call inside the @router method
            ctx["calls"] += 1
            targets = [t for t, _ in ctx["edges"]]
            ctx["target"] = targets[_parse_choice(raw, len(targets))]
            return ctx["target"]

    return RouteFlow


class CrewAIBaseline:
    """A real CrewAI Flow. The decision lives in an @router method whose body is an LLM call — the
    only conditional-branch mechanism CrewAI offers. We kick off the flow once per decision; the
    @router's returned label IS the routing choice."""
    name = "crewai"

    def __init__(self, temperature: float = 0.0):
        self.available = False
        try:
            from crewai import LLM
            self._flow_cls = _make_crew_flow()
        except Exception:
            return
        self._llm = LLM(model=f"openai/{MODEL}", base_url=BASE, api_key=KEY,
                        temperature=temperature, max_tokens=16)
        self.available = True

    def warm(self, cases):
        pass

    def decide(self, instruction, outcome, edges):
        if len(edges) == 1:
            return edges[0][0], 0, 0.0
        _CREW_CTX.clear()
        _CREW_CTX.update(instruction=instruction, outcome=outcome, edges=edges,
                         llm=self._llm, calls=0, target=None)
        flow = self._flow_cls()
        t = time.perf_counter()
        flow.kickoff()
        dt = time.perf_counter() - t
        return _CREW_CTX["target"], _CREW_CTX["calls"], dt


def all_baselines(margin: float = 0.05, temperature: float = 0.0):
    return [
        PrismPathBaseline(margin=margin, temperature=temperature),
        LLMRouterBaseline(temperature=temperature),
        LangGraphBaseline(temperature=temperature),
        CrewAIBaseline(temperature=temperature),
    ]
