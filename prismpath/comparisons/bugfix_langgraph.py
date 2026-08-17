# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""bugfix_langgraph.py — the `bugfix` flow expressed in LangGraph, as an Area-5 baseline.

Reference implementation (requires `pip install langgraph langchain-openai` and an OpenAI-compatible
endpoint). Its purpose is the comparison: it shows *where LangGraph's control flow lives* versus
prismpath's — in Python routing functions over a typed state object, not in a readable document.

The same three intent edges prismpath authors as prose in `flows/bugfix.md`:

    ## triage
    -> implement: the bug is reproduced and the root cause is clear
    -> gather_info: it cannot be reproduced or more information is needed
    -> close: it is a duplicate or an invalid report

become, in LangGraph, a `StateGraph` whose conditional edge is a Python function. A LangGraph user
routes a *content-based* branch by calling an LLM inside that function (there is no embedding tier,
no margin, no escalation, no routing-cost model) — which is exactly what `route_triage` below does,
and exactly the per-hop LLM call the measured table in comparisons/README.md counts. A bad route
traces to this function, not to a heading and a condition a PM can read, diff, and approve.

Run:  python -m prismpath.comparisons.bugfix_langgraph
"""
from __future__ import annotations

import os

from prismpath.comparisons.gemma import BASE, KEY, MODEL, routing_prompt

try:
    from langchain_openai import ChatOpenAI
    from langgraph.graph import END, StateGraph
    HAVE_LANGGRAPH = True
except Exception:                                    # keep the file importable without langgraph
    HAVE_LANGGRAPH = False


def _pick(llm, instruction, outcome, edges) -> str:
    """One LLM call in the routing function — the idiomatic LangGraph content-based branch."""
    import re
    raw = llm.invoke(routing_prompt(instruction, outcome, edges)).content
    m = re.search(r"\d+", raw or "")
    idx = max(0, min((int(m.group()) - 1) if m else 0, len(edges) - 1))
    return edges[idx][0]


def build_app():
    """The bugfix graph as a StateGraph. State is a dict; every branch is a Python routing fn."""
    llm = ChatOpenAI(base_url=BASE, api_key=KEY, model=MODEL, temperature=0, max_tokens=16)

    def triage(state):        # the work node would call an agent; here it just carries the outcome
        return state

    def route_triage(state):  # CONTROL FLOW IN CODE — an LLM call, no readable per-edge condition
        edges = [("implement", "the bug is reproduced and the root cause is clear"),
                 ("gather_info", "it cannot be reproduced or more information is needed"),
                 ("close", "it is a duplicate or an invalid report")]
        return _pick(llm, "Read the bug report and decide what to do next.",
                     state.get("outcome", ""), edges)

    g = StateGraph(dict)
    g.add_node("triage", triage)
    for leaf in ("implement", "gather_info", "close"):
        g.add_node(leaf, lambda s: s)
        g.add_edge(leaf, END)
    g.set_entry_point("triage")
    g.add_conditional_edges("triage", route_triage,
                            {"implement": "implement", "gather_info": "gather_info", "close": "close"})
    return g.compile()


def main():
    if not HAVE_LANGGRAPH:
        print("langgraph not installed — this is a reference baseline for comparisons/README.md.\n"
              "Install with `pip install langgraph langchain-openai` to run it.")
        return
    app = build_app()
    outcome = os.environ.get("OUTCOME",
                             "I reproduced the crash; it's a null dereference in parse_config().")
    app.invoke({"outcome": outcome}, {"recursion_limit": 5})
    # the routing decision is what the comparison measures; re-derive it for a human-visible print
    from langchain_openai import ChatOpenAI as _C
    llm = _C(base_url=BASE, api_key=KEY, model=MODEL, temperature=0, max_tokens=16)
    edges = [("implement", "the bug is reproduced and the root cause is clear"),
             ("gather_info", "it cannot be reproduced or more information is needed"),
             ("close", "it is a duplicate or an invalid report")]
    print("routed to:", _pick(llm, "Read the bug report and decide what to do next.", outcome, edges))


if __name__ == "__main__":
    main()
