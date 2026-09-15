# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""LangGraph-importer tests (critic #6) — AST-only, no langgraph install needed."""
from prismpath.workers import langgraph_import
from prismpath.kernel.parser import parse

SOURCE = '''
from langgraph.graph import StateGraph, START, END

def triage(state): ...
def implement(state): ...
def review(state): ...

def route_triage(state):
    return "implement" if state["ok"] else "close"

g = StateGraph(dict)
g.add_node("triage", triage)
g.add_node("implement", implement)
g.add_node("review", review)
g.add_edge(START, "triage")
g.add_conditional_edges("triage", route_triage, {"implement": "implement", "close": END})
g.add_edge("implement", "review")
g.add_edge("review", END)
'''


def test_import_produces_valid_flow():
    md = langgraph_import.import_langgraph(SOURCE, name="bugfix")
    graph = parse(md)                                          # the skeleton must at least parse
    assert graph.start == "triage"
    assert set(graph.nodes) >= {"triage", "implement", "review", "done"}
    # deterministic edges from add_edge
    assert ("review", "done", "when always") in _edges(graph)
    assert ("implement", "review", "when always") in _edges(graph)
    # conditional edge -> a TODO condition the human fills in
    todo = [(target, condition) for target, condition in graph.nodes["triage"].edges if "TODO" in condition]
    assert any(target == "implement" for target, _ in todo)
    assert graph.nodes["done"].terminal


def _edges(graph):
    return [(name, target, condition) for name, node in graph.nodes.items() for target, condition in node.edges]


def test_set_entry_point_form():
    src = ('g = StateGraph(dict)\n'
           'g.add_node("a", a)\n'
           'g.set_entry_point("a")\n'
           'g.add_edge("a", END)\n')
    graph = parse(langgraph_import.import_langgraph(src))
    assert graph.start == "a" and ("a", "done", "when always") in _edges(graph)
