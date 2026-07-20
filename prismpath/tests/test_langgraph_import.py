"""LangGraph-importer tests (critic #6) — AST-only, no langgraph install needed."""
from prismpath import langgraph_import
from prismpath.parser import parse

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
    g = parse(md)                                          # the skeleton must at least parse
    assert g.start == "triage"
    assert set(g.nodes) >= {"triage", "implement", "review", "done"}
    # deterministic edges from add_edge
    assert ("review", "done", "when always") in _edges(g)
    assert ("implement", "review", "when always") in _edges(g)
    # conditional edge -> a TODO condition the human fills in
    todo = [(t, c) for t, c in g.nodes["triage"].edges if "TODO" in c]
    assert any(t == "implement" for t, _ in todo)
    assert g.nodes["done"].terminal


def _edges(g):
    return [(name, t, c) for name, n in g.nodes.items() for t, c in n.edges]


def test_set_entry_point_form():
    src = ('g = StateGraph(dict)\n'
           'g.add_node("a", a)\n'
           'g.set_entry_point("a")\n'
           'g.add_edge("a", END)\n')
    g = parse(langgraph_import.import_langgraph(src))
    assert g.start == "a" and ("a", "done", "when always") in _edges(g)
