"""flow_context — the kernel publishes its own PROVEN facts about a flow as agent grounding."""
from prismpath.parser import parse
from prismpath.flow_context import flow_context, render_context

_CLEAN = """---
name: t
start: a
---
## a
-> b: when score > 5
-> c: the user is angry
-> d: else
## b
x
## c
y
## d
z
"""

_UNREACHABLE = """---
name: u
start: a
---
## a
-> done: else
## orphan
-> done: else
## done
end
"""


def test_context_keys_and_counts():
    facts = flow_context(parse(_CLEAN))
    assert set(facts) >= {"name", "start", "n_nodes", "n_edges", "nodes", "fields",
                          "terminal_nodes", "reachability", "unreachable_nodes",
                          "level_m", "capability", "findings"}
    assert facts["n_nodes"] == 4
    assert facts["n_edges"] == 3
    assert facts["start"] == "a"
    assert facts["fields"] == ["score"]                 # only the deterministic edge reads a field
    assert set(facts["terminal_nodes"]) == {"b", "c", "d"}


def test_edge_tiers_classified():
    facts = flow_context(parse(_CLEAN))
    a = next(n for n in facts["nodes"] if n["name"] == "a")
    vias = {e["target"]: e["via"] for e in a["edges"]}
    assert vias == {"b": "deterministic", "c": "semantic", "d": "deterministic"}  # 'else' is deterministic


def test_unreachable_node_is_proven():
    facts = flow_context(parse(_UNREACHABLE))
    assert "orphan" in facts["unreachable_nodes"]
    assert facts["reachability"]["orphan"]["reachable"] == "no"
    assert facts["reachability"]["orphan"]["proven"] is True
    assert any(f["code"] == "unreachable-node" for f in facts["findings"])


def test_render_is_grounding_prose():
    text = render_context(flow_context(parse(_UNREACHABLE)))
    assert "do not contradict" in text
    assert "UNREACHABLE" in text
    assert "orphan" in text
