# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
import pytest
from prismpath.kernel.parser import parse, parse_file, Graph, Node, ParseError
from prismpath.kernel import parser as _parser
from prismpath.kernel import analysis

def test_front_matter_parsing():
    text = """---
name: Test Workflow
start: my_node
---
## My Node
This is the instruction.
-> next_node: always
"""
    graph = parse(text)
    assert graph.name == "Test Workflow"
    assert graph.start == "my_node"
    assert len(graph.nodes) == 1
    node = graph.nodes['my_node']
    assert node.instruction == "This is the instruction."
    assert node.edges == [('next_node', 'always')]
    assert not node.terminal

def test_heading_to_node_name():
    text = """## My Node
Instruction text."""
    graph = parse(text)
    assert 'my_node' in graph.nodes
    node = graph.nodes['my_node']
    assert node.instruction == "Instruction text."

def test_edge_parsing():
    text = """## My Node
Instruction text.
-> next_node: always
-> another_node: never"""
    graph = parse(text)
    node = graph.nodes['my_node']
    assert node.edges == [('next_node', 'always'), ('another_node', 'never')]

def test_terminal_node():
    text = """## My Node
Instruction text."""
    graph = parse(text)
    node = graph.nodes['my_node']
    assert node.terminal

def test_default_start_node():
    text = """## My Node
Instruction text."""
    graph = parse(text)
    assert graph.start == "my_node"

def test_graph_validation():
    # post-loop fix: a valid graph needs the edge target to exist; and assert against the
    # real validate() format (a non-empty list naming the offending node + target).
    text = """## My Node
Instruction text.
-> next_node: always

## Next Node
Done."""
    graph = parse(text)
    assert analysis.errors(graph) == []

    text = """## My Node
Instruction text.
-> next_node: always
-> undefined_node: always"""
    graph = parse(text)
    problems = analysis.errors(graph)
    assert problems  # non-empty: both targets are undefined
    assert any("undefined_node" in problem for problem in problems)

def test_no_headings():
    text = "No headings here."
    graph = parse(text)
    assert graph.nodes == {}


# ── input bounds (hardening): untrusted/oversized documents fail fast, not fatally ──
def test_oversized_text_rejected(monkeypatch):
    monkeypatch.setattr(_parser, "MAX_FLOW_BYTES", 100)
    with pytest.raises(ParseError) as ei:
        parse("## n\n" + "x" * 500)
    assert "MAX_FLOW_BYTES" in str(ei.value)
    parse("## n\nshort")                                   # within the cap still parses


def test_too_many_nodes_rejected(monkeypatch):
    monkeypatch.setattr(_parser, "MAX_NODES", 3)
    doc = "".join(f"## n{index}\nbody\n" for index in range(10))
    with pytest.raises(ParseError) as ei:
        parse(doc)
    assert "MAX_NODES" in str(ei.value)


def test_repeated_heading_is_not_a_new_node(monkeypatch):
    # the node cap counts distinct names — re-declaring a heading must not trip it.
    monkeypatch.setattr(_parser, "MAX_NODES", 2)
    parse("## a\none\n## a\ntwo\n## b\nthree\n")            # two distinct names, under the cap


def test_too_many_edges_rejected(monkeypatch):
    monkeypatch.setattr(_parser, "MAX_EDGES", 3)
    doc = "## a\n" + "".join(f"-> t{index}: always\n" for index in range(10))
    with pytest.raises(ParseError) as ei:
        parse(doc)
    assert "MAX_EDGES" in str(ei.value)


def test_parse_file_gates_on_disk_size(tmp_path, monkeypatch):
    monkeypatch.setattr(_parser, "MAX_FLOW_BYTES", 50)
    big = tmp_path / "big.md"
    big.write_text("## n\n" + "y" * 500, encoding="utf-8")
    with pytest.raises(ParseError) as ei:
        parse_file(str(big))
    assert "MAX_FLOW_BYTES" in str(ei.value)


def test_parse_error_is_value_error():
    # Mission Control's 400 envelope funnels ValueError — ParseError must ride that path.
    assert issubclass(ParseError, ValueError)


if __name__ == "__main__":
    pytest.main()


# A rules source (prismpath/kernel/policy_source.py) is not a flow: its `-> refuse <cause>:` lines would read as
# prose, so the flow tools would see an allow only graph. The parser refuses it and points at `prismpath policy`.
_RULES = """---
name: r
start: core_decision
field.tool: category
---
## core_decision
-> refuse agent:network: when tool == "connect"
-> allow: always
"""


def test_a_rules_source_is_refused_with_its_line():
    from prismpath.kernel.parser import RulesSourceError
    with pytest.raises(RulesSourceError, match=r"line 7 is a rule of a rules source.*prismpath policy compile"):
        parse(_RULES)


def test_an_escalate_rule_is_refused_too():
    with pytest.raises(ParseError, match="rules source"):
        parse("## core_decision\n  - -> escalate agent:push-escalated: when git_op == \"push\"\n")


def test_a_rules_file_is_refused_by_its_name(tmp_path):
    path = tmp_path / "only_allow.rules.md"
    path.write_text("---\nstart: core_decision\n---\n## core_decision\n-> allow: always\n")
    with pytest.raises(ParseError, match="only_allow.rules.md is a rules source"):
        parse_file(str(path))


def test_every_shipped_rules_source_is_refused():
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    sources = sorted(root.glob("prismpath/**/*.rules.md")) + sorted(root.glob("integrations/**/*.rules.md"))
    assert len(sources) >= 6
    for path in sources:
        with pytest.raises(ParseError, match="rules source"):
            parse(path.read_text(encoding="utf-8"))


def test_a_rendered_core_image_still_parses_as_a_flow():
    # the canonical rendering of an image names causes by code (`refuse_106`), which is a flow edge
    graph = parse("---\nstart: core_decision\n---\n## core_decision\n-> refuse_106: when tool == \"connect\"\n")
    assert graph.nodes["core_decision"].edges == [("refuse_106", 'when tool == "connect"')]


def test_prose_that_mentions_refusing_is_still_prose():
    graph = parse("## a\nWe refuse -> nothing here.\n-> refuse later on, then stop\n")
    assert graph.nodes["a"].edges == []
