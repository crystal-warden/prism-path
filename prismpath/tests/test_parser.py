import pytest
from prismpath.parser import parse, parse_file, Graph, Node, ParseError
from prismpath import parser as _parser

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
    assert graph.validate() == []

    text = """## My Node
Instruction text.
-> next_node: always
-> undefined_node: always"""
    graph = parse(text)
    problems = graph.validate()
    assert problems  # non-empty: both targets are undefined
    assert any("undefined_node" in p for p in problems)

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
    doc = "".join(f"## n{i}\nbody\n" for i in range(10))
    with pytest.raises(ParseError) as ei:
        parse(doc)
    assert "MAX_NODES" in str(ei.value)


def test_repeated_heading_is_not_a_new_node(monkeypatch):
    # the node cap counts distinct names — re-declaring a heading must not trip it.
    monkeypatch.setattr(_parser, "MAX_NODES", 2)
    parse("## a\none\n## a\ntwo\n## b\nthree\n")            # two distinct names, under the cap


def test_too_many_edges_rejected(monkeypatch):
    monkeypatch.setattr(_parser, "MAX_EDGES", 3)
    doc = "## a\n" + "".join(f"-> t{i}: always\n" for i in range(10))
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
