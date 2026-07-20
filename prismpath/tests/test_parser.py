import pytest
from prismpath.parser import parse, Graph, Node

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

if __name__ == "__main__":
    pytest.main()
