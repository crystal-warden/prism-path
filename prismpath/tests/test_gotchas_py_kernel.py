# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Regression tests for the gotchas the 2026-09-12 kernel review found.

One test per fix, each pinning the behavior the review said was wrong: the component search no
longer trades a RecursionError for a C stack overflow, a lockfile that exists but cannot be read is
reported instead of silently read as no lock, and the compile report's size figure is a count of
bytes rather than three quarters of a base64 length.
"""
import sys

from prismpath.kernel import analysis
from prismpath.kernel.parser import Graph, Node, parse_file


def _chain(length: int) -> Graph:
    """A flow of `length` nodes in one line, the shape that puts the component search at its
    deepest: node 0 -> node 1 -> ... -> node length-1."""
    nodes = {}
    for position in range(length):
        edges = [(f"n{position + 1}", "when always")] if position + 1 < length else []
        nodes[f"n{position}"] = Node(name=f"n{position}", instruction="step", edges=edges)
    return Graph(name="chain", start="n0", nodes=nodes)


def test_sccs_walks_a_chain_deeper_than_the_recursion_limit(monkeypatch):
    # the limit is frozen at its default: a recursive search would raise RecursionError here, and
    # with the limit raised far enough to admit the chain it would overflow the C stack instead
    monkeypatch.setattr(sys, "setrecursionlimit", lambda _limit: None)
    depth = sys.getrecursionlimit() * 4
    components = analysis._sccs(_chain(depth))
    assert len(components) == depth
    assert all(len(component) == 1 for component in components)


def test_sccs_still_finds_a_cycle():
    graph = _chain(4)
    graph.nodes["n3"].edges.append(("n1", "when again"))
    cyclic = [component for component in analysis._sccs(graph) if len(component) > 1]
    assert cyclic == [{"n1", "n2", "n3"}]


def test_sccs_leaves_the_recursion_limit_alone():
    before = sys.getrecursionlimit()
    analysis._sccs(_chain(50))
    assert sys.getrecursionlimit() == before


SEMANTIC_FLOW = """---
name: sem
start: a
---

## a
-> b: the change is correct and complete
-> c: when visits > 3

## b
Done.

## c
Done.
"""


def test_unreadable_lock_is_reported_not_silently_treated_as_absent(tmp_path):
    flow_path = tmp_path / "sem.md"
    flow_path.write_text(SEMANTIC_FLOW)
    (tmp_path / "sem.lock").write_text("{ this is not json")
    tier = analysis.portability_tier(parse_file(str(flow_path)), str(flow_path))
    assert tier["tier"] == "P2"
    assert tier["lock"] is None                       # nothing usable was loaded, so the tier degrades
    assert tier["lock_error"] and "sem.lock" in tier["lock_error"]


def test_readable_lock_has_no_lock_error(tmp_path):
    import json
    flow_path = tmp_path / "sem.md"
    flow_path.write_text(SEMANTIC_FLOW)
    (tmp_path / "sem.lock").write_text(json.dumps({
        "version": 1, "flow": "sem", "flow_hash": "sha256:x",
        "embedder": {"name": "stub", "dim": 8, "probe": "p", "probe_vec": ""},
        "delta": 0.05,
        "conditions": {"the change is correct and complete": ""}}))
    tier = analysis.portability_tier(parse_file(str(flow_path)), str(flow_path))
    assert tier["tier"] == "P1" and tier["lock_error"] is None


def test_compile_report_size_is_the_decoded_byte_count():
    import base64
    from prismpath import cli
    for payload_length in range(1, 40):
        payload = bytes(range(payload_length))
        encoded = base64.b64encode(payload).decode()
        assert cli._b64_decoded_size(encoded) == payload_length
