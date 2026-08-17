# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Mermaid-export tests (critic capability #4)."""
from prismpath import graph_export
from prismpath.parser import parse

FLOW = """---
name: bugfix
start: triage
---
## triage
-> implement: the bug is reproduced and the root cause is clear
-> review: when tests_pass
## implement
-> triage: a design decision is needed
## review
## done
Terminal.
"""


def test_mermaid_edges_by_tier():
    m = graph_export.to_mermaid(parse(FLOW))
    assert m.startswith("flowchart TD")
    assert "_start(( )) --> triage" in m
    assert 'triage -->|"when tests_pass"| review' in m          # deterministic -> solid
    assert 'triage -.->|"the bug is reproduced' in m            # semantic -> dashed
    assert 'review(["review"])' in m                            # terminal -> pill
    assert "class" in m and "terminal" in m


def test_direction_and_fence():
    assert graph_export.to_mermaid(parse(FLOW), "LR").startswith("flowchart LR")
    fenced = graph_export.to_mermaid_fenced(parse(FLOW))
    assert fenced.startswith("```mermaid\n") and fenced.rstrip().endswith("```")


def test_long_labels_truncated():
    long = "x " * 60
    g = parse(f"---\nstart: a\n---\n## a\n-> b: {long}\n## b\n")
    line = [l for l in graph_export.to_mermaid(g).splitlines() if "-.->|" in l][0]
    assert "…" in line
