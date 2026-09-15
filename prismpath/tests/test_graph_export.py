# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Mermaid-export tests (critic capability #4)."""
from prismpath.kernel import graph_export
from prismpath.kernel.parser import parse

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
    mermaid = graph_export.to_mermaid(parse(FLOW))
    assert mermaid.startswith("flowchart TD")
    assert "_start(( )) --> triage" in mermaid
    assert 'triage -->|"when tests_pass"| review' in mermaid          # deterministic -> solid
    assert 'triage -.->|"the bug is reproduced' in mermaid            # semantic -> dashed
    assert 'review(["review"])' in mermaid                            # terminal -> pill
    assert "class" in mermaid and "terminal" in mermaid


def test_direction_and_fence():
    assert graph_export.to_mermaid(parse(FLOW), "LR").startswith("flowchart LR")
    fenced = graph_export.to_mermaid_fenced(parse(FLOW))
    assert fenced.startswith("```mermaid\n") and fenced.rstrip().endswith("```")


def test_long_labels_truncated():
    long = "x " * 60
    graph = parse(f"---\nstart: a\n---\n## a\n-> b: {long}\n## b\n")
    line = [line for line in graph_export.to_mermaid(graph).splitlines() if "-.->|" in line][0]
    assert "…" in line
