# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Structural tests for the Area-5 comparison harness.

These do NOT hit the network or require langgraph/crewai — they assert the runner loads the labeled
suite correctly and the baselines construct + degrade gracefully when a framework is absent. The
measured numbers themselves come from `python -m prismpath.comparisons.run_comparison` against a live endpoint.
"""
import os

import pytest

from prismpath.comparisons.run_comparison import load_cases, markdown_table


def test_load_cases_matches_labeled_suite():
    cases = load_cases()
    assert len(cases) >= 17
    for c, instruction, outcome, edges in cases:
        assert outcome == c["outcome"]
        targets = [t for t, _ in edges]
        assert c["label"] in targets, f"label {c['label']!r} not an edge of node {c['node']!r}"
        assert isinstance(instruction, str)


def test_baselines_construct_and_gate_on_availability():
    # PrismPathBaseline builds a Gemma client (openai SDK), so this needs the `comparisons` extra —
    # skip on a light install where the head-to-head harness deps aren't present.
    pytest.importorskip("openai")
    from prismpath.comparisons.baselines import (CrewAIBaseline, LangGraphBaseline,
                                        LLMRouterBaseline, PrismPathBaseline)
    # prismpath + llm-router never touch a framework, so they're always available (no network yet:
    # constructing an EmbeddingRouter does not load the model).
    assert PrismPathBaseline().available is True
    assert LLMRouterBaseline().available is True
    # framework baselines expose .available as a bool and never raise on construction
    for cls in (LangGraphBaseline, CrewAIBaseline):
        bl = cls()
        assert isinstance(bl.available, bool)
        # a single-edge "decision" is answered without any model call, framework or not
        assert bl.decide("n", "o", [("only", "x")]) == ("only", 0, 0.0)


def test_markdown_table_orders_and_formats():
    rows = [
        {"name": "llm_router", "accuracy": 1.0, "llm_calls_per_1k": 1000,
         "latency_median_s": 0.33, "latency_p95_s": 0.34, "determinism": 1.0},
        {"name": "prismpath", "accuracy": 16 / 17, "llm_calls_per_1k": 188,
         "latency_median_s": 0.10, "latency_p95_s": 0.37, "determinism": 1.0},
    ]
    table = markdown_table(rows)
    # prismpath is ordered first regardless of input order, and percentages render
    assert table.index("prismpath") < table.index("llm_router")
    assert "94.1%" in table and "188" in table


def test_reproducer_artifacts_committed():
    """The recorded measured numbers travel with the repo so the README table is auditable."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for name in ("comparisons/results.json", "comparisons/results_table.md",
                 "comparisons/requirements.txt"):
        assert os.path.exists(os.path.join(here, name)), f"missing {name}"
