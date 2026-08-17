# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Decision-preserving quantizer — the contract, pinned:
  * the partition is the coarsest that keeps every atom truth-invariant per cell (minimum sufficient
    statistic for the decisions);
  * quantize -> reconstruct routes IDENTICALLY to the original reading, across numeric / boolean /
    categorical fields (the differentiated claim, in miniature — the frozen cross-flow proof is next);
  * symbols are small ints (Fibonacci-friendly).
"""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import quantizer as q  # noqa: E402

from prismpath import predicates  # noqa: E402
from prismpath.parser import parse, parse_file  # noqa: E402

_INCIDENT = os.path.join(os.path.dirname(__file__), "..", "..", "..",
                         "prismpath", "gallery", "incident_severity", "incident_severity.md")

CATEGORICAL = """---
name: cat
start: classify
---
## classify
-> urgent: when kind == 'urgent'
-> batch: when kind in ('nightly', 'weekly')
-> blocked: when status != 'ok'
-> normal: else
## urgent
## batch
## blocked
## normal
"""

NUMERIC_EQ = """---
name: numeq
start: classify
---
## classify
-> exact: when x == 5
-> high: when x >= 10
-> low: else
## exact
## high
## low
"""


def _route(graph, node, reading):
    """First-match deterministic routing from `node` over a reading (mirrors the engine's edge order)."""
    for target, cond in graph.nodes[node].edges:
        if predicates.is_deterministic(cond) and predicates.eval_condition(cond, reading):
            return target
    return None


def _assert_decisions_preserved(graph, node, readings):
    parts = q.build_partitions(graph)
    for r in readings:
        orig = _route(graph, node, r)
        recon = _route(graph, node, q.reconstruct(parts, q.quantize(parts, r)))
        assert orig == recon, f"decision changed for {r}: {orig} -> {recon}"


# ---------------------------------------------------------------- partition shape
def test_incident_partition_is_minimal():
    g = parse_file(_INCIDENT)
    parts = q.build_partitions(g)
    # error_rate thresholds >=1,>=5,>=25 -> exactly 4 decision cells
    assert parts["error_rate"].kind == "numeric"
    assert parts["error_rate"].n == 4
    # the two bare-field flags are boolean (2 cells each)
    assert parts["data_at_risk"].kind == "boolean" and parts["data_at_risk"].n == 2
    assert parts["user_facing"].kind == "boolean" and parts["user_facing"].n == 2


def test_categorical_partition_shape():
    g = parse(CATEGORICAL)
    parts = q.build_partitions(g)
    # kind: urgent/nightly/weekly + other = 4 ; status: ok + other = 2
    assert parts["kind"].kind == "categorical" and parts["kind"].n == 4
    assert parts["status"].kind == "categorical" and parts["status"].n == 2


def test_numeric_equality_keeps_the_point_cell():
    g = parse(NUMERIC_EQ)
    parts = q.build_partitions(g)
    # x: {<5}, {5}, {6..9}, {>=10} -> 4 cells (the == carves out the singleton {5})
    assert parts["x"].kind == "numeric" and parts["x"].n == 4
    assert parts["x"].symbol(5) != parts["x"].symbol(4)
    assert parts["x"].symbol(7) != parts["x"].symbol(5)


# ---------------------------------------------------------------- the focused decision-preserving proof
def test_incident_decisions_preserved():
    g = parse_file(_INCIDENT)
    readings = []
    for dar in (True, False):
        for uf in (True, False):
            for er in [-5, 0, 1, 2, 4, 5, 6, 24, 25, 26, 50, 100]:
                readings.append({"data_at_risk": dar, "user_facing": uf, "error_rate": er})
    _assert_decisions_preserved(g, "classify" if "classify" in g.nodes else "assess", readings)


def test_categorical_decisions_preserved():
    g = parse(CATEGORICAL)
    readings = [{"kind": k, "status": s}
                for k in ("urgent", "nightly", "weekly", "adhoc", "xyz")
                for s in ("ok", "bad", "degraded")]
    _assert_decisions_preserved(g, "classify", readings)


def test_numeric_equality_decisions_preserved():
    g = parse(NUMERIC_EQ)
    _assert_decisions_preserved(g, "classify", [{"x": v} for v in range(-3, 20)])


# ---------------------------------------------------------------- symbols stay small
def test_symbols_are_small():
    g = parse_file(_INCIDENT)
    parts = q.build_partitions(g)
    r = {"data_at_risk": True, "user_facing": False, "error_rate": 42}
    syms = q.quantize(parts, r)
    assert all(0 <= s < 8 for s in syms.values())   # tiny -> 1-2 Fibonacci bytes each
