# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Regression: every value at which an atom can change truth is a cut point (PROTOCOL.md I1).

Found in September 2026 while stating I1 in Lean (formal/FQ): the first `_numeric_partition`
collected only the ordering and equality constants, so `in` / `not in` list members and the
truthiness cut at zero were not boundaries, and `_categorical_partition` had no `""` constant for
string truthiness. Each case below routed two values differently while quantizing them to one
symbol. The frozen corpus (`conformance/decisions.json` v2) carries the same three flows so the
Rust mirror is held to the same rule.
"""
import pytest

from prismpath import engine
from prismpath.parser import parse

from adapters.telemetry import quantizer as q

FLOW = "---\nname: t\nstart: s\n---\n## s\n@emits(x, name)\n{edges}\n## a\nA\n## b\nB\n## c\nC\n"


class _NoRouter:
    def route(self, *a, **k):
        raise AssertionError("semantic routing in a deterministic fixture")


def _route(graph, reading):
    return engine.run(graph, lambda n, i, ctx: dict(reading), router=_NoRouter(), max_steps=5).path[-1]


def _preserved(edges, readings):
    graph = parse(FLOW.format(edges=edges))
    parts = q.build_partitions(graph)
    for r in readings:
        rep = q.reconstruct(parts, q.quantize(parts, r))
        assert _route(graph, r) == _route(graph, rep), (r, rep)
    return parts


def test_numeric_in_list_members_are_cut_points():
    parts = _preserved("-> a: when x in (3, 5)\n-> b: else", [{"x": v} for v in range(-2, 9)])
    assert parts["x"].n == 5          # (..2] [3] [4] [5] [6..)


def test_numeric_not_in_list_members_are_cut_points():
    parts = _preserved("-> a: when x not in (7,)\n-> b: else", [{"x": v} for v in range(4, 10)])
    assert parts["x"].n == 3


def test_truthiness_cut_at_zero_survives_other_constants():
    parts = _preserved("-> a: when x >= 5\n-> b: when x\n-> c: else", [{"x": v} for v in range(-3, 8)])
    assert parts["x"].n == 4          # (..-1] [0] [1..4] [5..)


def test_string_truthiness_names_the_empty_string():
    parts = _preserved("-> a: when name == 'root'\n-> b: when name\n-> c: else",
                       [{"name": s} for s in ["root", "", "zzz", "admin"]])
    assert parts["name"].n == 3       # root, "", other


@pytest.mark.parametrize("edges,n", [
    ("-> a: when x >= 25\n-> b: when x >= 5\n-> c: else", 3),
    ("-> a: when x == 5\n-> b: when x >= 10\n-> c: else", 4),
])
def test_existing_shapes_unchanged(edges, n):
    parts = _preserved(edges, [{"x": v} for v in range(-1, 30)])
    assert parts["x"].n == n
