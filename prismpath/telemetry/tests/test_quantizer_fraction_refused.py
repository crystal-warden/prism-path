# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Regression: a fractional reading is refused on the permissive path too, never truncated.

Found in October 2026 by the Lean formalization's float check. The checked path already refused a fraction,
but the permissive `symbol`, used by the spiral packer, one wire encoder, the CLI and preflight, truncated it
with `int()`, toward zero. Truncation moves a reading across a cut, so the decision the codec carried was not
the decision the engine makes on the reading itself: -0.5 truncated to 0 against `x < 0`, and 3.5 to 3 against
`x == 3`, `x <= 3` and `x in [3, 7]`. Every case below changed its decision before the fix.
"""
import pytest

from prismpath.kernel import engine
from prismpath.kernel.parser import parse
from prismpath.telemetry import quantizer

FLOW = "---\nname: t\nstart: s\n---\n## s\n@emits(x)\n-> hit: when {condition}\n-> miss: else\n## hit\nH\n## miss\nM\n"

CASES = [("x < 0", -0.5), ("x < 0", -0.9), ("x == 3", 3.5), ("x <= 3", 3.5),
         ("x in [3, 7]", 3.5), ("x in [3, 7]", 7.5)]


def _route(graph, reading):
    return engine.first_deterministic(graph.nodes["s"].edges, reading)[0]


@pytest.mark.parametrize("condition,value", CASES)
def test_a_fraction_is_refused_on_both_paths(condition, value):
    graph = parse(FLOW.format(condition=condition))
    parts = quantizer.build_partitions(graph)
    with pytest.raises(ValueError, match="fractional"):
        quantizer.quantize(parts, {"x": value})
    with pytest.raises(quantizer.InputRefused):
        quantizer.checked_quantize(parts, {"x": value})


@pytest.mark.parametrize("condition", sorted({condition for condition, _value in CASES}))
def test_every_value_the_permissive_path_accepts_routes_as_the_engine_does(condition):
    graph = parse(FLOW.format(condition=condition))
    parts = quantizer.build_partitions(graph)
    for value in (-2, -1, 0, 1, 2, 3, 4, 7, 8, -1.0, 0.0, 3.0, 7.0, True, False, "3", "-1"):
        converted = {"x": quantizer.numeric_view(value)}
        representative = quantizer.reconstruct(parts, quantizer.quantize(parts, {"x": value}))
        assert _route(graph, converted) == _route(graph, representative), (condition, value)


def test_non_finite_floats_are_refused():
    for value in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValueError, match="fractional or not finite"):
            quantizer.numeric_view(value)
