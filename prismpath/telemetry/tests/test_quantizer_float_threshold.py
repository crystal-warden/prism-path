# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Regression: a float comparison constant is refused, never silently truncated.

Found in the September 2026 readability review: `_classify_kind` fell through every branch on a float
constant and answered "boolean", so `x > 21.7` built a two cell boolean partition in which 5 and 30
quantized to the same symbol; and `_numeric_partition` truncated float cut points with `int()`. The codec
compares integers; a float threshold in a flow is the author's decision to make, so the quantizer refuses
it with the constant named, the way facet_init reports it as a float threshold.
"""
import pytest

from prismpath.kernel.parser import parse
from prismpath.telemetry import quantizer

FLOW = "---\nname: t\nstart: s\n---\n## s\n@emits(x)\n{edges}\n## a\nA\n## b\nB\n"


def _graph(edges):
    return parse(FLOW.format(edges=edges))


def test_float_ordering_constant_is_refused():
    with pytest.raises(ValueError, match="float"):
        quantizer.build_partitions(_graph("-> a: when x > 21.7\n-> b: else"))


def test_float_equality_constant_is_refused():
    with pytest.raises(ValueError, match="float"):
        quantizer.build_partitions(_graph("-> a: when x == 2.5\n-> b: else"))


def test_float_in_list_member_is_refused():
    with pytest.raises(ValueError, match="float"):
        quantizer.build_partitions(_graph("-> a: when x in (3, 5.5)\n-> b: else"))


def test_integer_thresholds_still_partition():
    parts = quantizer.build_partitions(_graph("-> a: when x > 21\n-> b: else"))
    assert "x" in parts and parts["x"].kind == "numeric"
