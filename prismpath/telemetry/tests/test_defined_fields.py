# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Facet over a flow that defines its fields (SPEC section 4.5): the engine's route survives the wire
for every canonical reading, absence has a cell of its own, and a value that is not canonical is
refused on every path, never converted.

The readings and routes come from the frozen field definition vectors, which record the engine's
route on each canonical reading. The Rust twin replays the same file.
"""
import json
from pathlib import Path

import pytest

from prismpath.kernel import engine
from prismpath.kernel.parser import parse
from prismpath.portable import gen_field_definitions
from prismpath.telemetry import quantizer, wire

CORPUS = json.loads((Path(gen_field_definitions.__file__).parent / "conformance" / "field_definitions.json")
                    .read_text())
ACCEPTED = [policy for policy in CORPUS["policies"] if policy["accepted"]]


def _route(graph, reading):
    return engine.first_deterministic(graph.nodes["s"].edges, reading)[0]


@pytest.mark.parametrize("policy", ACCEPTED, ids=lambda policy: policy["name"])
def test_every_canonical_reading_keeps_its_route_through_the_wire(policy):
    graph = parse(policy["flow"])
    parts = quantizer.build_partitions(graph)
    for probe in policy["probes"]:
        reading = probe["reading"]
        for encode in (wire.encode_reading, wire.encode_reading_checked):
            decoded = wire.decode_reading(parts, encode(parts, reading))
            assert _route(graph, decoded) == probe["route"], (reading, decoded)
            assert wire.encode_reading(parts, decoded) == encode(parts, reading)


@pytest.mark.parametrize("policy", ACCEPTED, ids=lambda policy: policy["name"])
def test_a_value_that_is_not_canonical_is_refused_on_every_path(policy):
    graph = parse(policy["flow"])
    parts = quantizer.build_partitions(graph)
    for refusal in policy["refused_readings"]:
        for encode in (wire.encode_reading, wire.encode_reading_checked):
            with pytest.raises(quantizer.InputRefused) as raised:
                encode(parts, refusal["reading"])
            assert (raised.value.field, raised.value.reason) == (refusal["field"], refusal["reason"])


def test_absence_is_its_own_cell_distinct_from_zero_false_and_every_string():
    graph = parse(next(policy for policy in ACCEPTED if policy["name"] == "int_and_bool_with_absent_count")["flow"])
    parts = quantizer.build_partitions(graph)
    count = parts["count"]
    absent = count.symbol(None)
    assert absent == count.absent_symbol == count.n - 1
    assert count.representative(absent) is None
    assert absent not in {count.symbol(value) for value in range(-5, 6)}
    assert quantizer.quantize(parts, {"armed": True})["count"] == absent       # missing is absent
    label_graph = parse(next(policy for policy in ACCEPTED if policy["name"] == "floor_ratio_with_absent_label")["flow"])
    label = quantizer.build_partitions(label_graph)["label"]
    assert label.symbol(None) not in {label.symbol(text) for text in ("", "a", "b", "anything")}


def test_a_field_refusing_absence_has_no_absent_cell():
    graph = parse(next(policy for policy in ACCEPTED if policy["name"] == "ceiling_seconds")["flow"])
    latency = quantizer.build_partitions(graph)["latency"]
    assert latency.absent_symbol is None
    with pytest.raises(quantizer.InputRefused, match="missing"):
        latency.symbol(None)


def test_the_frozen_streams_are_what_the_reference_produces():
    from prismpath.telemetry import gen_defined_wire_corpus
    committed = json.loads(gen_defined_wire_corpus.OUT.read_text())
    assert gen_defined_wire_corpus.build() == committed
