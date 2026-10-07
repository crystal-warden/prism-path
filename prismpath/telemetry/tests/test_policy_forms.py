# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Regression: the codec carries every Level M form with the engine's route, and refuses the rest.

Found in October 2026 by the reading boundary audit. The partition builder walked a plain `ast.parse`
and skipped anything it did not recognize, so a negative threshold (`x < -3`, a unary minus) and a
chained range (`0 < x < 5`) left the field out of the partition, and every reading decoded to the same
cell. A field compared with another field, or a string ordered against a constant, was skipped the same
way, so the decoded reading could take an edge the raw reading did not. The frozen corpus pins the
engine's route for every carried probe and the refusal of every other form. The Rust twin replays the
same file.
"""
import json
from pathlib import Path

import pytest

from prismpath.kernel import engine
from prismpath.kernel.parser import parse
from prismpath.telemetry import quantizer, spiral

CORPUS = json.loads((Path(__file__).resolve().parents[1] / "conformance" / "policy_forms.json").read_text())


def _route(graph, reading):
    return engine.first_deterministic(graph.nodes[CORPUS["node"]].edges, reading)[0]


def test_corpus_pinned():
    assert len(CORPUS["carried"]) == 12
    assert len(CORPUS["refused"]) == 11


@pytest.mark.parametrize("case", CORPUS["carried"], ids=lambda case: case["condition"])
def test_a_carried_form_routes_as_the_engine_does_on_both_paths(case):
    graph = parse(CORPUS["flow_template"].format(condition=case["condition"]))
    parts = quantizer.build_partitions(graph)
    assert case["field"] in parts, "the field the condition routes on is missing from the partition"
    for probe in case["readings"]:
        raw = {case["field"]: probe["value"]}
        assert _route(graph, raw) == probe["route"]
        permissive = quantizer.reconstruct(parts, quantizer.quantize(parts, raw))
        checked = quantizer.reconstruct(parts, quantizer.checked_quantize(parts, raw))
        assert _route(graph, permissive) == probe["route"], (probe, permissive)
        assert _route(graph, checked) == probe["route"], (probe, checked)


@pytest.mark.parametrize("case", CORPUS["carried"], ids=lambda case: case["condition"])
def test_the_spiral_packer_sees_the_field(case):
    graph = parse(CORPUS["flow_template"].format(condition=case["condition"]))
    layout = spiral.SpiralLayout(graph, CORPUS["node"])
    assert layout.fields == [case["field"]]


@pytest.mark.parametrize("case", CORPUS["refused"], ids=lambda case: case["condition"])
def test_a_form_the_codec_cannot_carry_refuses_the_whole_flow(case):
    graph = parse(CORPUS["flow_template"].format(condition=case["condition"]))
    with pytest.raises(ValueError):
        quantizer.build_partitions(graph)


def test_the_refusal_names_the_condition_and_its_reason():
    graph = parse(CORPUS["flow_template"].format(condition="x == y"))
    with pytest.raises(ValueError, match=r"'when x == y' \(field-vs-field\)"):
        quantizer.build_partitions(graph)


def test_a_none_comparison_is_refused_as_absence():
    graph = parse(CORPUS["flow_template"].format(condition="x == None"))
    with pytest.raises(ValueError, match="absent field"):
        quantizer.build_partitions(graph)
