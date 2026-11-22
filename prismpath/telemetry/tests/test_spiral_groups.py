# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The spiral profile for policies whose joint grid is too large to list (PROTOCOL.md 2.6.1): the band and
signature tiers round trip on the seven large policies, every reading of a seeded sample keeps its decision
through each tier, the full 64,484 reading populations are a checkpoint, and a decoder refuses a stream that
is not its policy's or its layout's."""
import json
import zlib
from pathlib import Path

import pytest

from prismpath.kernel import core_render
from prismpath.kernel.parser import parse
from prismpath.telemetry import quantizer, spiral, spiral_groups as sg, wire
from prismpath.telemetry import zeckendorf as zeck

ROOT = Path(__file__).resolve().parents[3]
LARGE = ["integrations/governed_intent/policy/intent_calls.core.json",
         "integrations/governed_population/policy/admission.core.json",
         "prismpath-hw/esp-vision-node/flows/occupancy_6x8.md",
         "prismpath-hw/esp-vision-node/flows/occupancy_6x8_v2.md",
         "prismpath/agent/policy/agent_default.core.json",
         "prismpath/agent/policy/agent_review.core.json",
         "prismpath/agent/policy/agent_rules.core.json"]
FULL = 64_484        # the population size of the Facet bandwidth measurement
SAMPLE = 400         # readings per population on every push


def load(path):
    raw = (ROOT / path).read_text(encoding="utf-8")
    return core_render.render(json.loads(raw)) if path.endswith(".core.json") else raw


_FACETS = {}


def facet(path):
    if path not in _FACETS:
        text = load(path)
        _FACETS[path] = (sg.GroupedFacet(parse(text), text), text)
    return _FACETS[path]


def seed_of(path):
    return zlib.crc32(path.encode())


def check_reading(fct, reading):
    """The reading keeps every node's decision through the band, the signature and the refined cell."""
    graph = fct.graph
    symbols = quantizer.checked_quantize(fct.parts, reading)
    for name in fct.nodes:
        layout = fct.layouts[name]
        want = wire.route_node(graph, name, reading)
        assert layout.routes[layout.band_id(reading)] == want
        if isinstance(layout, sg.GroupedLayout):
            located = layout.locate(symbols)
            assert layout.route_of_signature([rank for rank, _l in located]) == want
            rebuilt = layout.rebuild([rank for rank, _l in located], [local for _r, local in located])
            assert wire.route_node(graph, name, rebuilt) == want
            for group in layout.groups:      # the refined cell is the reading's own cell
                assert [group.parts[f].symbol(rebuilt[f]) for f in group.fields] == [symbols[f] for f in group.fields]


# ------------------------------------------------------------------ layout shape
@pytest.mark.parametrize("path", LARGE)
def test_large_policies_get_grouped_layouts(path):
    fct, _text = facet(path)
    assert fct.nodes
    for name in fct.nodes:
        layout = fct.layouts[name]
        assert isinstance(layout, sg.GroupedLayout)
        assert sg.joint_cells(fct.graph, name, fct.parts) > sg.ENUMERATION_LIMIT
        assert sorted(f for group in layout.groups for f in group.fields) == layout.fields
        for group in layout.groups:
            assert sum(group.class_width) == group.size <= sg.GROUP_LIMIT
            assert group.class_width == sorted(group.class_width, reverse=True)
            assert [len(cells) for cells in group.cell_of] == group.class_width


# ------------------------------------------------------------------ round trip
@pytest.mark.parametrize("path", LARGE)
@pytest.mark.parametrize("tier", [sg.TIER_BAND, sg.TIER_SIGNATURE, sg.TIER_REFINED])
def test_round_trip(path, tier):
    fct, _text = facet(path)
    readings = sg.populations(fct.parts, seed_of(path), 60)["uniform"][:40]
    data = fct.encode(readings, tier)
    got = fct.decode(data)
    assert len(got) == len(readings)
    for reading, routes in zip(readings, got):
        for name in fct.nodes:
            assert routes[name] == wire.route_node(fct.graph, name, reading)
    for reading in readings[:8]:       # one decision's bits decode alone
        bits = fct.encode_reading(reading, tier)
        assert fct.decode_reading(bits, tier) == {n: wire.route_node(fct.graph, n, reading) for n in fct.nodes}


# ------------------------------------------------------------------ decision preservation
@pytest.mark.parametrize("path", LARGE)
def test_decision_preserved_sample(path):
    fct, _text = facet(path)
    for pop in sg.populations(fct.parts, seed_of(path), SAMPLE).values():
        for reading in pop:
            check_reading(fct, reading)


@pytest.mark.checkpoint
@pytest.mark.parametrize("path", LARGE)
def test_decision_preserved_full_population(path):
    fct, _text = facet(path)
    for pop in sg.populations(fct.parts, seed_of(path), FULL).values():
        for reading in pop:
            check_reading(fct, reading)


# ------------------------------------------------------------------ refusals
def test_decoder_refuses_another_policys_stream():
    path = LARGE[4]
    fct, text = facet(path)
    reading = sg.populations(fct.parts, 1, 5)["uniform"][0]
    data = fct.encode([reading], sg.TIER_SIGNATURE)
    other = sg.GroupedFacet(parse(text), text + "\n")      # the same graph under another document text
    with pytest.raises(sg.StreamMismatch, match="policy hash"):
        other.decode(data)
    sibling, sibling_text = facet(LARGE[5])
    with pytest.raises(sg.StreamMismatch):
        sibling.decode(data)


def test_decoder_refuses_another_layout():
    path = LARGE[4]
    fct, text = facet(path)
    reading = sg.populations(fct.parts, 1, 5)["uniform"][0]
    data = fct.encode([reading], sg.TIER_SIGNATURE)
    coarser = sg.GroupedFacet(parse(text), text, group_limit=2_000)
    assert coarser.policy_hash == fct.policy_hash and coarser.layout_hash != fct.layout_hash
    with pytest.raises(sg.StreamMismatch, match="layout hash"):
        coarser.decode(data)


def test_decoder_refuses_a_damaged_stream():
    path = LARGE[4]
    fct, _text = facet(path)
    readings = sg.populations(fct.parts, 1, 20)["uniform"][:10]
    data = fct.encode(readings, sg.TIER_REFINED)
    with pytest.raises(sg.StreamMismatch):
        fct.decode(b"XXXX" + data[4:])
    with pytest.raises(sg.StreamMismatch):
        fct.decode(data[:41])
    with pytest.raises(sg.StreamMismatch):
        fct.decode(data[:-3])                       # cut inside the body
    bad_tier = bytearray(data)
    bad_tier[5] = 9
    with pytest.raises(sg.StreamMismatch):
        fct.decode(bytes(bad_tier))
    bad_count = bytearray(data)
    bad_count[38] = 200                              # more decisions than the body holds
    with pytest.raises(sg.StreamMismatch):
        fct.decode(bytes(bad_count))


# ------------------------------------------------------------------ small policies are untouched
FLOW = """---
name: attitude
start: watch
---
## watch
-> critical: when vibration >= 80
-> alarm: when pitch >= 45 or roll >= 45
-> caution: when pitch >= 20 or roll >= 20 or vibration >= 40
-> nominal: else
## critical
## alarm
## caution
## nominal
"""


def test_a_policy_that_fits_keeps_the_spiral_layout():
    graph = parse(FLOW)
    layout = sg.layout_for(graph, "watch")
    assert type(layout) is spiral.SpiralLayout
    fct = sg.GroupedFacet(graph, FLOW)
    reading = {"pitch": 50, "roll": 0, "vibration": 10}
    assert fct.encode_reading(reading, sg.TIER_BAND) == layout.encode_decision(reading)
    with pytest.raises(ValueError):
        fct.encode([reading], sg.TIER_SIGNATURE)
    routes = fct.decode(fct.encode([reading], sg.TIER_BAND))
    assert routes == [{"watch": "alarm"}]


def test_grouping_a_small_policy_preserves_every_cell():
    """Forcing the grouped layout on a policy that fits, every cell of its joint grid keeps its route
    through the signature and through the signature plus refinement."""
    graph = parse(FLOW)
    small = spiral.SpiralLayout(graph, "watch")
    fct = sg.GroupedFacet(graph, FLOW, limit=1, group_limit=1)
    layout = fct.layouts["watch"]
    assert isinstance(layout, sg.GroupedLayout) and len(layout.groups) > 1
    for cell in small.cell_of:
        reading = small.reconstruct(small.n_of[cell])
        check_reading(fct, reading)
        data = fct.encode([reading], sg.TIER_REFINED)
        assert fct.decode(data) == [{"watch": wire.route_node(graph, "watch", reading)}]


# ------------------------------------------------------------------ the frozen band vectors
def test_band_vectors_are_the_live_reference_and_rust_has_the_same_file(tmp_path):
    """Regenerating `grouped_band.json` reproduces the committed file and the Rust crate's copy, which the
    crate's test_conformance_grouped_band.rs replays by evaluating the policy. An intended change to the
    profile shows up as a diff of this file."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("gen_grouped_corpus",
                                                  ROOT / "prismpath/telemetry/gen_grouped_corpus.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    committed = ROOT / "prismpath/telemetry/conformance/grouped_band.json"
    rust = ROOT / "prismpath-telemetry-rs/tests/fixtures/grouped_band.json"
    assert rust.read_bytes() == committed.read_bytes()
    cases = []
    for number, path in enumerate(gen.POLICIES):
        cases.append(gen._case(path.rsplit("/", 1)[1], load(path), 20261121 + number))
    cases.append(gen._case("attitude", gen.SMALL, 20261121 + len(gen.POLICIES)))
    assert json.loads(committed.read_text()) == json.loads(json.dumps({"version": 1, "cases": cases}))
