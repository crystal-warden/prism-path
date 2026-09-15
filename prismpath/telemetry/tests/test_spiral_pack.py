# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The baked materialization's referee: derived and baked must describe the identical layout,
the builder must be deterministic, and  -  per the profile's rule  -  a flow that fails the lint
or does not declare the profile must be REFUSED at bake time, not approximated."""
import os
import sys

import pytest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.dirname(HERE))

from prismpath.telemetry import spiral                    # noqa: E402
from prismpath.telemetry import spiral_pack as spk              # noqa: E402
from prismpath.kernel.parser import parse     # noqa: E402

FLOW = """---
name: fusion
start: decide
packing: spiral
---
## decide
-> alarm: when range < 200 and level >= 300
-> warn: when level >= 300
-> notice: when range < 200
-> ok: else
## alarm
## warn
## notice
## ok
"""


def test_bake_is_deterministic():
    graph = parse(FLOW)
    assert spk.serialize_layouts(graph) == spk.serialize_layouts(graph)


def test_parse_round_trip_and_referee():
    graph = parse(FLOW)
    blob = spk.serialize_layouts(graph)
    got = spk.parse_sidecar(blob)
    assert "decide" in got["nodes"]
    assert spk.verify_derived_equals_baked(graph, blob) == []


def test_referee_catches_a_flipped_band():
    graph = parse(FLOW)
    blob = bytearray(spk.serialize_layouts(graph))
    # corrupt one byte of the cell map (the tail of the blob)
    blob[-1] ^= 0x01
    errs = spk.verify_derived_equals_baked(graph, bytes(blob))
    assert errs, "a corrupted sidecar must not verify as equal to the derived layout"


def test_bake_refuses_undeclared_flow():
    graph = parse(FLOW.replace("packing: spiral\n", ""))
    with pytest.raises(ValueError, match="does not declare"):
        spk.serialize_layouts(graph)


def test_bake_refuses_lint_errors():
    bad = FLOW.replace("-> ok: else\n", "").replace(
        "-> alarm: when range < 200 and level >= 300",
        "-> ok: else\n-> alarm: when range < 200 and level >= 300")
    graph = parse(bad)
    with pytest.raises(ValueError, match="lint errors"):
        spk.serialize_layouts(graph)


def test_bake_refuses_categorical_fields():
    graph = parse("""---
start: decide
packing: spiral
---
## decide
-> page: when kind == 'burst'
-> ok: else
## page
## ok
""")
    with pytest.raises(ValueError, match="numeric/boolean"):
        spk.serialize_layouts(graph)


def test_band_tier_matches_derived_routing():
    """The decision-lossless tier: quantize a reading via the BAKED partitions, look up its band
    via the BAKED map, and the route must equal the derived layout's route for the same reading."""
    graph = parse(FLOW)
    layout = spiral.SpiralLayout(graph, "decide")
    blob = spk.serialize_layouts(graph)
    rec = spk.parse_sidecar(blob)["nodes"]["decide"]
    radices = [field["n"] for field in rec["fields"]]
    for reading in ({"level": 0, "range": 500}, {"level": 300, "range": 100},
                    {"level": 299, "range": 199}, {"level": 1000, "range": 0}):
        cell = layout.cell(reading)
        lin = 0
        for symbol, radix in zip(cell, radices):
            lin = lin * radix + symbol
        spiral_index = rec["cell_n"][lin]
        band = next(band_record for band_record in rec["bands"]
                    if band_record["base"] <= spiral_index
                    < band_record["base"] + band_record["width"])
        assert band["route"] == layout.routes[layout.band_id(reading)] if hasattr(layout, "band_id") else True
        # authoritative cross-check: the derived layout's own route for this cell
        derived_route = layout.routes[
            next(band_index for band_index, (bs, bw)
                 in enumerate(zip(layout.band_base, layout.band_width))
                 if bs <= layout.n_of[cell] < bs + bw)]
        assert band["route"] == derived_route
