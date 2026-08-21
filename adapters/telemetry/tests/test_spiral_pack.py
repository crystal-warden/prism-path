# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The baked materialization's referee: derived and baked must describe the identical layout,
the builder must be deterministic, and — per the profile's rule — a flow that fails the lint
or does not declare the profile must be REFUSED at bake time, not approximated."""
import os
import sys

import pytest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.dirname(HERE))

import spiral as sp                    # noqa: E402
import spiral_pack as spk              # noqa: E402
from prismpath.parser import parse     # noqa: E402

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
    g = parse(FLOW)
    assert spk.serialize_layouts(g) == spk.serialize_layouts(g)


def test_parse_round_trip_and_referee():
    g = parse(FLOW)
    blob = spk.serialize_layouts(g)
    got = spk.parse_sidecar(blob)
    assert "decide" in got["nodes"]
    assert spk.verify_derived_equals_baked(g, blob) == []


def test_referee_catches_a_flipped_band():
    g = parse(FLOW)
    blob = bytearray(spk.serialize_layouts(g))
    # corrupt one byte of the cell map (the tail of the blob)
    blob[-1] ^= 0x01
    errs = spk.verify_derived_equals_baked(g, bytes(blob))
    assert errs, "a corrupted sidecar must not verify as equal to the derived layout"


def test_bake_refuses_undeclared_flow():
    g = parse(FLOW.replace("packing: spiral\n", ""))
    with pytest.raises(ValueError, match="does not declare"):
        spk.serialize_layouts(g)


def test_bake_refuses_lint_errors():
    bad = FLOW.replace("-> ok: else\n", "").replace(
        "-> alarm: when range < 200 and level >= 300",
        "-> ok: else\n-> alarm: when range < 200 and level >= 300")
    g = parse(bad)
    with pytest.raises(ValueError, match="lint errors"):
        spk.serialize_layouts(g)


def test_bake_refuses_categorical_fields():
    g = parse("""---
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
        spk.serialize_layouts(g)


def test_band_tier_matches_derived_routing():
    """The decision-lossless tier: quantize a reading via the BAKED partitions, look up its band
    via the BAKED map, and the route must equal the derived layout's route for the same reading."""
    g = parse(FLOW)
    L = sp.SpiralLayout(g, "decide")
    blob = spk.serialize_layouts(g)
    rec = spk.parse_sidecar(blob)["nodes"]["decide"]
    radices = [f["n"] for f in rec["fields"]]
    for reading in ({"level": 0, "range": 500}, {"level": 300, "range": 100},
                    {"level": 299, "range": 199}, {"level": 1000, "range": 0}):
        cell = L.cell(reading)
        lin = 0
        for s, r in zip(cell, radices):
            lin = lin * r + s
        n = rec["cell_n"][lin]
        band = next(b for b in rec["bands"] if b["base"] <= n < b["base"] + b["width"])
        assert band["route"] == L.routes[L.band_id(reading)] if hasattr(L, "band_id") else True
        # authoritative cross-check: the derived layout's own route for this cell
        derived_route = L.routes[next(i for i, (bs, bw) in enumerate(zip(L.band_base, L.band_width))
                                      if bs <= L.n_of[cell] < bs + bw)]
        assert band["route"] == derived_route
