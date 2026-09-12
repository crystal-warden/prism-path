# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Tier 6 spiral packing: Gray-locality, contiguous decision-bands, route-by-integer-compare, the
decisions-preserved proof through the spiral map, and the frozen tessellation (a mapping bug -> RED)."""
import json
import sys
from pathlib import Path

import pytest

_ADAPTER = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ADAPTER))
sys.path.insert(0, str(_ADAPTER.parent.parent))            # repo root

from prismpath.telemetry import spiral   # noqa: E402
from prismpath.telemetry import wire      # noqa: E402
from prismpath.kernel.parser import parse            # noqa: E402

CORPUS = json.loads((_ADAPTER / "conformance" / "spiral.json").read_text())


def _layout():
    graph = parse(CORPUS["flow"])
    return graph, spiral.SpiralLayout(graph, CORPUS["node"])


# ---------------------------------------------------------------- Gray-code locality
@pytest.mark.parametrize("radices", [[2, 2], [3, 2], [3, 3, 3], [4, 2, 3]])
def test_gray_sequence_is_single_step_and_complete(radices):
    seq = list(spiral.mixed_radix_gray(radices))
    size = 1
    for radix in radices:
        size *= radix
    assert len(seq) == size and len(set(seq)) == size          # every cell exactly once
    for cell, next_cell in zip(seq, seq[1:]):
        diffs = [field_index for field_index in range(len(radices))
                 if cell[field_index] != next_cell[field_index]]
        assert len(diffs) == 1 and abs(cell[diffs[0]] - next_cell[diffs[0]]) == 1   # one field, +/-1


# ---------------------------------------------------------------- band structure
def test_bands_are_contiguous_and_partition_the_index():
    _, layout = _layout()
    bounds = layout.band_bounds()
    assert bounds[0][0] == 0
    for (lo, hi, _), (nlo, _, _) in zip(bounds, bounds[1:]):
        assert hi == nlo                                       # no gaps, no overlaps
    assert bounds[-1][1] == layout.size


def test_baseline_route_sits_at_the_center():
    _, layout = _layout()
    # the all-minimum cell (n=0) is the baseline; it is band 0 (the dense center)
    assert layout.route_of(0) == layout.routes[0]
    baseline_reading = {field: layout.parts[field].representative(0) for field in layout.fields}
    assert layout.band_id(baseline_reading) == 0


def test_route_of_is_an_integer_band_compare():
    _, layout = _layout()
    for spiral_index in range(layout.size):
        # explicit Level M atom: first band whose exclusive upper bound exceeds n
        expect = None
        for band in range(len(layout.routes)):
            if spiral_index < layout.band_base[band] + layout.band_width[band]:
                expect = layout.routes[band]
                break
        assert layout.route_of(spiral_index) == expect
        assert isinstance(spiral.radius2(spiral_index), int) \
            and isinstance(spiral.theta_u32(spiral_index), int)


# ---------------------------------------------------------------- the core proof
def test_decisions_preserved_through_the_spiral():
    graph, layout = _layout()
    for probe in CORPUS["probes"]:
        reading = probe["reading"]
        direct = wire.route_node(graph, CORPUS["node"], reading)            # the flow's own routing
        via_band = wire.route_node(graph, CORPUS["node"], layout.reconstruct_band(layout.band_id(reading)))
        via_index = layout.route_of(layout.index(reading))
        assert direct == probe["route"] == via_band == via_index


def test_progressive_round_trip_recovers_the_cell():
    graph, layout = _layout()
    for probe in CORPUS["probes"]:
        reading = probe["reading"]
        db, rb = layout.encode_progressive(reading)
        rec = layout.decode_progressive(db, rb)
        assert layout.cell(rec) == layout.cell(reading)                        # exact quantized cell
        assert wire.route_node(graph, CORPUS["node"], rec) == probe["route"]
        # the cheap stream alone still decodes to the right route
        assert layout.decode_decision(layout.encode_decision(reading)) == probe["route"]


# ---------------------------------------------------------------- frozen tessellation (regression guard)
def test_frozen_tessellation_matches():
    _, layout = _layout()
    assert layout.fields == CORPUS["fields"]
    assert layout.radices == CORPUS["radices"]
    assert layout.size == CORPUS["size"]
    got_bands = [{"route": route, "base": layout.band_base[band], "width": layout.band_width[band]}
                 for band, route in enumerate(layout.routes)]
    assert got_bands == CORPUS["bands"]
    got_cells = [{"cell": list(layout.cell_of[spiral_index]), "n": spiral_index,
                  "band": layout.band_index[layout.route_of(spiral_index)],
                  "route": layout.route_of(spiral_index)}
                 for spiral_index in range(layout.size)]
    assert got_cells == CORPUS["cells"]


# ---------------------------------------------------------------- the win exists (sanity, not the benchmark)
def test_decision_stream_cheaper_than_linear_for_multidim():
    import quantizer
    graph, layout = _layout()
    parts = quantizer.build_partitions(graph)
    readings = [{"pitch": pitch, "roll": roll, "vibration": vibration}
                for pitch in (0, 25, 50) for roll in (0, 25, 50) for vibration in (0, 50, 90)]
    lin = sum(len(wire.encode_reading(parts, rd)) for rd in readings)
    dec = sum(len(layout.encode_decision(rd)) for rd in readings)
    assert dec < lin                                           # one band ID beats three field symbols
