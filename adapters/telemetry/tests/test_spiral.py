"""Tier 6 spiral packing: Gray-locality, contiguous decision-bands, route-by-integer-compare, the
decisions-preserved proof through the spiral map, and the frozen tessellation (a mapping bug -> RED)."""
import json
import sys
from pathlib import Path

import pytest

_ADAPTER = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ADAPTER))
sys.path.insert(0, str(_ADAPTER.parent.parent))            # repo root

import spiral as sp   # noqa: E402
import wire as w      # noqa: E402
from prismpath.parser import parse            # noqa: E402

CORPUS = json.loads((_ADAPTER / "conformance" / "spiral.json").read_text())


def _layout():
    g = parse(CORPUS["flow"])
    return g, sp.SpiralLayout(g, CORPUS["node"])


# ---------------------------------------------------------------- Gray-code locality
@pytest.mark.parametrize("radices", [[2, 2], [3, 2], [3, 3, 3], [4, 2, 3]])
def test_gray_sequence_is_single_step_and_complete(radices):
    seq = list(sp.mixed_radix_gray(radices))
    size = 1
    for r in radices:
        size *= r
    assert len(seq) == size and len(set(seq)) == size          # every cell exactly once
    for a, b in zip(seq, seq[1:]):
        diffs = [i for i in range(len(radices)) if a[i] != b[i]]
        assert len(diffs) == 1 and abs(a[diffs[0]] - b[diffs[0]]) == 1   # one field, +/-1


# ---------------------------------------------------------------- band structure
def test_bands_are_contiguous_and_partition_the_index():
    _, L = _layout()
    bounds = L.band_bounds()
    assert bounds[0][0] == 0
    for (lo, hi, _), (nlo, _, _) in zip(bounds, bounds[1:]):
        assert hi == nlo                                       # no gaps, no overlaps
    assert bounds[-1][1] == L.size


def test_baseline_route_sits_at_the_center():
    _, L = _layout()
    # the all-minimum cell (n=0) is the baseline; it is band 0 (the dense center)
    assert L.route_of(0) == L.routes[0]
    baseline_reading = {f: L.parts[f].representative(0) for f in L.fields}
    assert L.band_id(baseline_reading) == 0


def test_route_of_is_an_integer_band_compare():
    _, L = _layout()
    for n in range(L.size):
        # explicit Level M atom: first band whose exclusive upper bound exceeds n
        expect = None
        for b in range(len(L.routes)):
            if n < L.band_base[b] + L.band_width[b]:
                expect = L.routes[b]
                break
        assert L.route_of(n) == expect
        assert isinstance(sp.radius2(n), int) and isinstance(sp.theta_u32(n), int)


# ---------------------------------------------------------------- the core proof
def test_decisions_preserved_through_the_spiral():
    g, L = _layout()
    for probe in CORPUS["probes"]:
        r = probe["reading"]
        direct = w.route_node(g, CORPUS["node"], r)            # the flow's own routing
        via_band = w.route_node(g, CORPUS["node"], L.reconstruct_band(L.band_id(r)))
        via_index = L.route_of(L.index(r))
        assert direct == probe["route"] == via_band == via_index


def test_progressive_round_trip_recovers_the_cell():
    g, L = _layout()
    for probe in CORPUS["probes"]:
        r = probe["reading"]
        db, rb = L.encode_progressive(r)
        rec = L.decode_progressive(db, rb)
        assert L.cell(rec) == L.cell(r)                        # exact quantized cell
        assert w.route_node(g, CORPUS["node"], rec) == probe["route"]
        # the cheap stream alone still decodes to the right route
        assert L.decode_decision(L.encode_decision(r)) == probe["route"]


# ---------------------------------------------------------------- frozen tessellation (regression guard)
def test_frozen_tessellation_matches():
    _, L = _layout()
    assert L.fields == CORPUS["fields"]
    assert L.radices == CORPUS["radices"]
    assert L.size == CORPUS["size"]
    got_bands = [{"route": r, "base": L.band_base[i], "width": L.band_width[i]}
                 for i, r in enumerate(L.routes)]
    assert got_bands == CORPUS["bands"]
    got_cells = [{"cell": list(L.cell_of[n]), "n": n,
                  "band": L.band_index[L.route_of(n)], "route": L.route_of(n)}
                 for n in range(L.size)]
    assert got_cells == CORPUS["cells"]


# ---------------------------------------------------------------- the win exists (sanity, not the benchmark)
def test_decision_stream_cheaper_than_linear_for_multidim():
    import quantizer as q
    g, L = _layout()
    parts = q.build_partitions(g)
    readings = [{"pitch": p, "roll": r, "vibration": v}
                for p in (0, 25, 50) for r in (0, 25, 50) for v in (0, 50, 90)]
    lin = sum(len(w.encode_reading(parts, rd)) for rd in readings)
    dec = sum(len(L.encode_decision(rd)) for rd in readings)
    assert dec < lin                                           # one band ID beats three field symbols
