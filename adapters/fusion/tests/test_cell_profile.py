# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Rung-one referee: the predicate profile behind a symbol is faithful (its cell contains
exactly what the codebook says, its atom truths match the quantizer's own evaluator, and the
cell's representative routes back to the same symbol), refuses to invent cells, and its wire
cost is measured, not asserted from vibes."""
import sys
from pathlib import Path

import pytest

ADAPTER = Path(__file__).resolve().parent.parent
REPO = ADAPTER.parent.parent
from prismpath.telemetry import quantizer as q                       # noqa: E402
from prismpath.telemetry.predicate_profile import cell_profile, profile_wire_bytes  # noqa: E402
from prismpath.kernel.parser import parse          # noqa: E402

FLOW = """
## decide
Route a reading.
-> high: when level >= 1631
-> mid: when level >= 665
-> low: when level >= 0
-> reject: when kind == "bad"

## high
Terminal.
## mid
Terminal.
## low
Terminal.
## reject
Terminal.
"""

GRAPH = parse(FLOW)
PARTS = q.build_partitions(GRAPH)


def test_profile_is_faithful_for_every_cell():
    for field, p in PARTS.items():
        for sym in range(p.n):
            prof = cell_profile(GRAPH, PARTS, field, sym)
            assert prof["symbol"] == sym and prof["n_cells"] == p.n
            assert prof["cell"] == p.cells[sym]
            # the representative routes back to the same symbol (I1's shadow at rung one)
            assert p.symbol(prof["cell"]["rep"]) == sym
            # atom truths match the quantizer's own evaluator at the representative
            for a in prof["atoms"]:
                assert a["truth"] == q._atom_true(a["op"], a["const"], prof["cell"]["rep"])


def test_adjacent_cells_differ_in_truth_vector():
    """The partition is the COARSEST decision-preserving one, so neighboring numeric cells
    must disagree on at least one atom — the profile makes that visible."""
    p = PARTS["level"]
    vecs = []
    for sym in range(p.n):
        prof = cell_profile(GRAPH, PARTS, "level", sym)
        vecs.append(tuple(a["truth"] for a in prof["atoms"]))
    assert all(vecs[i] != vecs[i + 1] for i in range(len(vecs) - 1))


def test_profile_refuses_to_invent():
    with pytest.raises(KeyError):
        cell_profile(GRAPH, PARTS, "no_such_field", 0)
    with pytest.raises(IndexError):
        cell_profile(GRAPH, PARTS, "level", PARTS["level"].n)
    with pytest.raises(IndexError):
        cell_profile(GRAPH, PARTS, "level", -1)


def test_bytes_promoted_is_measured():
    """The price of rung one, measured: a symbol is a few bits on the wire; its profile is
    tens of bytes. Frozen loosely (a band, not an exact byte) so serialization tweaks do not
    thrash the test while the order of magnitude stays pinned."""
    prof = cell_profile(GRAPH, PARTS, "level", 0)
    cost = profile_wire_bytes(prof)
    assert 100 <= cost <= 600
    # and the symbol it expands stays a handful of bits under Zeckendorf on the wire
    assert PARTS["level"].n <= 12
