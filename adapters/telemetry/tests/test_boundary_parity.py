# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Boundary parity, frozen: the quantizer's symbol at every threshold edge (t-1, t, t+1 for cuts
from 10^2 to 10^12) and at the f64 integer exactness edge (2^53-1, 2^53, 2^53+2, 10^15) must match
the frozen corpus exactly. A drift on either side of any boundary is a decision change and goes red."""
import json
import sys
from pathlib import Path

_ADAPTER = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ADAPTER))
sys.path.insert(0, str(_ADAPTER.parent.parent))
import quantizer as q  # noqa: E402
from prismpath.parser import parse  # noqa: E402

_CORPUS = _ADAPTER / "conformance" / "boundary.json"


def test_boundary_symbols_match_frozen_corpus():
    corpus = json.loads(_CORPUS.read_text())
    parts = q.build_partitions(parse(corpus["flow"]))
    p = parts[corpus["field"]]
    assert p.n == corpus["cells"]
    for probe in corpus["probes"]:
        assert p.symbol(probe["value"]) == probe["symbol"], probe


def test_strict_inequality_normalizes_to_closed_integer_intervals():
    corpus = json.loads(_CORPUS.read_text())
    parts = q.build_partitions(parse(corpus["flow"]))
    p = parts[corpus["field"]]
    # every cut `mag < t` becomes the closed bound hi = t - 1: t-1 and t always land in
    # different cells, and no cell has an open interior edge
    for c in p.cells:
        if c["hi"] is not None:
            assert p.symbol(c["hi"]) != p.symbol(c["hi"] + 1)
