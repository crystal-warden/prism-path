# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""profile.py — the predicate profile behind a Facet symbol (escalation rung one).

A symbol on the wire is a cell index: the minimum sufficient statistic for the policy's
decisions. When a consumer needs to look closer, the first rung of escalation is not raw data,
it is THIS: the cell's full membership (the interval or category the value fell in), the policy
atoms that cut that field's domain, and each atom's truth over the cell — everything the
decision layer knew, still derived entirely from the signed policy, still zero raw readings.

This module is pure introspection over the codebook (`build_partitions`): nothing is
transmitted, retained, or invented. The wire cost accounting (`profile_wire_bytes`) exists so
that "bytes promoted" is a measured quantity from day one: a symbol costs a few bits, its
profile costs tens of bytes, and that ratio is the price of rung one.
"""
from __future__ import annotations

import json
from typing import Any, Dict

import quantizer as q


def cell_profile(graph, parts: Dict[str, "q.FieldPartition"], field: str, symbol: int) -> dict:
    """The fuller predicate profile behind (field, symbol), derived from the signed policy.

    Raises KeyError for a field the policy never routes on, IndexError for a symbol outside
    the field's partition — a profile request must never invent a cell."""
    p = parts[field]
    if not (0 <= symbol < p.n):
        raise IndexError(f"{field}: symbol {symbol} outside partition (n={p.n})")
    cell = dict(p.cells[symbol])
    rep = cell["rep"]
    atoms = q._flow_atoms(graph).get(field, [])
    return {
        "field": field,
        "kind": p.kind,
        "symbol": symbol,
        "n_cells": p.n,
        "cell": cell,
        "atoms": [{"op": op, "const": const, "truth": q._atom_true(op, const, rep)}
                  for op, const in atoms],
    }


def profile_wire_bytes(profile: dict) -> int:
    """Canonical serialized size — the measured cost of promoting one symbol to its profile."""
    return len(json.dumps(profile, sort_keys=True, separators=(",", ":")).encode())
