# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Wire glue — a reading <-> a self-framing Fibonacci bitstream, through the decision-preserving quantizer.

Field order is canonical (sorted field names), so encode and decode agree with **zero header**. Symbols
are 0-based cell indices; the Fibonacci codec is defined for positive integers, so each is sent as
``symbol + 1``. The composition is the whole point: quantize (decision-preserving) -> Fibonacci-code
(self-framing) -> decode -> reconstruct routes identically to the original reading.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from prismpath import predicates

import quantizer as q
import zeckendorf as z


def _order(parts: Dict[str, "q.FieldPartition"]) -> List[str]:
    return sorted(parts.keys())


def encode_reading(parts: Dict[str, "q.FieldPartition"], reading: Dict[str, Any]) -> str:
    """Reading -> bitstream. Requires every decision-relevant field present (missing-field handling is a
    later refinement)."""
    order = _order(parts)
    missing = [f for f in order if f not in reading]
    if missing:
        raise KeyError(f"reading missing decision fields: {missing}")
    syms = q.quantize(parts, reading)
    return z.encode_stream([syms[f] + 1 for f in order])


def decode_reading(parts: Dict[str, "q.FieldPartition"], bits: str) -> Dict[str, Any]:
    """Bitstream -> a representative reading that routes identically to the original."""
    order = _order(parts)
    wire = z.decode_stream(bits)
    if len(wire) != len(order):
        raise ValueError(f"symbol count {len(wire)} != decision fields {len(order)}")
    syms = {f: wire[i] - 1 for i, f in enumerate(order)}
    return q.reconstruct(parts, syms)


# --------------------------------------------------------- reference routing (the deterministic tier)
def route_node(graph, node: str, reading: Dict[str, Any]) -> Optional[str]:
    """First-match deterministic routing from `node` over a reading — the engine's field-routing tier."""
    for target, cond in graph.nodes[node].edges:
        if predicates.is_deterministic(cond) and predicates.eval_condition(cond, reading):
            return target
    return None


def decision_nodes(graph) -> List[str]:
    """Nodes with at least one deterministic (field-routing) edge."""
    return [name for name, node in graph.nodes.items()
            if any(predicates.is_deterministic(c) for _t, c in node.edges)]
