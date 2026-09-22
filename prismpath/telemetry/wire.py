# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The Facet wire (Facet/1, PROTOCOL.md §2): a reading <-> a self framing Fibonacci bitstream, through Figueroa quantization.

Field order is canonical (sorted field names), so encode and decode agree with **zero header**. Symbols
are 0-based cell indices; the Fibonacci codec is defined for positive integers, so each is sent as
``symbol + 1``. The composition is the whole point: quantize (decision-preserving) -> Fibonacci-code
(self-framing) -> decode -> reconstruct routes identically to the original reading.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from prismpath.kernel import predicates
from prismpath.telemetry import quantizer
from prismpath.telemetry import zeckendorf as zeck


def _order(parts: Dict[str, "q.FieldPartition"]) -> List[str]:
    return sorted(parts.keys())


def encode_reading(parts: Dict[str, "q.FieldPartition"], reading: Dict[str, Any]) -> str:
    """Reading -> bitstream. Requires every decision-relevant field present (missing-field handling is a
    later refinement)."""
    order = _order(parts)
    missing = [field for field in order if field not in reading]
    if missing:
        raise KeyError(f"reading missing decision fields: {missing}")
    syms = quantizer.quantize(parts, reading)
    return zeck.encode_stream([syms[field] + 1 for field in order])


def encode_reading_checked(parts: Dict[str, "q.FieldPartition"], reading: Dict[str, Any]) -> str:
    """`encode_reading` behind the input contract (`quantizer.accept_value`): a value the contract
    refuses raises `quantizer.InputRejected` with the field and the reason instead of being
    truncated, coerced or read as zero. Encode through this at a runtime boundary; a preflight
    run over the same sample reports exactly the rejections this will raise."""
    order = _order(parts)
    syms = quantizer.checked_quantize(parts, reading)
    return zeck.encode_stream([syms[field] + 1 for field in order])


def decode_reading(parts: Dict[str, "q.FieldPartition"], bits: str) -> Dict[str, Any]:
    """Bitstream -> a representative reading that routes identically to the original."""
    order = _order(parts)
    wire = zeck.decode_stream(bits)
    if len(wire) != len(order):
        raise ValueError(f"symbol count {len(wire)} != decision fields {len(order)}")
    syms = {field: wire[field_index] - 1 for field_index, field in enumerate(order)}
    return quantizer.reconstruct(parts, syms)


# --------------------------------------------------------- reference routing (the deterministic tier)
def route_node(graph, node: str, reading: Dict[str, Any]) -> Optional[str]:
    """First-match deterministic routing from `node` over a reading  -  the engine's field-routing tier."""
    for target, cond in graph.nodes[node].edges:
        if predicates.is_deterministic(cond) and predicates.eval_condition(cond, reading):
            return target
    return None


def decision_nodes(graph) -> List[str]:
    """Nodes with at least one deterministic (field-routing) edge."""
    return [name for name, node in graph.nodes.items()
            if any(predicates.is_deterministic(cond) for _t, cond in node.edges)]
