"""Tier 6 — decision-first Fermat-spiral spatial packing (progressive, integer-only).

Packs a multi-variable reading into a **single ordered index** ``n`` whose contiguous ranges *are* the
routes, so the cheap wire quantity is a band ID ("transmit the decision, not the magnitude"), with a
within-band refinement recovered on demand. Two properties the plain per-field wire lacks:

  * **Decision-first layout.** The bands are the flow's own routes, laid out center-outward with the
    fallthrough/baseline (matched last in a first-match flow) at the dense center and the most-specific /
    severe branches (declared first) outward — the doc's "center = baseline, outward = deviation". Band
    membership is
    ``band_base[b] <= n < band_base[b] + width[b]`` — two integer compares, a Level M atom — because a
    Fermat/Vogel spiral has ``r^2 = c^2 * n``, so a radial ring ``r < R`` *is* ``n < K``. The golden angle
    ``theta = n * 137.5deg`` is a deterministic function of ``n`` (a ``u32`` add, ``0x9E3779B9``, no trig),
    so the wire quantity stays a single integer: a 1-D ordered index with uniform 2-D coverage, not 2-D
    data.

  * **Progressive transmit order.** The band ID alone routes correctly at ~1 symbol (it is decision-
    lossless, magnitude-lossy); the within-band **Gray**-ordered local index refines it to the exact
    quantized cell (full magnitude) only when the link can afford it. On a degrading link you keep routing
    correctly and lose only fidelity.

All continuous math (``sqrt``, the golden angle in degrees) lives at **build time** here — the edge path
is integer table lookup + integer compares. This module builds the layout and the codec; the gate is the
routing-accuracy-vs-bits benchmark (``bench/spiral_bench.py``) and the decisions-preserved + frozen
tessellation conformance tests. Hysteresis at the band edges (anti-flap) is a sampling concern of the
edge, deliberately outside this codec.

Scope: an OPTION for *multi-dimensional, correlated* state where progressive refinement pays — not the
default. Scalar channels stay on the layer-2 quantizer (``quantizer.py`` / ``wire.py``); O(1) here holds
only after quantization to a bounded key space.
"""
from __future__ import annotations

import ast
import math
from typing import Any, Dict, Iterator, List, Optional, Tuple

from prismpath import predicates

import quantizer as q
import wire as w
import zeckendorf as z

GOLDEN_ANGLE_U32 = 0x9E3779B9                 # golden ratio * 2^32; add-with-overflow == mod 2*pi, no trig
GOLDEN_ANGLE_DEG = 180.0 * (3.0 - math.sqrt(5.0))   # ~= 137.5077640; build-time only (geometry/plots)


# --------------------------------------------------------------- integer-only spiral geometry (edge path)
def theta_u32(n: int) -> int:
    """Golden angle of point ``n`` as a ``u32`` phase — a single multiply-add, overflow == mod 2*pi."""
    return (n * GOLDEN_ANGLE_U32) & 0xFFFFFFFF


def radius2(n: int) -> int:
    """Squared radius of point ``n`` (``r^2 = c^2 * n``, ``c = 1``): a radial ring ``r < R`` is ``n < R^2``."""
    return n


def spiral_xy(n: int, c: float = 1.0) -> Tuple[float, float]:
    """Build-time Cartesian coords of point ``n`` (Vogel model). Floats — for tessellation/plots only."""
    r = c * math.sqrt(n)
    theta = math.radians(n * GOLDEN_ANGLE_DEG)
    return (r * math.cos(theta), r * math.sin(theta))


# --------------------------------------------------------------- mixed-radix reflected Gray code
def mixed_radix_gray(radices: List[int]) -> Iterator[Tuple[int, ...]]:
    """Yield every cell of a mixed-radix grid in reflected Gray order: **consecutive tuples differ by 1
    in exactly one field**. Locality ordering for the on-demand within-band refinement (small deltas)."""
    n = len(radices)
    digits = [0] * n
    directions = [1] * n
    total = 1
    for r in radices:
        total *= r
    yield tuple(digits)
    for _ in range(total - 1):
        i = n - 1
        while i >= 0:
            nd = digits[i] + directions[i]
            if 0 <= nd < radices[i]:
                digits[i] = nd
                break
            directions[i] = -directions[i]     # reflect this wheel, carry to the next more-significant one
            i -= 1
        yield tuple(digits)


def _node_fields(graph, node: str, parts: Dict[str, "q.FieldPartition"]) -> List[str]:
    """The decision-relevant fields this node actually routes on (canonical sorted order)."""
    seen: List[str] = []
    for _target, cond in graph.nodes[node].edges:
        if not predicates.is_deterministic(cond) or predicates.is_semantic(cond):
            continue
        expr = predicates._expr_of(cond)
        if expr.lower() in predicates.ALWAYS or expr.lower() in predicates.NEVER:
            continue
        try:
            body = ast.parse(expr, mode="eval").body
        except SyntaxError:
            continue
        for field, _op, _const in q._atoms(body):
            if field in parts and field not in seen:
                seen.append(field)
    return sorted(seen)


# --------------------------------------------------------------- the layout
class SpiralLayout:
    """A decision-first spiral packing of one node's joint quantized-cell space.

    Bands (routes) are contiguous, ordered center-outward (baseline central, severe branches outward);
    cells within a band are Gray-ordered for locality. ``index`` packs a reading to ``n``; ``band_id`` is
    the cheap decision symbol; ``route_of`` recovers the route from ``n`` with integer compares (the Level
    M atom).
    """

    def __init__(self, graph, node: str):
        self.graph = graph
        self.node = node
        self.parts = q.build_partitions(graph)
        self.fields = _node_fields(graph, node, self.parts)
        if not self.fields:
            raise ValueError(f"node {node!r} routes on no decision-relevant fields — nothing to pack")
        self.radices = [self.parts[f].n for f in self.fields]

        # Route every joint cell; group cells by route in edge-declaration (severity) order, Gray-ordered
        # within each band -> contiguous, severity-ordered index ranges.
        order = self._route_order()                       # route -> severity rank (first appearance)
        buckets: Dict[Optional[str], List[Tuple[int, ...]]] = {}
        for cell in mixed_radix_gray(self.radices):       # Gray order => within-band order is Gray-local
            route = self._route_of_cell(cell)
            buckets.setdefault(route, []).append(cell)

        self.routes: List[Optional[str]] = sorted(buckets, key=lambda r: order.get(r, len(order)))
        self.band_index: Dict[Optional[str], int] = {r: i for i, r in enumerate(self.routes)}
        self.band_base: List[int] = []
        self.band_width: List[int] = []
        self.cell_of: List[Tuple[int, ...]] = []          # n -> cell
        self.n_of: Dict[Tuple[int, ...], int] = {}        # cell -> n
        base = 0
        for r in self.routes:
            cells = buckets[r]
            self.band_base.append(base)
            self.band_width.append(len(cells))
            for cell in cells:
                self.n_of[cell] = len(self.cell_of)
                self.cell_of.append(cell)
            base += len(cells)
        self.size = base

    # -- build-time helpers -------------------------------------------------
    def _route_order(self) -> Dict[Optional[str], int]:
        """Severity rank per route: LOWER = more central. First-match flows declare severe branches first
        and the baseline (``else``) last, so we reverse edge order -> baseline at the dense center (rank 0),
        most-specific branches outward. An unrouted cell (``None``) sorts outermost."""
        appear: List[Optional[str]] = []
        for target, cond in self.graph.nodes[self.node].edges:
            if predicates.is_deterministic(cond) and target not in appear:
                appear.append(target)
        return {t: i for i, t in enumerate(reversed(appear))}

    def _cell_reading(self, cell: Tuple[int, ...]) -> Dict[str, Any]:
        return {f: self.parts[f].representative(s) for f, s in zip(self.fields, cell)}

    def _route_of_cell(self, cell: Tuple[int, ...]) -> Optional[str]:
        return w.route_node(self.graph, self.node, self._cell_reading(cell))

    # -- packing (edge path) ------------------------------------------------
    def cell(self, reading: Dict[str, Any]) -> Tuple[int, ...]:
        """A reading -> its joint symbol tuple over this node's fields."""
        return tuple(self.parts[f].symbol(reading[f]) for f in self.fields)

    def index(self, reading: Dict[str, Any]) -> int:
        """A reading -> its spiral index ``n``."""
        return self.n_of[self.cell(reading)]

    def band_id(self, reading: Dict[str, Any]) -> int:
        """A reading -> its band (route) index — the cheap, decision-lossless wire symbol."""
        return self.band_index[self._route_of_cell(self.cell(reading))]

    def route_of(self, n: int) -> Optional[str]:
        """``n`` -> route, by integer band-boundary compares (``base <= n < base+width``: the Level M atom)."""
        for b in range(len(self.routes)):
            if n < self.band_base[b] + self.band_width[b]:   # ranges are contiguous & ascending
                return self.routes[b]
        raise ValueError(f"index {n} outside the spiral ({self.size} cells)")

    def band_bounds(self) -> List[Tuple[int, int, Optional[str]]]:
        """``[(lo, hi_exclusive, route), ...]`` — the contiguous decision-bands."""
        return [(self.band_base[b], self.band_base[b] + self.band_width[b], self.routes[b])
                for b in range(len(self.routes))]

    # -- reconstruct --------------------------------------------------------
    def reconstruct_band(self, band_id: int) -> Dict[str, Any]:
        """Band ID -> a representative reading of that band (routes to the band's route; magnitude-lossy)."""
        return self._cell_reading(self.cell_of[self.band_base[band_id]])

    def reconstruct(self, n: int) -> Dict[str, Any]:
        """``n`` -> the exact cell's representative reading (full quantized magnitude)."""
        return self._cell_reading(self.cell_of[n])

    # -- wire codec ---------------------------------------------------------
    def encode_decision(self, reading: Dict[str, Any]) -> str:
        """The cheap stream: just the band ID (Fibonacci-coded). Routes correctly; carries no magnitude."""
        return z.encode(self.band_id(reading) + 1)

    def decode_decision(self, bits: str) -> Optional[str]:
        """Cheap-stream bits -> the route."""
        return self.routes[z.decode(bits) - 1]

    def encode_progressive(self, reading: Dict[str, Any]) -> Tuple[str, str]:
        """(decision bits, refinement bits): band ID first, then the within-band Gray local index."""
        n = self.index(reading)
        b = self.band_index[self.route_of(n)]
        local = n - self.band_base[b]
        return z.encode(b + 1), z.encode(local + 1)

    def decode_progressive(self, decision_bits: str, refine_bits: str) -> Dict[str, Any]:
        """(decision, refinement) -> the exact cell's representative reading."""
        b = z.decode(decision_bits) - 1
        local = z.decode(refine_bits) - 1
        return self.reconstruct(self.band_base[b] + local)

    # -- conformance / inspection ------------------------------------------
    def tessellation(self) -> Dict[str, Any]:
        """A frozen-corpus view: every cell -> its ``n``, band index, route, and build-time xy."""
        cells = []
        for n, cell in enumerate(self.cell_of):
            x, y = spiral_xy(n)
            cells.append({"cell": list(cell), "n": n,
                          "band": self.band_index[self.route_of(n)],
                          "route": self.route_of(n),
                          "xy": [round(x, 6), round(y, 6)]})
        return {"node": self.node, "fields": self.fields, "radices": self.radices,
                "bands": [{"route": r, "base": self.band_base[i], "width": self.band_width[i]}
                          for i, r in enumerate(self.routes)],
                "size": self.size, "cells": cells}
