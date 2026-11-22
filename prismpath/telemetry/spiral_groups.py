# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The spiral profile for policies whose joint grid is too large to enumerate (PROTOCOL.md 2.6.1).

`spiral.SpiralLayout` lists every cell of a node's joint grid, so it cannot be built for a policy with
tens of fields. This module keeps the same two tiers and changes how each is found.

Band tier. The band is the route the node fires, coded by its rank in the declared edge order (baseline
central, most specific outward). The reading is evaluated once, so no grid is listed.

Signature tier (field-partition fusion). The node's fields are grouped by which rules read them together.
A group's reachable grid stays at or under `GROUP_LIMIT` cells. Each group sends the *residual* of every
rule on its cell (the rule's condition with this group's fields filled in and every other field left
open, cut after the first rule that is already true), coded by the rank of that residual's class among
the group's classes. The classes of all groups together determine the decision exactly, because two
cells of one class decide alike for every value of the other fields. Within a group the layout is a
spiral in the `SpiralLayout` sense: the classes are the bands and the cells inside a class are Gray
ordered, so the refinement tier is the Gray index of the cell inside its class.

`layout_for` returns a `SpiralLayout` when the joint grid fits under `ENUMERATION_LIMIT`, so a policy that
already used the spiral profile keeps its bytes, and a `GroupedLayout` otherwise.
"""
from __future__ import annotations

import ast
import hashlib
import itertools
import math
import random
import struct
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Sequence, Tuple

from prismpath.kernel import predicates
from prismpath.telemetry import quantizer, spiral, wire
from prismpath.telemetry import zeckendorf as zeck

ENUMERATION_LIMIT = 300_000      # a joint grid at or under this is listed by SpiralLayout
GROUP_LIMIT = 50_000             # a group's reachable grid is kept at or under this by merging
MAX_GROUP_CELLS = 1_000_000      # one atom that reads several fields can force a bigger group; refuse beyond

MAGIC = b"PPLF"
VERSION = 1
TIER_BAND, TIER_SIGNATURE, TIER_REFINED = 1, 2, 3
_TRUE, _FALSE = ("T",), ("F",)


class StreamMismatch(ValueError):
    """A stream that does not belong to the policy or layout it was handed to: wrong magic or version,
    another policy's hash, another layout's hash, or a body that does not decode to whole decisions."""


# ----------------------------------------------------------------------------- policy analysis
def _names(node) -> set:
    return {item.id for item in ast.walk(node) if isinstance(item, ast.Name)}


def _edge_tree(cond: str):
    expr = predicates._expr_of(cond).strip()
    if expr.lower() in predicates.ALWAYS:
        return True
    if expr.lower() in predicates.NEVER:
        return False
    tree = ast.parse(expr, mode="eval")
    predicates.fold_unary_signs(tree)
    return tree.body


def _atoms(node, out: list) -> None:
    if node is True or node is False:
        return
    if isinstance(node, ast.BoolOp):
        for value in node.values:
            _atoms(value, out)
    elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        _atoms(node.operand, out)
    else:
        out.append(node)


class _Residuals:
    """Residuals of conditions over one group, memoized by node and by the cells of the group fields the
    node reads, so a node is evaluated once per combination of those cells, not once per cell."""

    def __init__(self, group: set):
        self.group = group
        self._names: Dict[int, frozenset] = {}
        self._memo: Dict[tuple, Any] = {}

    def names(self, node) -> frozenset:
        found = self._names.get(id(node))
        if found is None:
            found = self._names[id(node)] = frozenset(_names(node))
        return found

    def of(self, node, ctx: Dict[str, Any]):
        """A condition with the group's names set from `ctx` and every other name left open, in a
        canonical form: equal forms decide alike for every value of the open names."""
        if node is True:
            return _TRUE
        if node is False:
            return _FALSE
        reads = tuple(sorted(self.names(node) & self.group))
        key = (id(node), tuple(ctx[name] for name in reads))
        found = self._memo.get(key)
        if found is None:
            found = self._memo[key] = self._compute(node, ctx)
        return found

    def _compute(self, node, ctx: Dict[str, Any]):
        if isinstance(node, ast.BoolOp):
            kids = [self.of(value, ctx) for value in node.values]
            if isinstance(node.op, ast.And):
                if _FALSE in kids:
                    return _FALSE
                rest = frozenset(kid for kid in kids if kid != _TRUE)
                return _TRUE if not rest else (next(iter(rest)) if len(rest) == 1 else ("and", rest))
            if _TRUE in kids:
                return _TRUE
            rest = frozenset(kid for kid in kids if kid != _FALSE)
            return _FALSE if not rest else (next(iter(rest)) if len(rest) == 1 else ("or", rest))
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            kid = self.of(node.operand, ctx)
            return _FALSE if kid == _TRUE else _TRUE if kid == _FALSE else ("not", kid)
        used = self.names(node)
        if used and used <= self.group:
            return _TRUE if predicates._ev(node, ctx, 0) else _FALSE
        if used & self.group:
            raise ValueError(f"an atom reads fields of two groups: {ast.dump(node)}")
        if not used:
            return _TRUE if predicates._ev(node, {}, 0) else _FALSE
        return ("atom", ast.dump(node))


def reachable(part: "quantizer.FieldPartition") -> List[Tuple[int, Any]]:
    """(symbol, a raw value in that cell the encoder accepts) for every cell some admissible value falls
    in. A defined integer field admits only its declared range, so a cell wholly outside it is never sent
    and the value used is clamped into the range."""
    definition = part.definition
    out = []
    for symbol, cell in enumerate(part.cells):
        if definition is not None and part.kind == "numeric" and not cell.get("absent"):
            low = definition.minimum if cell["lo"] is None else max(cell["lo"], definition.minimum)
            high = definition.maximum if cell["hi"] is None else min(cell["hi"], definition.maximum)
            if low > high:
                continue
            out.append((symbol, low))
        else:
            out.append((symbol, cell["rep"]))
    return out


def boundary_values(part):
    """Raw values at and next to every cut, every named constant, a near miss string, and absence."""
    if part.kind == "boolean":
        values = [False, True]
    elif part.kind == "categorical":
        consts = [cell["const"] for cell in part.cells if cell.get("const") != quantizer.OTHER_CELL]
        values = consts + [const + "~" for const in consts[:3]] + ["ünlisted"]
    else:
        found = set()
        for cell in part.cells:
            if cell.get("absent"):
                continue
            for edge in (cell["lo"], cell["hi"]):
                if edge is not None:
                    found.update((edge - 1, edge, edge + 1))
        values = sorted(found) or [0]
    if part.definition is not None and part.definition.absent_allowed:
        values = list(values) + [None]
    return list(values)


def populations(parts, seed, count):
    """The uniform (a cell, then a value in it) and boundary populations of the Facet measurement,
    keeping the readings the encoder accepts."""
    rng = random.Random(seed)
    order = sorted(parts)
    reach = {field: reachable(parts[field]) for field in order}
    edges = {field: boundary_values(parts[field]) for field in order}
    pops = {"uniform": [{f: rng.choice(reach[f])[1] for f in order} for _ in range(count)],
            "boundary": [{f: rng.choice(edges[f]) for f in order} for _ in range(count)]}
    for name, pop in pops.items():
        kept = []
        for reading in pop:
            try:
                quantizer.checked_quantize(parts, reading)
                kept.append(reading)
            except quantizer.InputRefused:
                pass
        pops[name] = kept
    return pops


def joint_cells(graph, node: str, parts: Optional[Dict[str, Any]] = None) -> int:
    """The size of the node's joint grid (what `SpiralLayout` would have to list)."""
    parts = parts if parts is not None else quantizer.build_partitions(graph)
    return math.prod(parts[field].n for field in spiral._node_fields(graph, node, parts))


def route_order(graph, node: str) -> List[Optional[str]]:
    """The bands of a node, centre outward: the deterministic targets in reverse first appearance (the
    baseline, declared last, is band 0), then `None` for a reading no rule routes."""
    seen: List[Optional[str]] = []
    for target, cond in graph.nodes[node].edges:
        if predicates.is_deterministic(cond) and target not in seen:
            seen.append(target)
    return list(reversed(seen)) + [None]


def group_fields(trees: list, fields: Sequence[str], reach: Dict[str, list],
                 limit: int = GROUP_LIMIT) -> List[List[str]]:
    """Fields grouped by which rules read them together, greedily, each group's grid at or under `limit`
    (an atom that reads two fields puts them in one group whatever the size)."""
    parent = {field: field for field in fields}
    size = {field: len(reach[field]) for field in fields}

    def find(item):
        while parent[item] != item:
            parent[item] = parent[parent[item]]
            item = parent[item]
        return item

    for tree in trees:
        found: list = []
        _atoms(tree, found)
        for atom in found:
            shared = sorted(_names(atom) & set(fields))
            for other in shared[1:]:
                root_a, root_b = find(shared[0]), find(other)
                if root_a != root_b:
                    parent[root_b] = root_a
                    size[root_a] *= size[root_b]
    together: Counter = Counter()
    for tree in trees:
        roots = sorted({find(field) for field in _names(tree) if field in parent}) \
            if tree not in (True, False) else []
        for first, second in itertools.combinations(roots, 2):
            together[(first, second)] += 1
    for (first, second), _count in together.most_common():
        root_a, root_b = find(first), find(second)
        if root_a != root_b and size[root_a] * size[root_b] <= limit:
            parent[root_b] = root_a
            size[root_a] *= size[root_b]
    grouped: Dict[str, List[str]] = defaultdict(list)
    for field in fields:
        grouped[find(field)].append(field)
    return [sorted(members) for members in grouped.values()]


# ----------------------------------------------------------------------------- one group
class GroupLayout:
    """The spiral of one field group: classes of cells with the same residual are the bands (largest
    first, ties by first appearance in Gray order), cells inside a class in Gray order."""

    def __init__(self, fields: List[str], trees: list, parts: Dict[str, Any], reach: Dict[str, list]):
        self.fields = fields
        self.parts = parts
        self.reach = [reach[field] for field in fields]
        radices = [len(options) for options in self.reach]
        cells = math.prod(radices)
        if cells > MAX_GROUP_CELLS:
            raise ValueError(f"group {fields} has {cells:,} cells, over {MAX_GROUP_CELLS:,}")
        residuals = _Residuals(set(fields))
        by_class: Dict[tuple, List[Tuple[int, ...]]] = {}
        for position in spiral.mixed_radix_gray(radices):
            context = {field: options[at][1] for field, options, at in zip(fields, self.reach, position)}
            signature = []
            for tree in trees:
                residual = residuals.of(tree, context)
                signature.append(residual)
                if residual == _TRUE:
                    break
            by_class.setdefault(tuple(signature), []).append(position)
        ranked = sorted(by_class.values(), key=lambda members: -len(members))   # stable: Gray first seen
        self.class_width: List[int] = [len(members) for members in ranked]
        self.cell_of: List[List[Tuple[int, ...]]] = ranked      # class -> positions in Gray order
        self.size = cells
        self._class_local: Dict[Tuple[int, ...], Tuple[int, int]] = {}
        for rank, members in enumerate(ranked):
            for local, position in enumerate(members):
                self._class_local[tuple(self.reach[i][at][0] for i, at in enumerate(position))] = (rank, local)

    @property
    def classes(self) -> int:
        return len(self.class_width)

    def locate(self, symbols: Dict[str, int]) -> Tuple[int, int]:
        """A reading's symbols -> (class rank, Gray index inside the class)."""
        return self._class_local[tuple(symbols[field] for field in self.fields)]

    def reading(self, rank: int, local: int = 0) -> Dict[str, Any]:
        """A representative reading of a cell (the class's first cell when `local` is 0)."""
        position = self.cell_of[rank][local]
        return {field: options[at][1] for field, options, at in zip(self.fields, self.reach, position)}


# ----------------------------------------------------------------------------- one node
class GroupedLayout:
    """A node's band and signature tiers without listing its joint grid."""

    def __init__(self, graph, node: str, parts: Optional[Dict[str, Any]] = None, group_limit: int = GROUP_LIMIT):
        self.graph = graph
        self.node = node
        self.parts = parts if parts is not None else quantizer.build_partitions(graph)
        self.fields = spiral._node_fields(graph, node, self.parts)
        if not self.fields:
            raise ValueError(f"node {node!r} routes on no decision-relevant fields  -  nothing to pack")
        self.routes = route_order(graph, node)
        self.band_index = {route: band for band, route in enumerate(self.routes)}
        reach = {field: reachable(self.parts[field]) for field in self.fields}
        trees = [_edge_tree(cond) for _target, cond in graph.nodes[node].edges
                 if predicates.is_deterministic(cond)]
        self.groups = [GroupLayout(members, trees, self.parts, reach)
                       for members in group_fields(trees, self.fields, reach, group_limit)]

    # -- band tier ---------------------------------------------------------
    def band_id(self, reading: Dict[str, Any]) -> int:
        """The reading evaluated once: the fired route's band."""
        return self.band_index[wire.route_node(self.graph, self.node, reading)]

    def route_of_band(self, band: int) -> Optional[str]:
        return self.routes[band]

    # -- signature tier ----------------------------------------------------
    def locate(self, symbols: Dict[str, int]) -> List[Tuple[int, int]]:
        return [group.locate(symbols) for group in self.groups]

    def signature(self, symbols: Dict[str, int]) -> List[int]:
        return [rank for rank, _local in self.locate(symbols)]

    def rebuild(self, signature: Sequence[int], refinement: Optional[Sequence[int]] = None) -> Dict[str, Any]:
        """The groups' classes (and cells, when refined) -> a reading that decides as every reading of
        those classes does."""
        reading: Dict[str, Any] = {}
        for index, group in enumerate(self.groups):
            reading.update(group.reading(signature[index], 0 if refinement is None else refinement[index]))
        return reading

    def route_of_signature(self, signature: Sequence[int]) -> Optional[str]:
        return wire.route_node(self.graph, self.node, self.rebuild(signature))

    # -- identity ----------------------------------------------------------
    def describe(self) -> str:
        """The layout as text, for its hash: the node, its fields, its band list, and per group its fields,
        radices and class sizes."""
        routes = "/".join(route or "" for route in self.routes)
        groups = " ".join("[{}:{}:{}]".format(",".join(group.fields),
                                              "x".join(str(len(options)) for options in group.reach),
                                              ",".join(str(width) for width in group.class_width))
                          for group in self.groups)
        return f"grouped {self.node} {','.join(self.fields)} {routes} {groups}"


def layout_for(graph, node: str, parts: Optional[Dict[str, Any]] = None, limit: int = ENUMERATION_LIMIT,
               group_limit: int = GROUP_LIMIT):
    """`SpiralLayout` when the node's joint grid fits under `limit`, `GroupedLayout` when it does not."""
    parts = parts if parts is not None else quantizer.build_partitions(graph)
    if joint_cells(graph, node, parts) <= limit:
        return spiral.SpiralLayout(graph, node)
    return GroupedLayout(graph, node, parts, group_limit)


# ----------------------------------------------------------------------------- the stream
def policy_hash(text: str) -> bytes:
    """The 16 bytes that name a policy in a stream: SHA-256 of its document text, truncated."""
    return hashlib.sha256(text.encode("utf-8")).digest()[:16]


class GroupedFacet:
    """Every decision node of a policy under the spiral profile, and the stream codec over them.

    A stream is a 42 byte preamble (magic, version, tier, policy hash, layout hash, decision count)
    followed by the tier's bits, zero padded to a byte. Per decision, per decision node in document
    order, the tier carries Fibonacci codes of `value + 1`:

      band        one code, the band
      signature   one code per group of a grouped node (omitted for a group with one class); a node
                  that fits `SpiralLayout` carries its band instead
      refined     the signature codes of every node, then per node per group the Gray index inside the
                  class (omitted for a class of one cell); a node that fits `SpiralLayout` carries
                  its index inside its band
    """

    def __init__(self, graph, policy_text: str, limit: int = ENUMERATION_LIMIT, group_limit: int = GROUP_LIMIT):
        self.graph = graph
        self.parts = quantizer.build_partitions(graph)
        self.order = wire._order(self.parts)
        self.policy_hash = policy_hash(policy_text)
        self.nodes = [name for name in wire.decision_nodes(graph)
                      if spiral._node_fields(graph, name, self.parts)]
        self.layouts = {name: layout_for(graph, name, self.parts, limit, group_limit) for name in self.nodes}
        self.layout_hash = hashlib.sha256("\n".join(
            lay.describe() if isinstance(lay, GroupedLayout) else f"joint {lay.node} {lay.size}"
            for lay in self.layouts.values()).encode("utf-8")).digest()[:16]

    # -- per reading -------------------------------------------------------
    def _values(self, reading: Dict[str, Any], tier: int) -> List[int]:
        out: List[int] = []
        if tier == TIER_BAND:
            return [self.layouts[name].band_id(reading) for name in self.nodes]
        symbols = quantizer.checked_quantize(self.parts, reading)
        located = {}
        for name in self.nodes:
            layout = self.layouts[name]
            if isinstance(layout, GroupedLayout):
                located[name] = layout.locate(symbols)
                out.extend(rank for (rank, _local), group in zip(located[name], layout.groups)
                           if group.classes > 1)
            else:
                out.append(layout.band_id(reading))
        if tier == TIER_REFINED:
            for name in self.nodes:
                layout = self.layouts[name]
                if isinstance(layout, GroupedLayout):
                    out.extend(local for (rank, local), group in zip(located[name], layout.groups)
                               if group.class_width[rank] > 1)
                else:
                    out.append(layout.index(reading) - layout.band_base[layout.band_id(reading)])
        return out

    def encode_reading(self, reading: Dict[str, Any], tier: int) -> str:
        return zeck.encode_stream(value + 1 for value in self._values(reading, tier))

    def decode_reading(self, bits: str, tier: int) -> Dict[str, Optional[str]]:
        """One decision's bits -> the route of every decision node."""
        return self._read(zeck.decode_stream(bits), tier)[0]

    def _read(self, ints: List[int], tier: int, at: int = 0) -> Tuple[Dict[str, Optional[str]], int]:
        values = [value - 1 for value in ints]

        def take() -> int:
            nonlocal at
            if at >= len(values):
                raise StreamMismatch("a decision is cut short")
            at += 1
            return values[at - 1]

        routes: Dict[str, Optional[str]] = {}
        ranks: Dict[str, List[int]] = {}
        for name in self.nodes:
            layout = self.layouts[name]
            if tier == TIER_BAND or not isinstance(layout, GroupedLayout):
                band = take()
                if not 0 <= band < len(layout.routes):
                    raise StreamMismatch("a band is outside its node")
                routes[name] = layout.routes[band]
                continue
            ranks[name] = []
            for group in layout.groups:
                rank = take() if group.classes > 1 else 0
                if not 0 <= rank < group.classes:
                    raise StreamMismatch("a class rank is outside its group")
                ranks[name].append(rank)
            routes[name] = layout.route_of_signature(ranks[name])
        if tier == TIER_REFINED:
            for name in self.nodes:
                layout = self.layouts[name]
                if isinstance(layout, GroupedLayout):
                    widths = [group.class_width[rank] for group, rank in zip(layout.groups, ranks[name])]
                    limits = [width for width in widths if width > 1]
                else:
                    limits = [layout.size]
                for width in limits:
                    if not 0 <= take() < width:
                        raise StreamMismatch("a refinement index is outside its class")
        return routes, at

    # -- the container -----------------------------------------------------
    def encode(self, readings: Sequence[Dict[str, Any]], tier: int) -> bytes:
        if tier not in (TIER_BAND, TIER_SIGNATURE, TIER_REFINED):
            raise ValueError(f"unknown tier {tier}")
        if tier != TIER_BAND and not any(isinstance(lay, GroupedLayout) for lay in self.layouts.values()):
            raise ValueError("this policy has no grouped node; its band and refinement tiers are SpiralLayout's")
        bits = "".join(self.encode_reading(reading, tier) for reading in readings)
        bits += "0" * (-len(bits) % 8)
        body = int(bits, 2).to_bytes(len(bits) // 8, "big") if bits else b""
        return MAGIC + struct.pack("<BB", VERSION, tier) + self.policy_hash + self.layout_hash \
            + struct.pack("<I", len(readings)) + body

    def decode(self, data: bytes) -> List[Dict[str, Optional[str]]]:
        """A stream -> the route of every decision node of every decision. Refuses a stream that is
        another policy's, another layout's, or not whole decisions."""
        if len(data) < 42 or data[:4] != MAGIC:
            raise StreamMismatch("not a grouped Facet stream")
        version, tier = struct.unpack_from("<BB", data, 4)
        if version != VERSION:
            raise StreamMismatch(f"unsupported version {version}")
        if tier not in (TIER_BAND, TIER_SIGNATURE, TIER_REFINED):
            raise StreamMismatch(f"unknown tier {tier}")
        if data[6:22] != self.policy_hash:
            raise StreamMismatch("policy hash does not match")
        if data[22:38] != self.layout_hash:
            raise StreamMismatch("layout hash does not match")
        (count,) = struct.unpack_from("<I", data, 38)
        body = data[42:]
        bits = bin(int.from_bytes(body, "big"))[2:].zfill(8 * len(body)) if body else ""
        ints, tail = zeck.decode_stream_tail(bits)
        if "1" in tail:
            raise StreamMismatch("the stream ends inside a code")
        decisions, at = [], 0
        for _ in range(count):
            routes, at = self._read(ints, tier, at)
            decisions.append(routes)
        if at != len(ints):
            raise StreamMismatch("the stream has codes beyond its decisions")
        return decisions
