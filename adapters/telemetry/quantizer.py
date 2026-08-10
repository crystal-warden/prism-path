"""Decision-preserving quantizer — the differentiator.

A flow's routing over a field changes truth only at the constants that field is compared against
(`field OP const`, the Level M fragment). Those constants partition the field's value domain into cells
on which *every* atom has constant truth — so any two values in the same cell route identically. The
minimum sufficient statistic for the field's decisions is therefore just **which cell** a reading falls
in: a small symbol. Reconstructing any representative of that cell reproduces every routing decision the
flow makes on that field.

This module extracts those cells from a flow (via the same conditions `model_check`/`ppt_compile` read)
and maps readings <-> symbols. The proof that it never mis-resolves a decision is the decisions-preserved
conformance test (next piece) — here we build the partition and a focused self-check.

Handled field kinds (auto-detected from the compared constants):
  * numeric (integer) — order (`< <= > >=`) and/or equality (`== !=`); coarsest cell partition via
    representative-evaluation + adjacent merge.
  * boolean — a bare `field` (truthiness) or `field == True/False`; two cells.
  * categorical — string `== != in not in`; one cell per distinct constant + an "other" cell.
A field mixing kinds (e.g. int and str constants) raises — well-formed Level M flows don't.
"""
from __future__ import annotations

import ast
from typing import Any, Dict, List, Optional, Tuple

from prismpath import predicates
from prismpath.parser import parse_file  # noqa: F401  (re-exported for callers)

_ORDER = {"Lt": "<", "LtE": "<=", "Gt": ">", "GtE": ">="}
_FLIP = {"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "!=": "!="}
_OTHER = "\x00__other__"          # a sentinel string equal to no real categorical constant


# ----------------------------------------------------------------- atom extraction
def _atoms(expr_node) -> List[Tuple[str, str, Any]]:
    """Collect (field, op, const) atoms from a predicate AST. `op` in {<,<=,>,>=,==,!=,in,not in,truthy}.
    `not`/`and`/`or` add no cuts, only recursion. Field-vs-field / non-literal atoms are ignored (they
    are not Level M and carry no transmittable cut)."""
    out: List[Tuple[str, str, Any]] = []
    n = expr_node
    if isinstance(n, ast.BoolOp):
        for v in n.values:
            out += _atoms(v)
    elif isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.Not):
        out += _atoms(n.operand)               # cut points unchanged by negation
    elif isinstance(n, ast.Name):
        out.append((n.id, "truthy", None))     # bare field -> truthiness
    elif isinstance(n, ast.Compare) and len(n.ops) == 1:
        left, op, right = n.left, n.ops[0], n.comparators[0]
        opname = type(op).__name__
        if opname in _ORDER or opname in ("Eq", "NotEq"):
            sym = _ORDER.get(opname) or ("==" if opname == "Eq" else "!=")
            if isinstance(left, ast.Name) and isinstance(right, ast.Constant):
                out.append((left.id, sym, right.value))
            elif isinstance(right, ast.Name) and isinstance(left, ast.Constant):
                out.append((right.id, _FLIP[sym], left.value))
        elif opname in ("In", "NotIn") and isinstance(left, ast.Name) \
                and isinstance(right, (ast.List, ast.Tuple)):
            consts = tuple(e.value for e in right.elts if isinstance(e, ast.Constant))
            if len(consts) == len(right.elts):
                out.append((left.id, "in" if opname == "In" else "not in", consts))
    return out


def _flow_atoms(graph) -> Dict[str, List[Tuple[str, Any]]]:
    """Every field's (op, const) atoms across all deterministic, non-semantic edges in the flow."""
    fields: Dict[str, List[Tuple[str, Any]]] = {}
    for node in graph.nodes.values():
        for _target, cond in node.edges:
            if not predicates.is_deterministic(cond) or predicates.is_semantic(cond):
                continue
            expr = predicates._expr_of(cond)
            if expr.lower() in predicates.ALWAYS or expr.lower() in predicates.NEVER:
                continue
            try:
                body = ast.parse(expr, mode="eval").body
            except SyntaxError:
                continue
            for field, op, const in _atoms(body):
                fields.setdefault(field, []).append((op, const))
    return fields


# ----------------------------------------------------------------- per-field partitions
class FieldPartition:
    """An ordered list of decision-cells for one field. `symbol(value)` -> cell index;
    `representative(symbol)` -> a value in that cell that routes identically."""

    def __init__(self, field: str, kind: str, cells: List[dict]):
        self.field = field
        self.kind = kind          # "numeric" | "boolean" | "categorical"
        self.cells = cells        # each: {"rep": value, plus kind-specific membership fields}
        self.n = len(cells)

    def symbol(self, value: Any) -> int:
        if self.kind == "numeric":
            v = int(value)
            for i, c in enumerate(self.cells):
                if (c["lo"] is None or v >= c["lo"]) and (c["hi"] is None or v <= c["hi"]):
                    return i
            raise ValueError(f"{self.field}={value!r} fell outside its numeric partition")
        if self.kind == "boolean":
            return 1 if value else 0
        # categorical
        for i, c in enumerate(self.cells):
            if c.get("const", _OTHER) == value:
                return i
        return self.n - 1                     # the trailing "other" cell

    def representative(self, symbol: int) -> Any:
        return self.cells[symbol]["rep"]


def _atom_true(op: str, const: Any, v: Any) -> bool:
    if op == "<":  return v < const
    if op == "<=": return v <= const
    if op == ">":  return v > const
    if op == ">=": return v >= const
    if op == "==": return v == const
    if op == "!=": return v != const
    if op == "in": return v in const
    if op == "not in": return v not in const
    if op == "truthy": return bool(v)
    raise ValueError(op)


def _numeric_partition(field: str, atoms: List[Tuple[str, Any]]) -> FieldPartition:
    consts = sorted({int(c) for op, c in atoms if op in ("<", "<=", ">", ">=", "==", "!=")})
    if not consts:                            # only "truthy" on an int -> split at 0
        consts = [0]
    # fine cells: each constant as a point + integer gaps between (drop empty gaps)
    fine: List[Tuple[Optional[int], Optional[int]]] = []
    fine.append((None, consts[0] - 1))
    for i, c in enumerate(consts):
        fine.append((c, c))
        nxt = consts[i + 1] if i + 1 < len(consts) else None
        lo = c + 1
        hi = (nxt - 1) if nxt is not None else None
        if hi is None or lo <= hi:
            fine.append((lo, hi))
    def rep(lo, hi):
        if lo is not None: return lo
        if hi is not None: return hi
        return 0
    def truth(v):
        return tuple(_atom_true(op, c, v) for op, c in atoms)
    # merge adjacent fine cells with identical atom-truth vectors -> coarsest decision partition
    cells: List[dict] = []
    prev_tv = object()
    for lo, hi in fine:
        tv = truth(rep(lo, hi))
        if tv == prev_tv:
            cells[-1]["hi"] = hi              # extend the previous cell's upper bound
        else:
            cells.append({"lo": lo, "hi": hi, "rep": rep(lo, hi)})
            prev_tv = tv
    return FieldPartition(field, "numeric", cells)


def _boolean_partition(field: str) -> FieldPartition:
    return FieldPartition(field, "boolean", [{"rep": False}, {"rep": True}])


def _categorical_partition(field: str, atoms: List[Tuple[str, Any]]) -> FieldPartition:
    consts: List[Any] = []
    for op, c in atoms:
        vals = c if op in ("in", "not in") else (c,)
        for v in vals:
            if v not in consts:
                consts.append(v)
    cells = [{"const": c, "rep": c} for c in consts] + [{"const": _OTHER, "rep": _OTHER}]
    return FieldPartition(field, "categorical", cells)


def _classify_kind(atoms: List[Tuple[str, Any]]) -> str:
    consts = [c for op, c in atoms if op not in ("truthy",)]
    flat = []
    for op, c in atoms:
        flat += list(c) if op in ("in", "not in") else ([c] if op != "truthy" else [])
    has_str = any(isinstance(v, str) for v in flat)
    has_bool = any(isinstance(v, bool) for v in flat)
    has_int = any(isinstance(v, int) and not isinstance(v, bool) for v in flat)
    if has_str and (has_int):
        raise ValueError("field mixes string and numeric constants — not a Level M field")
    if has_str:
        return "categorical"
    if has_int:
        return "numeric"
    if has_bool:
        return "boolean"
    return "boolean"                          # only "truthy" seen


def build_partitions(graph) -> Dict[str, FieldPartition]:
    """Per decision-relevant field, the coarsest partition that preserves every routing decision."""
    parts: Dict[str, FieldPartition] = {}
    for field, atoms in _flow_atoms(graph).items():
        kind = _classify_kind(atoms)
        if kind == "numeric":
            parts[field] = _numeric_partition(field, atoms)
        elif kind == "categorical":
            parts[field] = _categorical_partition(field, atoms)
        else:
            parts[field] = _boolean_partition(field)
    return parts


# ----------------------------------------------------------------- quantize / reconstruct
def quantize(parts: Dict[str, FieldPartition], reading: Dict[str, Any]) -> Dict[str, int]:
    """A reading -> one small symbol per decision-relevant field (fields the flow never routes on are
    dropped: they cannot change any decision)."""
    return {f: p.symbol(reading[f]) for f, p in parts.items() if f in reading}


def reconstruct(parts: Dict[str, FieldPartition], symbols: Dict[str, int]) -> Dict[str, Any]:
    """Symbols -> a representative reading that routes identically to the original."""
    return {f: parts[f].representative(s) for f, s in symbols.items() if f in parts}
