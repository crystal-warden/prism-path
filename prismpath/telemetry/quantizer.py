# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Figueroa quantization, the reference implementation (PROTOCOL.md §1): the decision preserving quantizer.

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
import re
from typing import Optional, Any, Dict, List, Optional, Tuple

from prismpath.kernel import predicates
from prismpath.kernel.parser import parse_file  # noqa: F401  (re-exported for callers)

_ORDER = {"Lt": "<", "LtE": "<=", "Gt": ">", "GtE": ">="}
_FLIP = {"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "!=": "!="}
# The categorical partition's trailing cell: every value the flow never names. Public because a
# caller cannot tell an enumerated cell from the catch-all without it, and five modules already ask
# (decode, preflight, gen_decisions_corpus). The value is a sentinel string equal to no real
# categorical constant, so it can never collide with one the author wrote.
OTHER_CELL = "\x00__other__"


# ----------------------------------------------------------------- atom extraction
def atoms_of(expr_node) -> List[Tuple[str, str, Any]]:
    """Collect (field, op, const) atoms from a predicate AST. `op` in {<,<=,>,>=,==,!=,in,not in,truthy}.
    `not`/`and`/`or` add no cuts, only recursion. Field-vs-field / non-literal atoms are ignored (they
    are not Level M and carry no transmittable cut)."""
    out: List[Tuple[str, str, Any]] = []
    node = expr_node
    if isinstance(node, ast.BoolOp):
        for operand in node.values:
            out += atoms_of(operand)
    elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        out += atoms_of(node.operand)               # cut points unchanged by negation
    elif isinstance(node, ast.Name):
        out.append((node.id, "truthy", None))     # bare field -> truthiness
    elif isinstance(node, ast.Compare) and len(node.ops) == 1:
        left, op, right = node.left, node.ops[0], node.comparators[0]
        opname = type(op).__name__
        if opname in _ORDER or opname in ("Eq", "NotEq"):
            sym = _ORDER.get(opname) or ("==" if opname == "Eq" else "!=")
            if isinstance(left, ast.Name) and isinstance(right, ast.Constant):
                out.append((left.id, sym, right.value))
            elif isinstance(right, ast.Name) and isinstance(left, ast.Constant):
                out.append((right.id, _FLIP[sym], left.value))
        elif opname in ("In", "NotIn") and isinstance(left, ast.Name) \
                and isinstance(right, (ast.List, ast.Tuple)):
            consts = tuple(element.value for element in right.elts if isinstance(element, ast.Constant))
            if len(consts) == len(right.elts):
                out.append((left.id, "in" if opname == "In" else "not in", consts))
    return out


def flow_atoms(graph) -> Dict[str, List[Tuple[str, Any]]]:
    """Every field's (op, const) atoms across all deterministic, non-semantic edges in the flow.

    The cut points of one flow, keyed by field: what `build_partitions` turns into cells and what a
    profile reports for a single field. Edges that route on a model, or on always/never, contribute
    nothing, because no value of any field changes their truth."""
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
            for field, op, const in atoms_of(body):
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
            integer_value = int(value)
            for cell_index, cell in enumerate(self.cells):
                if ((cell["lo"] is None or integer_value >= cell["lo"])
                        and (cell["hi"] is None or integer_value <= cell["hi"])):
                    return cell_index
            raise ValueError(f"{self.field}={value!r} fell outside its numeric partition")
        if self.kind == "boolean":
            return 1 if value else 0
        # categorical
        for cell_index, cell in enumerate(self.cells):
            if cell.get("const", OTHER_CELL) == value:
                return cell_index
        return self.n - 1                     # the trailing "other" cell

    def representative(self, symbol: int) -> Any:
        return self.cells[symbol]["rep"]

    def checked_symbol(self, value: Any) -> int:
        """`symbol` behind acceptance: the value is accepted and converted by `accept_value`
        or the call raises InputRefused naming the field and the reason. This is the runtime
        boundary a library consumer should encode through; `symbol` keeps its permissive behavior
        for compatibility (truncated fractions, truthiness on boolean fields)."""
        reason, converted = accept_value(self.kind, value)
        if reason is not None:
            raise InputRefused(self.field, reason, value)
        return self.symbol(converted)


# ------------------------------------------------------------------ acceptance
# One rule set for the Python and Rust encoders and for both preflight tools, frozen as
# conformance/inputs.json. Integers are accepted within the range every JSON reader represents
# exactly, so a value that is in range here is the same value on the other side of any wire.
SAFE_INTEGER_LIMIT = 2 ** 53
REFUSAL_MISSING = "missing"
REFUSAL_WRONG_TYPE = "wrong_type"
REFUSAL_UNPARSEABLE_STRING = "unparseable_string"
REFUSAL_FRACTIONAL = "fractional"
REFUSAL_OUT_OF_RANGE = "out_of_range"
_INTEGER_LITERAL = re.compile(r"^[+-]?[0-9]+$")


class InputRefused(ValueError):
    """A reading value acceptance refuses, with the field and the reason."""

    def __init__(self, field: str, reason: str, value: Any):
        super().__init__(f"{field}: {reason} ({value!r})")
        self.field = field
        self.reason = reason
        self.value = value


def accept_value(kind: str, value: Any) -> Tuple[Optional[str], Any]:
    """(refusal reason, converted value) for one field kind. None as the reason means accepted.

    numeric accepts an int within the safe range, an integral float, a bool as 0 or 1, and a
    string that is an integer literal with an optional sign. A fractional number is refused rather
    than truncated, a string that is not an integer literal is refused rather than read as zero,
    and null is missing. boolean accepts a bool and a number exactly 0 or 1. categorical accepts a
    string only. Anything else is the wrong type."""
    if value is None:
        return REFUSAL_MISSING, None
    if kind == "numeric":
        if isinstance(value, bool):
            return None, int(value)
        if isinstance(value, int):
            integer_value = value
        elif isinstance(value, float):
            if value != value or value in (float("inf"), float("-inf")):
                return REFUSAL_OUT_OF_RANGE, None
            if value != int(value):
                return REFUSAL_FRACTIONAL, None
            integer_value = int(value)
        elif isinstance(value, str):
            if not _INTEGER_LITERAL.match(value):
                return REFUSAL_UNPARSEABLE_STRING, None
            integer_value = int(value)
        else:
            return REFUSAL_WRONG_TYPE, None
        if not -SAFE_INTEGER_LIMIT < integer_value < SAFE_INTEGER_LIMIT:
            return REFUSAL_OUT_OF_RANGE, None
        return None, integer_value
    if kind == "boolean":
        if isinstance(value, bool):
            return None, value
        if isinstance(value, (int, float)) and value in (0, 1):
            return None, bool(value)
        return REFUSAL_WRONG_TYPE, None
    if isinstance(value, str):
        return None, value
    return REFUSAL_WRONG_TYPE, None


def checked_quantize(parts: Dict[str, "FieldPartition"], reading: Dict[str, Any]) -> Dict[str, int]:
    """`quantize` behind acceptance: every decision field present and accepted, or
    InputRefused names the first field that is not."""
    symbols = {}
    for field in sorted(parts):
        if field not in reading:
            raise InputRefused(field, REFUSAL_MISSING, None)
        symbols[field] = parts[field].checked_symbol(reading[field])
    return symbols


def atom_true(op: str, const: Any, value: Any) -> bool:
    """Evaluate one atom, the quantizer's own evaluator: is `value OP const` true?

    Public so a caller checking a cell (predicate_profile, and the fusion adapter's cell referee)
    asks the partition builder itself rather than reimplementing the comparison and drifting."""
    if op == "<":  return value < const
    if op == "<=": return value <= const
    if op == ">":  return value > const
    if op == ">=": return value >= const
    if op == "==": return value == const
    if op == "!=": return value != const
    if op == "in": return value in const
    if op == "not in": return value not in const
    if op == "truthy": return bool(value)
    raise ValueError(op)


def _refuse_float(value) -> None:
    """A float comparison constant is the author's decision, not the codec's: the codec compares
    integers, so a float threshold is refused here with the constant named, the same fact
    facet_init reports as a float threshold. Found in the September 2026 review: before this check a
    float fell through _classify_kind to "boolean" and _numeric_partition truncated it with int()."""
    raise ValueError(f"float constant {value!r} in a comparison: the codec compares integers, "
                     f"round the threshold in the flow (facet_init reports it as a float threshold)")


def _numeric_partition(field: str, atoms: List[Tuple[str, Any]]) -> FieldPartition:
    # Every value at which some atom can change truth is a cut point: the ordering and equality
    # constants, every member of an `in` / `not in` list, and 0 when a bare truthiness atom is
    # present (int truthiness flips exactly at 0). The September 2026 Lean formalization of I1
    # found that the first version collected only the ordering/equality constants, so `x in (3, 5)`,
    # `x not in (7,)`, and `x` alongside `x >= 5` each put values that route differently into one
    # cell (prismpath/telemetry/tests/test_quantizer_cut_points.py pins all three).
    consts_set = set()
    for op, const in atoms:
        if op in ("<", "<=", ">", ">=", "==", "!="):
            if isinstance(const, float):
                _refuse_float(const)
            consts_set.add(int(const))
        elif op in ("in", "not in"):
            for member in const:
                if isinstance(member, float):
                    _refuse_float(member)
                if isinstance(member, int) and not isinstance(member, bool):
                    consts_set.add(int(member))
        elif op == "truthy":
            consts_set.add(0)
    consts = sorted(consts_set)
    if not consts:                            # cannot happen for a numeric field, kept as a guard
        consts = [0]
    # fine cells: each constant as a point + integer gaps between (drop empty gaps)
    fine: List[Tuple[Optional[int], Optional[int]]] = []
    fine.append((None, consts[0] - 1))
    for const_index, const in enumerate(consts):
        fine.append((const, const))
        nxt = consts[const_index + 1] if const_index + 1 < len(consts) else None
        lo = const + 1
        hi = (nxt - 1) if nxt is not None else None
        if hi is None or lo <= hi:
            fine.append((lo, hi))
    def rep(lo, hi):
        if lo is not None: return lo
        if hi is not None: return hi
        return 0
    def truth(value):
        return tuple(atom_true(op, const, value) for op, const in atoms)
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
    for op, const in atoms:
        if op == "truthy":
            vals = ("",)                      # str truthiness is `s != ""`: the empty string is a named constant
        else:
            vals = const if op in ("in", "not in") else (const,)
        for member in vals:
            if isinstance(member, str) and member not in consts:
                consts.append(member)
    cells = [{"const": const, "rep": const} for const in consts] + [{"const": OTHER_CELL, "rep": OTHER_CELL}]
    return FieldPartition(field, "categorical", cells)


def _classify_kind(atoms: List[Tuple[str, Any]]) -> str:
    consts = [const for op, const in atoms if op not in ("truthy",)]
    flat = []
    for op, const in atoms:
        flat += list(const) if op in ("in", "not in") else ([const] if op != "truthy" else [])
    for value in flat:
        if isinstance(value, float):
            _refuse_float(value)
    has_str = any(isinstance(value, str) for value in flat)
    has_bool = any(isinstance(value, bool) for value in flat)
    has_int = any(isinstance(value, int) and not isinstance(value, bool) for value in flat)
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
    for field, atoms in flow_atoms(graph).items():
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
    return {field: partition.symbol(reading[field]) for field, partition in parts.items() if field in reading}


def reconstruct(parts: Dict[str, FieldPartition], symbols: Dict[str, int]) -> Dict[str, Any]:
    """Symbols -> a representative reading that routes identically to the original."""
    return {field: parts[field].representative(symbol) for field, symbol in symbols.items() if field in parts}


# ----------------------------------------------------------------- compatibility aliases
# The underscore spellings these four names used to carry are kept so an out of tree caller that
# reached for the private API still resolves. New code uses the public names above.
_OTHER = OTHER_CELL
_atoms = atoms_of
_flow_atoms = flow_atoms
_atom_true = atom_true
