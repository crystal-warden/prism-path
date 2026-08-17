# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""contract.py — derive each node's worker OUTPUT CONTRACT from the flow itself (roadmap item 1).

The deterministic edges already tell you what a node's worker must emit: `when tests_pass` implies a
boolean `tests_pass`; `when recommended_action == "contain"` implies a `recommended_action` whose value
space includes "contain". So walk the graph, read each node's out-edge predicates, and extract the
per-node output schema. This is a pure operation ON THE FLOW-AS-DATA — no engine impurity, no runtime.

One extraction, several payoffs:
  * `derive_contract(graph)` — the schema itself: {node: {field: FieldSpec}} (the interface a worker
    author reads, and the thing the flow *specifies* about the worker).
  * `to_json_schema(node_contract)` — a JSON Schema for an LLM worker's constrained decoding: the flow
    generates the worker's output grammar for free (the SOC schema-constrained pattern, generalized).
  * `validate_output(node_contract, fields)` — a runtime/offline TYPE GATE: does an actual worker
    output match the derived contract? Catches a worker emitting `tests_pass="yes"` (string) where a
    boolean is read.

Types are inferred from how each field is USED in the predicates:
  * compared with `< <= > >=` to a number            -> number
  * `== / != / in` a string literal (or list)        -> enum   (values = the routed literals)
  * `== / !=` a bool literal, OR used bare (`when f`, `not f`, `f and g`) -> boolean
  * `== / !=` a numeric literal                       -> number
Engine-provided names (`visits`, `error_count`, `error`, `error_type`, `error_message`) are NOT part of
the worker's contract and are excluded. A field used two incompatible ways is flagged as a conflict.

Scope note: an enum's value set is a LOWER bound — the values the flow *routes on*, not necessarily every
value the worker may emit (an unrouted value simply falls through). That is the useful set for routing.
"""
from __future__ import annotations

import ast
from typing import Dict, List, Optional

from prismpath import predicates

# Names supplied by the ENGINE, not the worker — excluded from the worker's output contract.
ENGINE_FIELDS = {"visits", "error_count", "error", "error_type", "error_message"}

_NUM_OPS = (ast.Lt, ast.LtE, ast.Gt, ast.GtE)
_EQ_OPS = (ast.Eq, ast.NotEq)
_MEMBER_OPS = (ast.In, ast.NotIn)


class FieldSpec:
    """The inferred type of one worker output field, accumulated across a node's edges.

    `values` holds the literals the flow routes on (native types), exposed as an enum ONLY when the
    field is never range-compared (`ranged` False) — a field used with `< <= > >=` is a genuine number
    with no closed value set."""
    def __init__(self):
        self.type: str = "unknown"        # 'boolean' | 'number' | 'enum' | 'unknown'
        self.values: set = set()          # literals the flow routes on (str for enum, num for number)
        self.ranged: bool = False         # compared with an ordering operator -> not a closed enum
        self.conflict: Optional[str] = None

    def add(self, t: str, values=None, ranged: bool = False):
        if values:
            self.values.update(values)
        if ranged:
            self.ranged = True
        if t == "unknown":
            return                        # a `== name` / mixed list gives no type signal; don't clobber
        if self.type == "unknown":
            self.type = t
        elif self.type != t and self.conflict is None:
            self.conflict = f"used as both {self.type} and {t}"

    def _routed_values(self):
        """The closed value set to expose, or None (booleans, ranged numbers, or no literals)."""
        if self.type not in ("enum", "number") or self.ranged or not self.values:
            return None
        return sorted(self.values, key=lambda v: (str(type(v)), v))

    def as_dict(self) -> dict:
        d = {"type": self.type}
        rv = self._routed_values()
        if rv is not None:
            d["values"] = rv
        if self.conflict:
            d["conflict"] = self.conflict
        return d


def _lit(node):
    """The literal value of a Constant, or None if not a plain literal."""
    return node.value if isinstance(node, ast.Constant) else _MISSING


_MISSING = object()


def _type_of_literal(v) -> Optional[str]:
    if isinstance(v, bool):        # bool BEFORE int (bool is a subclass of int)
        return "boolean"
    if isinstance(v, (int, float)):
        return "number"
    if isinstance(v, str):
        return "enum"
    return None


def _compare_fields(cmp: ast.Compare, fields: Dict[str, FieldSpec]):
    operands = [cmp.left] + list(cmp.comparators)
    for i, op in enumerate(cmp.ops):
        left, right = operands[i], operands[i + 1]
        # find the (Name, other-side) orientation
        if isinstance(left, ast.Name):
            name, other = left, right
        elif isinstance(right, ast.Name):
            name, other = right, left
        else:
            continue
        spec = fields.setdefault(name.id, FieldSpec())
        if isinstance(op, _NUM_OPS):
            spec.add("number", ranged=True)            # ordering compare -> a range, not a closed enum
        elif isinstance(op, _EQ_OPS):
            v = _lit(other)
            t = _type_of_literal(v) if v is not _MISSING else None
            # keep the literal for BOTH enum (strings) and number (numeric enums like priority == 3)
            spec.add(t or "unknown", {v} if t in ("enum", "number") else None)
        elif isinstance(op, _MEMBER_OPS) and isinstance(other, (ast.List, ast.Tuple)):
            all_const = all(isinstance(e, ast.Constant) for e in other.elts)
            vals = [e.value for e in other.elts if isinstance(e, ast.Constant)]
            types = {_type_of_literal(v) for v in vals}
            if not all_const or len(vals) == 0 or len(types) != 1:
                spec.add("unknown")                    # empty / mixed / non-literal -> no clean type
            elif types == {"enum"}:
                spec.add("enum", set(vals))
            elif types == {"number"}:
                spec.add("number", set(vals))
            elif types == {"boolean"}:
                spec.add("boolean")


def _walk(node, fields: Dict[str, FieldSpec], bool_ctx: bool):
    """Populate `fields` from one predicate AST. `bool_ctx` marks positions where a bare Name is used
    as a boolean (a BoolOp/Not operand, or the whole predicate)."""
    if isinstance(node, ast.BoolOp):
        for v in node.values:
            _walk(v, fields, True)
    elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        _walk(node.operand, fields, True)
    elif isinstance(node, ast.Compare):
        _compare_fields(node, fields)
    elif isinstance(node, ast.Name) and bool_ctx:
        fields.setdefault(node.id, FieldSpec()).add("boolean")


def derive_contract(graph) -> Dict[str, Dict[str, dict]]:
    """{node: {field: spec-dict}} — the output fields each node's worker must emit for its deterministic
    edges to route, with inferred types. Empty dict for a node whose out-edges are all semantic/error/
    event (nothing deterministic to constrain)."""
    out: Dict[str, Dict[str, dict]] = {}
    for name, node in graph.nodes.items():
        fields: Dict[str, FieldSpec] = {}
        for _target, cond in node.edges:
            if not predicates.is_deterministic(cond):
                continue
            expr = predicates._expr_of(cond)
            if expr.lower() in predicates.ALWAYS or expr.lower() in predicates.NEVER:
                continue
            try:
                tree = ast.parse(expr, mode="eval")
            except (SyntaxError, ValueError):
                continue                                  # check_predicate already reports these
            _walk(tree.body, fields, True)
        out[name] = {f: spec.as_dict() for f, spec in fields.items() if f not in ENGINE_FIELDS}
    return out


_JSON_TYPE = {"boolean": "boolean", "number": "number", "enum": "string", "unknown": "string"}


def to_json_schema(node_contract: Dict[str, dict]) -> dict:
    """A JSON Schema for the node's worker output — the constrained-decoding grammar an LLM worker can
    be forced to obey. All derived fields are `required` (the flow routes on them)."""
    props = {}
    for field, spec in node_contract.items():
        p = {"type": _JSON_TYPE.get(spec["type"], "string")}
        if spec.get("values"):                        # closed value set (string OR numeric enum)
            p["enum"] = spec["values"]
        props[field] = p
    return {"type": "object", "properties": props, "required": sorted(node_contract)}


def _py_type_ok(spec_type: str, value) -> bool:
    if value is None:
        return True   # an explicit `None` ("undecided") is treated like an unset field, not a type error
    if spec_type == "boolean":
        return isinstance(value, bool)
    if spec_type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if spec_type == "enum":
        return isinstance(value, str)
    return True   # unknown -> don't constrain


def validate_output(node_contract: Dict[str, dict], fields: dict) -> List[str]:
    """Type-gate: problems where an emitted field's value contradicts the derived contract. A MISSING
    contract field is a soft note (routing may fall through), returned with a `missing:` prefix; a
    present-but-wrong-TYPE field is a hard `type:` problem."""
    problems: List[str] = []
    for field, spec in node_contract.items():
        if field not in fields:
            problems.append(f"missing: worker did not emit {field!r} (read by a `when` edge)")
            continue
        val = fields[field]
        if not _py_type_ok(spec["type"], val):
            problems.append(
                f"type: {field!r} should be {spec['type']} but worker emitted {type(val).__name__} "
                f"({val!r})")
        elif spec.get("values"):
            routed = spec["values"]
            # enum values are strings, numeric-enum values are numbers — compare in kind
            hit = str(val) in routed if spec["type"] == "enum" else val in routed
            if not hit:
                problems.append(
                    f"note: {field!r}={val!r} is not one of the routed values {routed} "
                    f"(will fall through the deterministic tier)")
    return problems


def declared_emits(node) -> Optional[set]:
    """The field names a node DECLARES its worker emits, via `@emits(field, field2=type, …)` — or None
    if the node has no `@emits` (declarations are opt-in). This is the authoritative half that makes
    "the flow specifies the worker" literal; the provenance lint checks the derived (read) fields
    against it, and a node is `@field_only` iff it routes only on these declared fields (no raw text)."""
    anno = node.annotations.get("emits")
    return set(anno.keys()) if anno is not None else None


def describe(contract: Dict[str, Dict[str, dict]]) -> str:
    """Human-readable rendering for `prismpath contract`."""
    lines = []
    for node in sorted(contract):
        fields = contract[node]
        if not fields:
            continue
        lines.append(f"## {node}")
        for field in sorted(fields):
            spec = fields[field]
            t = spec["type"]
            if spec.get("values"):                    # enum{a, b} or number{1, 2, 3}
                t = f"{t}{{{', '.join(str(v) for v in spec['values'])}}}"
            flag = f"   ⚠ {spec['conflict']}" if spec.get("conflict") else ""
            lines.append(f"    {field}: {t}{flag}")
    return "\n".join(lines) if lines else "(no deterministic edges — nothing to constrain)"
