# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Field definitions (SPEC section 4.5): the signed meaning of every value a flow routes on.

A flow defines its fields in its front matter, one `field.<name>: <definition>` line each. This module
is the reference for everything a definition decides, and every other part of the toolchain asks it
rather than reimplementing a rule.

  * `definitions_of(meta)` parses the definitions out of the front matter.
  * `apply_definitions(graph)` runs at parse time. It checks the policy in the verified core's order
    (`core_problems`, docs/design/spec-verified-core.md section 4) and then lowers every decimal literal
    compared with a `fixed` field to the canonical integer, exactly. A flow that breaks a rule raises
    FieldDefinitionError for the first problem in that order, so no engine run, codebook, table or pack
    is ever built from it, and every implementation names the same cause.
  * `canonical_value(definition, raw)` is the one conversion from a source value to a canonical value,
    the function adapters call instead of writing their own numeric semantics.
  * `accept_canonical(definition, value)` is the boundary check on a value that should already be
    canonical. It converts nothing.

Lowering happens at parse time because the engine compares what the graph holds. A canonical reading
carries 8500 for 0.85 at scale 10000, so an edge left as `error_rate >= 0.85` would be satisfied by
almost every reading. After lowering the graph holds `error_rate >= 8500`, and every consumer of the
graph sees one representation.

Everything here is exact. Decimal text becomes a Fraction, never a float, because a binary double
cannot recover the decimal it was printed from.
"""
from __future__ import annotations

import ast
import math
import re
from dataclasses import dataclass
from fractions import Fraction
from typing import Any, Dict, List, Optional, Tuple

from prismpath.kernel import causes

FIELD_PREFIX = "field."

KIND_INT = "int"
KIND_FIXED = "fixed"
KIND_BOOL = "bool"
KIND_CATEGORY = "category"

ROUNDING_FLOOR = "floor"
ROUNDING_CEILING = "ceiling"
ROUNDING_EXACT = "exact"

# The integers every reader represents exactly, so a canonical value means the same thing in every
# implementation and on every wire. A definition's range may narrow this and may not exceed it.
EXACT_INTEGER_LIMIT = 2 ** 53 - 1
MAX_SCALE = 10 ** 9

# Decimal text the conversion accepts, and the bounds on it. The bounds keep the exact arithmetic
# inside 128 bit integers in the Rust twin, and the two must refuse the same texts.
DECIMAL_TEXT = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?")
MAX_DECIMAL_DIGITS = 28
MAX_DECIMAL_EXPONENT = 30

# The fields the engine supplies itself. They are canonical integers by construction, so a fully
# defined flow does not define them.
ENGINE_COUNTERS = frozenset({"visits", "error_count"})

_OPTIONS = {
    KIND_INT: {"min", "max", "absent"},
    KIND_FIXED: {"scale", "rounding", "unit", "min", "max", "absent"},
    KIND_BOOL: {"absent"},
    KIND_CATEGORY: {"absent"},
}

# The atoms each rounding mode carries exactly (SPEC section 4.5, rule 3 and the conversion lemma).
# Each set is closed under negation: not (x >= k) is x < k, and not (x > k) is x <= k.
_ROUNDING_OPERATORS = {
    ROUNDING_FLOOR: frozenset({">=", "<"}),
    ROUNDING_CEILING: frozenset({">", "<="}),
    ROUNDING_EXACT: frozenset({"<", "<=", ">", ">=", "==", "!=", "in", "not in", "truthy"}),
}

REFUSAL_MISSING = "missing"
REFUSAL_WRONG_TYPE = "wrong_type"
REFUSAL_UNPARSEABLE_STRING = "unparseable_string"
REFUSAL_FRACTIONAL = "fractional"
REFUSAL_OUT_OF_RANGE = "out_of_range"
REFUSAL_OFF_GRID = "off_grid"
REFUSAL_BINARY_FLOAT = "binary_float"


class FieldDefinitionError(ValueError):
    """A flow whose field definitions are malformed or whose predicates break a definition's rules.
    A ValueError, like the parser's own ParseError, so every caller that turns bad input into a client
    error already handles it.

    `cause` is the registered refusal (prismpath/kernel/causes.py) of the first problem, with `field` and
    `reason` where the refusal has them, and `problems` every problem found, each a `Problem` carrying its
    own cause. These are the refusals of the verified core (docs/design/spec-verified-core.md, section 5):
    every one is a registered row, so `code` is never None."""

    def __init__(self, message: str, cause: str = "policy:definition", field: Optional[str] = None,
                 reason: Optional[str] = None, problems: Tuple["Problem", ...] = ()):
        super().__init__(message)
        self.cause = cause
        self.field = field
        self.reason = reason
        self.problems = tuple(problems) or (Problem(message, cause, field, reason),)

    @property
    def code(self) -> Optional[int]:
        return causes.code(self.cause)


class Problem(str):
    """One way a flow breaks its field definitions: the message, as policy_problems always returned it,
    and the registered refusal it is (`cause`, with `field` and `reason` where the refusal has them)."""

    cause: str
    field: Optional[str]
    reason: Optional[str]

    def __new__(cls, text: str, cause: str, field: Optional[str] = None, reason: Optional[str] = None):
        problem = super().__new__(cls, text)
        problem.cause, problem.field, problem.reason = cause, field, reason
        return problem

    @property
    def code(self) -> Optional[int]:
        return causes.code(self.cause)


class CanonicalRefusal(ValueError):
    """A value the conversion or the canonical boundary refuses, with the field and the reason."""

    def __init__(self, field: str, reason: str, value: Any):
        super().__init__(f"{field}: {reason} ({value!r})")
        self.field = field
        self.reason = reason
        self.value = value


@dataclass(frozen=True)
class FieldDefinition:
    name: str
    kind: str
    scale: Optional[int] = None
    rounding: Optional[str] = None
    unit: Optional[str] = None
    minimum: int = -EXACT_INTEGER_LIMIT
    maximum: int = EXACT_INTEGER_LIMIT
    absent_allowed: bool = False

    def canonical_text(self) -> str:
        """The definition written one fixed way, so two spellings of the same definition compare equal
        wherever a definition is bound or checked, such as a pack manifest against an envelope."""
        words = [self.kind]
        if self.kind == KIND_FIXED:
            words += [f"scale={self.scale}", f"rounding={self.rounding}"]
            if self.unit is not None:
                words.append(f"unit={self.unit}")
        if self.kind in (KIND_INT, KIND_FIXED):
            words += [f"min={self.minimum}", f"max={self.maximum}"]
        words.append("absent=allowed" if self.absent_allowed else "absent=refused")
        return " ".join(words)


# ----------------------------------------------------------------- definitions
def _integer_option(name: str, option: str, text: str) -> int:
    if not re.fullmatch(r"[+-]?[0-9]+", text):
        raise FieldDefinitionError(f"field {name!r}: {option}={text!r} is not an integer", field=name, reason="not-integer")
    return int(text)


def parse_definition(name: str, text: str) -> FieldDefinition:
    """One `field.<name>` front matter value as a FieldDefinition, or FieldDefinitionError."""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        raise FieldDefinitionError(f"field {name!r}: not a field name", field=name, reason="name")
    if name in ENGINE_COUNTERS:
        raise FieldDefinitionError(f"field {name!r}: the engine supplies this counter, it is not defined", field=name, reason="engine-counter")
    words = text.split()
    if not words:
        raise FieldDefinitionError(f"field {name!r}: the definition is empty", field=name, reason="empty")
    kind, options = words[0], {}
    if kind not in _OPTIONS:
        raise FieldDefinitionError(f"field {name!r}: unknown kind {kind!r} (int, fixed, bool, category)", field=name, reason="unknown-kind")
    for word in words[1:]:
        option, equals, value = word.partition("=")
        if not equals or not value:
            raise FieldDefinitionError(f"field {name!r}: {word!r} is not option=value", field=name, reason="not-option")
        if option not in _OPTIONS[kind]:
            raise FieldDefinitionError(f"field {name!r}: a {kind} field takes no {option!r} option", field=name, reason="option-not-taken")
        if option in options:
            raise FieldDefinitionError(f"field {name!r}: {option!r} is given twice", field=name, reason="option-repeated")
        options[option] = value

    absent = options.get("absent", "refused")
    if absent not in ("refused", "allowed"):
        raise FieldDefinitionError(f"field {name!r}: absent={absent!r} is neither refused nor allowed", field=name, reason="absent")
    scale = rounding = unit = None
    if kind == KIND_FIXED:
        if "scale" not in options or "rounding" not in options:
            raise FieldDefinitionError(f"field {name!r}: a fixed field needs both scale and rounding", field=name, reason="fixed-needs-scale-and-rounding")
        scale = _integer_option(name, "scale", options["scale"])
        if not 1 <= scale <= MAX_SCALE:
            raise FieldDefinitionError(f"field {name!r}: scale={scale} is outside 1 to {MAX_SCALE}", field=name, reason="scale")
        rounding = options["rounding"]
        if rounding not in _ROUNDING_OPERATORS:
            raise FieldDefinitionError(f"field {name!r}: rounding={rounding!r} is not floor, ceiling or exact", field=name, reason="rounding")
        unit = options.get("unit")
    minimum, maximum = -EXACT_INTEGER_LIMIT, EXACT_INTEGER_LIMIT
    if "min" in options:
        minimum = _integer_option(name, "min", options["min"])
    if "max" in options:
        maximum = _integer_option(name, "max", options["max"])
    if not -EXACT_INTEGER_LIMIT <= minimum <= maximum <= EXACT_INTEGER_LIMIT:
        raise FieldDefinitionError(f"field {name!r}: the range {minimum} to {maximum} is empty or wider "
                                   f"than plus or minus 2^53 minus 1", field=name, reason="range")
    return FieldDefinition(name, kind, scale, rounding, unit, minimum, maximum, absent == "allowed")


def definitions_of(meta: Dict[str, str]) -> Dict[str, FieldDefinition]:
    """Every field definition in a flow's front matter, keyed by field name, parsed in code point order of
    the names (spec section 2.5), so the first malformed one is the one the core names."""
    return {key[len(FIELD_PREFIX):]: parse_definition(key[len(FIELD_PREFIX):], meta[key])
            for key in sorted(meta) if key.startswith(FIELD_PREFIX)}


# ----------------------------------------------------------------- exact decimals
def decimal_fraction(text: str) -> Optional[Fraction]:
    """The exact value of decimal text within the shared bounds, or None when it is not such text."""
    # fullmatch, not match with a trailing $, which would let a final newline through
    if not DECIMAL_TEXT.fullmatch(text):
        return None
    mantissa, _, exponent = text.lower().partition("e")
    digits = re.sub(r"[^0-9]", "", mantissa).lstrip("0")
    if len(digits) > MAX_DECIMAL_DIGITS or (exponent and abs(int(exponent)) > MAX_DECIMAL_EXPONENT):
        return None
    return Fraction(text)


def _scaled(definition: FieldDefinition, value: Fraction) -> Tuple[Optional[str], Optional[int]]:
    """(refusal reason, canonical integer) for an exact source value on a fixed field."""
    scaled = value * definition.scale
    if definition.rounding == ROUNDING_FLOOR:
        canonical = math.floor(scaled)
    elif definition.rounding == ROUNDING_CEILING:
        canonical = math.ceil(scaled)
    else:
        if scaled.denominator != 1:
            return REFUSAL_OFF_GRID, None
        canonical = scaled.numerator
    if not definition.minimum <= canonical <= definition.maximum:
        return REFUSAL_OUT_OF_RANGE, None
    return None, canonical


# ----------------------------------------------------------------- the shared conversion
def canonical_value(definition: FieldDefinition, raw: Any) -> Any:
    """The canonical value of a source value under its field's signed definition, or CanonicalRefusal.

    None is absence: it comes back as None when the field allows absence and is refused as missing
    otherwise. Numbers may arrive as an int, an exact decimal (fractions.Fraction or decimal.Decimal),
    or decimal text such as the original token of a JSON number. A float is accepted only when it is
    integral. A float with a fractional part is refused on a fixed field, because the decimal it was
    printed from cannot be recovered from it; parse the source with
    `json.loads(text, parse_float=decimal.Decimal)` instead. A boolean is never a number, and a bool or category field takes only its own
    type; mapping a source's own spellings onto them is the adapter's job."""
    field = definition.name
    if raw is None:
        if definition.absent_allowed:
            return None
        raise CanonicalRefusal(field, REFUSAL_MISSING, raw)
    if definition.kind == KIND_BOOL:
        if isinstance(raw, bool):
            return raw
        raise CanonicalRefusal(field, REFUSAL_WRONG_TYPE, raw)
    if definition.kind == KIND_CATEGORY:
        if isinstance(raw, str):
            return raw
        raise CanonicalRefusal(field, REFUSAL_WRONG_TYPE, raw)

    if isinstance(raw, bool):
        raise CanonicalRefusal(field, REFUSAL_WRONG_TYPE, raw)
    if isinstance(raw, float):
        # An integral double is exactly that integer, and some readers (the Rust twin among them) hold
        # every JSON number as a double, so it is accepted as the integer on both kinds. A double with a
        # fractional part is refused: on a fixed field because the decimal it was printed from is lost,
        # on an int field because it is a fraction.
        if not math.isfinite(raw):
            raise CanonicalRefusal(field, REFUSAL_OUT_OF_RANGE, raw)
        if not raw.is_integer():
            reason = REFUSAL_BINARY_FLOAT if definition.kind == KIND_FIXED else REFUSAL_FRACTIONAL
            raise CanonicalRefusal(field, reason, raw)
        exact = Fraction(int(raw))
    elif isinstance(raw, int):
        exact = Fraction(raw)
    elif isinstance(raw, Fraction):
        exact = raw
    elif isinstance(raw, str):
        exact = decimal_fraction(raw)
        if exact is None:
            raise CanonicalRefusal(field, REFUSAL_UNPARSEABLE_STRING, raw)
    elif type(raw).__name__ == "Decimal":
        if not raw.is_finite():
            raise CanonicalRefusal(field, REFUSAL_OUT_OF_RANGE, raw)
        exact = decimal_fraction(str(raw))
        if exact is None:
            raise CanonicalRefusal(field, REFUSAL_UNPARSEABLE_STRING, raw)
    else:
        raise CanonicalRefusal(field, REFUSAL_WRONG_TYPE, raw)

    if definition.kind == KIND_FIXED:
        reason, canonical = _scaled(definition, exact)
        if reason is not None:
            raise CanonicalRefusal(field, reason, raw)
        return canonical
    if exact.denominator != 1:
        raise CanonicalRefusal(field, REFUSAL_FRACTIONAL, raw)
    if not definition.minimum <= exact.numerator <= definition.maximum:
        raise CanonicalRefusal(field, REFUSAL_OUT_OF_RANGE, raw)
    return exact.numerator


def accept_canonical(definition: FieldDefinition, value: Any) -> Tuple[Optional[str], Any]:
    """(refusal reason, value) for a value that should already be canonical. It converts nothing: a
    string that spells a number is the wrong type here, since parsing it was the adapter's job. An
    integral float is the same integer and passes, because some readers hold every number as a double.
    None is the absent value when the field allows it and missing otherwise."""
    if value is None:
        return (None, None) if definition.absent_allowed else (REFUSAL_MISSING, None)
    if definition.kind == KIND_BOOL:
        return (None, value) if isinstance(value, bool) else (REFUSAL_WRONG_TYPE, None)
    if definition.kind == KIND_CATEGORY:
        return (None, value) if isinstance(value, str) else (REFUSAL_WRONG_TYPE, None)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return REFUSAL_WRONG_TYPE, None
    if isinstance(value, float):
        if not math.isfinite(value):
            return REFUSAL_OUT_OF_RANGE, None
        if not value.is_integer():
            return REFUSAL_FRACTIONAL, None
        value = int(value)
    if not definition.minimum <= value <= definition.maximum:
        return REFUSAL_OUT_OF_RANGE, None
    return None, value


# ----------------------------------------------------------------- the two checks of a reading
# Which fields a reading must hold canonically depends on who is checking (docs/design/spec-verified-core.md,
# section 6.1). The SYSTEM boundary validates the soundness of the system: every field the flow defines,
# in code point order, is the reading's contract, whether or not a rule reads it; this is the core's runtime
# boundary and the composition the frozen field definition vectors replay. The POLICY check validates the
# soundness of a policy: only the fields its rules route on, as SPEC section 4.5 calls a reading canonical
# and as the Facet quantizer checks the fields it partitions. The system boundary is the stricter: a reading
# it accepts passes the policy check, and the two agree on every flow that routes on every field it defines
# (proved in formal/Core/Boundary.lean).

def routed_fields(graph) -> List[str]:
    """The defined fields the flow's deterministic conditions read, in code point order. Engine counters
    and names the flow does not define are not reading fields, so they are not listed."""
    from prismpath.kernel import level_m, predicates
    defined = getattr(graph, "fields", None) or {}
    read = set()
    for node in graph.nodes.values():
        for _target, cond in node.edges:
            if not predicates.is_deterministic(cond) or predicates.is_semantic(cond):
                continue
            tree = predicates.expr_ast(cond)
            if tree is None:
                continue
            try:
                atoms = _atoms(level_m._desugar_chains(tree))
            except (AttributeError, KeyError, IndexError):
                continue
            read.update(field_name for field_name, _op, _constant in atoms if field_name in defined)
    return sorted(read)


def _first_refused(definitions: Dict[str, FieldDefinition], names, reading: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    for field_name in names:
        reason, _value = accept_canonical(definitions[field_name], reading.get(field_name))
        if reason is not None:
            return field_name, reason
    return None


def system_boundary(graph, reading: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """The first defined field, in code point order, whose value the reading does not hold canonically,
    with the reason; None when every defined field is canonical. The core's runtime boundary."""
    definitions = getattr(graph, "fields", None) or {}
    return _first_refused(definitions, sorted(definitions), reading)


def policy_check(graph, reading: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """The first ROUTED field, in code point order, whose value the reading does not hold canonically,
    with the reason; None when every field the flow routes on is canonical. The check of a policy's
    soundness (SPEC section 4.5): a defined field no rule reads is not its concern."""
    definitions = getattr(graph, "fields", None) or {}
    return _first_refused(definitions, routed_fields(graph), reading)


# ----------------------------------------------------------------- lowering
def _literal_value(expr: str, node) -> Optional[Fraction]:
    """The exact value of a numeric literal node, signed or not, read from its source text."""
    sign = 1
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        sign = -1 if isinstance(node.op, ast.USub) else 1
        inner = node.operand
        # The sign must sit directly on the literal. `-(0.5)` is a signed literal to Python's syntax tree
        # but not to the predicate tokenizer the other kernels share, and leaving `-(5)` unlowered would
        # compare -5 canonical units instead of -5.0, so a separated sign is refused outright.
        if isinstance(inner, ast.Constant) and not isinstance(inner.value, bool) \
                and isinstance(inner.value, (int, float)) \
                and ast.get_source_segment(expr, node)[1:].strip() != ast.get_source_segment(expr, inner):
            raise FieldDefinitionError(f"the threshold {ast.get_source_segment(expr, node)} puts its sign outside "
                                       f"parentheses; write the sign on the number", cause="policy:threshold",
                                       reason="sign")
        node = inner
    if not isinstance(node, ast.Constant) or isinstance(node.value, bool) \
            or not isinstance(node.value, (int, float)):
        return None
    if isinstance(node.value, int):
        return sign * Fraction(node.value)
    exact = decimal_fraction(ast.get_source_segment(expr, node).replace("_", ""))
    if exact is None:
        raise FieldDefinitionError(f"the literal {ast.get_source_segment(expr, node)!r} has more digits "
                                   f"than an exact threshold carries", cause="policy:threshold", reason="digits")
    return sign * exact


def lower_expression(expr: str, definitions: Dict[str, FieldDefinition]) -> str:
    """The expression with every numeric literal compared with a fixed field replaced by its canonical
    integer. A literal off the field's grid, or outside its range, raises FieldDefinitionError."""
    fixed = {name for name, definition in definitions.items() if definition.kind == KIND_FIXED}
    if not fixed:
        return expr
    tree = ast.parse(expr, mode="eval")
    spans: Dict[Tuple[int, int], Tuple[str, Any]] = {}

    def lower(field_name: str, node) -> None:
        exact = _literal_value(expr, node)
        if exact is None:
            return
        definition = definitions[field_name]
        scaled = exact * definition.scale
        if scaled.denominator != 1:
            raise FieldDefinitionError(f"field {field_name!r}: the threshold {ast.get_source_segment(expr, node)} "
                                       f"is not a multiple of 1/{definition.scale}", cause="policy:threshold",
                                       field=field_name, reason="off-grid")
        canonical = scaled.numerator
        if not definition.minimum <= canonical <= definition.maximum:
            raise FieldDefinitionError(f"field {field_name!r}: the threshold {ast.get_source_segment(expr, node)} "
                                       f"is {canonical} canonically, outside {definition.minimum} to "
                                       f"{definition.maximum}", cause="policy:threshold", field=field_name,
                                       reason="out-of-range")
        span = (node.col_offset, node.end_col_offset)
        if span in spans and spans[span][0] != field_name \
                and definitions[spans[span][0]].scale != definition.scale:
            raise FieldDefinitionError(f"the literal {ast.get_source_segment(expr, node)} sits between two "
                                       f"fixed fields of different scales", cause="policy:threshold",
                                       reason="two-scales")
        spans[span] = (field_name, canonical)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        operands = [node.left] + list(node.comparators)
        for index, operator_node in enumerate(node.ops):
            left, right = operands[index], operands[index + 1]
            if isinstance(operator_node, (ast.In, ast.NotIn)):
                if isinstance(left, ast.Name) and left.id in fixed and isinstance(right, (ast.List, ast.Tuple)):
                    for element in right.elts:
                        lower(left.id, element)
                continue
            if isinstance(left, ast.Name) and left.id in fixed:
                lower(left.id, right)
            if isinstance(right, ast.Name) and right.id in fixed:
                lower(right.id, left)
    if not spans:
        return expr
    # ast offsets count UTF-8 bytes, so splice the encoded text, rightmost span first.
    encoded = expr.encode("utf-8")
    for (start, end), (_field_name, canonical) in sorted(spans.items(), reverse=True):
        encoded = encoded[:start] + str(canonical).encode("utf-8") + encoded[end:]
    return encoded.decode("utf-8")


def lower_condition(cond: str, definitions: Dict[str, FieldDefinition]) -> str:
    """A `when` or `on error when` condition with its expression lowered; any other condition as is."""
    from prismpath.kernel import predicates
    if predicates.is_deterministic(cond):
        expr = predicates._expr_of(cond)
    elif predicates.is_error(cond) and predicates.error_expr(cond).lower().startswith("when "):
        expr = predicates._expr_of(predicates.error_expr(cond))
    else:
        return cond
    if expr.lower() in predicates.ALWAYS or expr.lower() in predicates.NEVER:
        return cond
    stripped = cond.rstrip()
    if not stripped.endswith(expr):
        return cond
    try:
        lowered = lower_expression(expr, definitions)
    except SyntaxError:
        return cond                     # not a valid predicate; the policy rules report it
    return stripped[:len(stripped) - len(expr)] + lowered


# ----------------------------------------------------------------- the policy rules
def _atoms(node) -> List[Tuple[str, str, Any]]:
    """(field, op, constant) atoms of a folded, desugared Level M tree, field on the left."""
    flip = {"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "!=": "!="}
    names = {ast.Lt: "<", ast.LtE: "<=", ast.Gt: ">", ast.GtE: ">=", ast.Eq: "==", ast.NotEq: "!=",
             ast.In: "in", ast.NotIn: "not in"}
    if isinstance(node, ast.BoolOp):
        return [atom for value in node.values for atom in _atoms(value)]
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _atoms(node.operand)
    if isinstance(node, ast.Name):
        return [(node.id, "truthy", None)]
    if isinstance(node, ast.Compare):
        left, right, op = node.left, node.comparators[0], names[type(node.ops[0])]
        if op in ("in", "not in"):
            return [(left.id, op, tuple(element.value for element in right.elts))]
        if isinstance(left, ast.Name):
            return [(left.id, op, right.value)]
        return [(right.id, flip[op], left.value)]
    return []


# ----------------------------------------------------------------- the checks of a policy, in the core's order
# docs/design/spec-verified-core.md, section 4, and the Lean semantics it defines (formal/Core/Policy.lean,
# `loadPolicy`): a policy with several problems is refused for the FIRST, in one order, so every
# implementation names the same cause (D7). The order has four phases:
#
#   1. decoding: rule by rule, each condition depth first and left to right, each atom its field name, then
#      its operator, then its constant; a rule's depth after its whole condition decoded;
#   2. the definitions, in code point order of their names;
#   3. lowering: rule by rule, atom by atom, each atom against its field's definition;
#   4. rule 6, the fields that allow absence, in code point order.
#
# Every problem is collected, in that order, so a refusal still names all of them for diagnostics
# (`FieldDefinitionError.problems`); the first is the cause.

_CORE_CMP = {ast.Lt: "<", ast.LtE: "<=", ast.Gt: ">", ast.GtE: ">=", ast.Eq: "==", ast.NotEq: "!="}
_FLIP = {"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "!=": "!="}
_ORDERING = frozenset({"<", "<=", ">", ">="})
# the syntax the predicate language has (predicates._ALLOWED_NODES) and the sign written on a number
_CORE_SYNTAX = (ast.Expression, ast.Constant, ast.Name, ast.Load, ast.BoolOp, ast.And, ast.Or, ast.UnaryOp, ast.Not,
                ast.USub, ast.UAdd, ast.Compare, ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In,
                ast.NotIn, ast.List, ast.Tuple)


class _Refused(Exception):
    def __init__(self, problem: Problem):
        super().__init__(str(problem))
        self.problem = problem


def _outside(where: str, cond: str, cause: str, reason: str) -> _Refused:
    return _Refused(Problem(f"{where}: {cond!r} is outside Level M ({reason}), and a flow that defines its fields "
                            f"routes only on Level M conditions", cause, None, reason))


def _signed_number(node):
    """(sign, Constant) for a numeric literal with at most one sign written on it, or None."""
    sign = 1
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        sign = -1 if isinstance(node.op, ast.USub) else 1
        node = node.operand
    if isinstance(node, ast.Constant) and not isinstance(node.value, bool) and isinstance(node.value, (int, float)):
        return sign, node
    return None


def _decode_const(expr: str, node, where: str, cond: str):
    """One constant of the core (spec section 2.3): ('int', n), ('dec', text, exact), ('bool', b), ('str', s)
    or ('none',), or the decoding refusal (Lean `decodeConst`)."""
    number = _signed_number(node)
    if number is not None:
        sign, constant = number
        if isinstance(constant.value, int):
            return ("int", sign * constant.value)
        text = (ast.get_source_segment(expr, constant) or "").replace("_", "")
        exact = decimal_fraction(text)
        if exact is None:
            raise _Refused(Problem(f"{where}: {cond!r}: the literal {text!r} has more digits than an exact threshold "
                                   f"carries", "policy:threshold", None, "digits"))
        return ("dec", text, sign * exact)
    if isinstance(node, ast.Constant):
        if node.value is None:
            return ("none",)
        if isinstance(node.value, bool):
            return ("bool", node.value)
        if isinstance(node.value, str):
            return ("str", node.value)
        raise _outside(where, cond, "image:unknown-type", "constant")
    if isinstance(node, ast.Name):
        raise _outside(where, cond, "image:unknown-type", "field-vs-field")
    if isinstance(node, (ast.List, ast.Tuple)):
        raise _outside(where, cond, "image:unknown-type", "nested-container")
    raise _outside(where, cond, "image:unknown-type", "constant")


def _decode_cond(expr: str, node, where: str, cond: str):
    """A desugared condition as the core's abstract syntax (spec section 2.2), or the first decoding refusal
    met depth first and left to right (Lean `decodeCond`)."""
    if isinstance(node, ast.BoolOp):
        tag = "and" if isinstance(node.op, ast.And) else "or"
        return (tag, [_decode_cond(expr, value, where, cond) for value in node.values])
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return ("not", _decode_cond(expr, node.operand, where, cond))
    if isinstance(node, ast.Name):
        return ("truthy", node.id)
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        left, op, right = node.left, node.ops[0], node.comparators[0]
        if isinstance(op, (ast.In, ast.NotIn)):
            if not isinstance(left, ast.Name):
                raise _outside(where, cond, "policy:not-level-m", "name")
            tag = "in" if isinstance(op, ast.In) else "not in"
            if isinstance(right, (ast.List, ast.Tuple)):
                return (tag, left.id, [_decode_const(expr, element, where, cond) for element in right.elts])
            raise _outside(where, cond, "image:unknown-op", "membership-not-in-a-list")
        name = _CORE_CMP.get(type(op))
        if name is None:
            raise _outside(where, cond, "policy:not-level-m", "disallowed-or-unparseable")
        if isinstance(left, ast.Name):
            field_name, constant_node = left.id, right
        elif isinstance(right, ast.Name):
            field_name, constant_node, name = right.id, left, _FLIP[name]
        else:
            raise _outside(where, cond, "policy:not-level-m", "name")
        constant = _decode_const(expr, constant_node, where, cond)
        if name in _ORDERING and constant[0] == "str":
            raise _outside(where, cond, "image:unknown-op", "string-ordering")
        return ("cmp", field_name, name, constant)
    if isinstance(node, ast.Constant):
        raise _outside(where, cond, "policy:not-level-m", "name")
    raise _outside(where, cond, "policy:not-level-m", "disallowed-or-unparseable")


def _core_depth(tree) -> int:
    """The core's depth of a decoded condition (spec section 2.4, Lean `Cond.depth`)."""
    tag = tree[0]
    if tag in ("always", "never"):
        return 0
    if tag == "truthy":
        return 1
    if tag in ("cmp", "in", "not in"):
        return 2
    if tag == "not":
        return 1 + _core_depth(tree[1])
    return 1 + max(_core_depth(operand) for operand in tree[1])


def decode_condition(cond: str, where: str = "core"):
    """The core's abstract syntax of one deterministic condition (spec section 2.2), after the one
    desugaring of chains, or the Problem that refuses it at decoding: phase 1 of section 4."""
    from prismpath.kernel import level_m, predicates
    expr = predicates._expr_of(cond)
    if expr.lower() in predicates.ALWAYS:
        return ("always",)
    if expr.lower() in predicates.NEVER:
        return ("never",)
    try:
        tree = ast.parse(expr, mode="eval")
    except (SyntaxError, ValueError):
        return Problem(f"{where}: {cond!r} does not parse, and a flow that defines its fields routes only on "
                       f"Level M conditions", "policy:not-level-m", None, "disallowed-or-unparseable")
    for node in ast.walk(tree):
        bad_sign = isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)) \
            and _signed_number(node) is None
        bad_constant = isinstance(node, ast.Constant) and isinstance(node.value, (bytes, complex))
        if not isinstance(node, _CORE_SYNTAX) or bad_sign or bad_constant:
            return Problem(f"{where}: {cond!r} uses syntax outside the predicate language ({type(node).__name__})",
                           "policy:not-level-m", None, "disallowed-or-unparseable")
    try:
        decoded = _decode_cond(expr, level_m._desugar_chains(tree.body), where, cond)
    except _Refused as refused:
        return refused.problem
    if _core_depth(decoded) > predicates._MAX_DEPTH:
        # SPEC section 4.1: a predicate nested beyond the bound is invalid. The Level M classifier has no depth
        # bound, so until November 2026 a defined flow deeper than 50 loaded, and from depth 52 the evaluator's
        # run time bound raised on every reading and the edge silently never matched (D1)
        return Problem(f"{where}: {cond!r} is nested too deeply (> {predicates._MAX_DEPTH})", "policy:not-level-m",
                       None, "depth")
    return decoded


def _carries(rounding: str, op: Optional[str]) -> bool:
    """Whether a rounding mode carries an operator (rule 4); None stands for truthiness and membership."""
    return op in _ROUNDING_OPERATORS[rounding] if op is not None else rounding == ROUNDING_EXACT


def _threshold(definition: FieldDefinition, text: str, reason: str) -> Problem:
    return Problem(f"field {definition.name!r}: the threshold {text} is {reason.replace('-', ' ')} for "
                   f"{definition.canonical_text()!r}", "policy:threshold", definition.name, reason)


def _lower_number(definition: FieldDefinition, constant) -> Optional[Problem]:
    """A numeric constant of an int or fixed field against the field (Lean `lowerNum`)."""
    name, tag = definition.name, constant[0]
    if tag == "int":
        value = constant[1] * definition.scale if definition.kind == KIND_FIXED else constant[1]
        if not definition.minimum <= value <= definition.maximum:
            return _threshold(definition, str(constant[1]), "out-of-range" if definition.kind == KIND_FIXED
                              else "constant-range")
        return None
    if tag == "dec":
        if definition.kind != KIND_FIXED:
            return Problem(f"field {name!r}: the decimal {constant[1]} is a float, and a {definition.kind} field "
                           f"compares integers", "image:unknown-type", None, "float")
        scaled = constant[2] * definition.scale
        if scaled.denominator != 1:
            return _threshold(definition, constant[1], "off-grid")
        if not definition.minimum <= scaled.numerator <= definition.maximum:
            return _threshold(definition, constant[1], "out-of-range")
        return None
    return Problem(f"field {name!r}: a {definition.kind} field is compared only with numbers", "policy:kind-mismatch",
                   name)


def _rounding(definition: FieldDefinition, op: Optional[str]) -> Problem:
    allowed = " and ".join(sorted(_ROUNDING_OPERATORS[definition.rounding]))
    written = "a bare truthiness test or a membership" if op is None else f"{op!r}"
    return Problem(f"field {definition.name!r}: rounding={definition.rounding} carries only {allowed}, so {written} "
                   f"would not decide on the canonical value as it does on the source value", "policy:rounding",
                   definition.name)


def _atom_problem(definition: FieldDefinition, atom) -> Optional[Problem]:
    """Why one decoded atom breaks its field's definition, or None (Lean `checkTruthy`, `checkCmp`,
    `checkMem`, in their order)."""
    kind, name, fixed = definition.kind, definition.name, definition.kind == KIND_FIXED
    tag = atom[0]
    if tag == "truthy":
        return _rounding(definition, None) if fixed and not _carries(definition.rounding, None) else None
    if tag == "cmp":
        op, constant = atom[2], atom[3]
        if constant[0] == "none":
            if op not in ("==", "!="):
                return Problem(f"field {name!r}: None is compared only by == or !=", "policy:none", name, "ordered")
            if not definition.absent_allowed:
                return Problem(f"field {name!r}: compared with None, but its definition refuses absence", "policy:none",
                               name, "absence-refused")
            return None
        if kind in (KIND_BOOL, KIND_CATEGORY):
            own = "bool" if kind == KIND_BOOL else "str"
            if constant[0] == own and op in ("==", "!="):
                return None
            if constant[0] == "dec":
                return Problem(f"field {name!r}: the decimal {constant[1]} is a float, and a {kind} field takes none",
                               "image:unknown-type", None, "float")
            return Problem(f"field {name!r}: a bool field is tested by truthiness or == and != with True or False"
                           if kind == KIND_BOOL else
                           f"field {name!r}: a category field is compared with strings by ==, !=, in and not in",
                           "policy:kind-mismatch", name)
        is_number = constant[0] in ("int", "dec")
        if fixed and not _carries(definition.rounding, op) and is_number:
            return _rounding(definition, op)
        problem = _lower_number(definition, constant)
        if problem is not None:
            return problem
        return _rounding(definition, op) if fixed and not _carries(definition.rounding, op) else None
    members = atom[2]
    if any(member[0] == "none" for member in members):
        return Problem(f"field {name!r}: None may not appear in a list", "policy:none", name, "in-list")
    for member in members:
        if kind == KIND_CATEGORY and member[0] == "str":
            continue
        if kind in (KIND_INT, KIND_FIXED):
            problem = _lower_number(definition, member)
            if problem is not None:
                return problem
            continue
        if member[0] == "dec":
            return Problem(f"field {name!r}: the decimal {member[1]} is a float, and a {kind} field takes none",
                           "image:unknown-type", None, "float")
        return Problem(f"field {name!r}: a {kind} field is compared with {'strings' if kind == KIND_CATEGORY else 'True or False'} only",
                       "policy:kind-mismatch", name)
    return _rounding(definition, None) if fixed and not _carries(definition.rounding, None) else None


def _core_atoms(tree):
    """The atoms of a decoded condition, depth first and left to right."""
    tag = tree[0]
    if tag in ("always", "never"):
        return []
    if tag == "not":
        return _core_atoms(tree[1])
    if tag in ("and", "or"):
        return [atom for operand in tree[1] for atom in _core_atoms(operand)]
    return [tree]


def _rules(graph):
    """(where, condition) of every deterministic condition of the flow, in node order and edge order: the
    rules of the core."""
    from prismpath.kernel import predicates
    for name, node in graph.nodes.items():
        for _target, cond in node.edges:
            if predicates.is_deterministic(cond) and not predicates.is_semantic(cond):
                yield name, cond


def core_problems(graph) -> List[Problem]:
    """Every problem of a flow that defines its fields, in the order of spec section 4: the first is the one
    the core refuses the policy for, the rest are diagnostics. Empty when the policy is checked."""
    texts = {key[len(FIELD_PREFIX):]: value for key, value in graph.meta.items() if key.startswith(FIELD_PREFIX)}
    problems: List[Problem] = []
    # phase 1: decoding, rule by rule
    decoded = []
    for where, cond in _rules(graph):
        tree = decode_condition(cond, where)
        if isinstance(tree, Problem):
            problems.append(tree)
        else:
            decoded.append((where, cond, tree))
    # phase 2: the definitions, in code point order of the names
    definitions: Dict[str, FieldDefinition] = {}
    for name in sorted(texts):
        try:
            definitions[name] = parse_definition(name, texts[name])
        except FieldDefinitionError as error:
            problems.extend(error.problems)
    # phase 3: lowering, rule by rule and atom by atom
    tested_for_absence = set()
    for where, cond, tree in decoded:
        for atom in _core_atoms(tree):
            field_name = atom[1]
            if field_name in ENGINE_COUNTERS:
                # the engine's registers: outside the core (spec section 1), routed by the flow engine
                continue
            definition = definitions.get(field_name)
            if definition is None:
                if field_name not in texts:
                    problems.append(Problem(f"{where}: {cond!r} reads {field_name!r}, which the flow does not define",
                                            "image:field-index-oob", field_name))
                continue
            problem = _atom_problem(definition, atom)
            if problem is not None:
                problems.append(Problem(f"{where}: {cond!r}: {problem}", problem.cause, problem.field, problem.reason))
            elif atom[0] == "cmp" and atom[3][0] == "none":
                tested_for_absence.add(field_name)
    # phase 4: rule 6, in code point order
    for field_name in sorted(definitions):
        if definitions[field_name].absent_allowed and field_name not in tested_for_absence:
            problems.append(Problem(f"field {field_name!r} allows absence but no edge tests it with == None or "
                                    f"!= None, so absence would only ever be observed by accident",
                                    "policy:absence-untested", field_name))
    return problems


def policy_problems(graph) -> List[Problem]:
    """Every way the flow breaks the rules of SPEC section 4.5, in the core's order; empty when it obeys
    them. Each problem is a Problem, a str carrying its registered cause."""
    return core_problems(graph)


def apply_definitions(graph) -> None:
    """Parse the flow's field definitions, check the policy in the core's order (spec section 4), lower its
    conditions in place, and refuse a flow that breaks a rule. A flow with no definitions is left exactly as
    it was. The refusal's cause is the first problem in that order; `problems` names every one, each with
    its registered cause."""
    if not any(key.startswith(FIELD_PREFIX) for key in graph.meta):
        graph.fields = {}
        return
    problems = core_problems(graph)
    if not problems:
        definitions = definitions_of(graph.meta)
        graph.fields = definitions
        for name, node in graph.nodes.items():
            lowered = []
            for target, cond in node.edges:
                try:
                    lowered.append((target, lower_condition(cond, definitions)))
                except FieldDefinitionError as error:
                    # outside the core's syntax: a sign written outside parentheses, a literal between two scales
                    problems.extend(Problem(f"{name}: {cond!r}: {problem}", problem.cause, problem.field,
                                            problem.reason) for problem in error.problems)
                    lowered.append((target, cond))
            node.edges = lowered
    if problems:
        first = problems[0]
        message = str(first) if first.cause == "policy:definition" else \
            "the flow breaks its field definitions: " + "; ".join(problems)
        raise FieldDefinitionError(message, cause=first.cause, field=first.field, reason=first.reason,
                                   problems=problems)
