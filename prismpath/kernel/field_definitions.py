# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Field definitions (SPEC section 4.5): the signed meaning of every value a flow routes on.

A flow defines its fields in its front matter, one `field.<name>: <definition>` line each. This module
is the reference for everything a definition decides, and every other part of the toolchain asks it
rather than reimplementing a rule.

  * `definitions_of(meta)` parses the definitions out of the front matter.
  * `apply_definitions(graph)` runs at parse time. It lowers every decimal literal compared with a
    `fixed` field to the canonical integer, exactly, and then checks the policy rules. A flow that
    breaks a rule raises FieldDefinitionError, so no engine run, codebook, table or pack is ever built
    from it.
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
    """Every field definition in a flow's front matter, keyed by field name."""
    return {key[len(FIELD_PREFIX):]: parse_definition(key[len(FIELD_PREFIX):], value)
            for key, value in meta.items() if key.startswith(FIELD_PREFIX)}


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


def _atom_problem(definition: FieldDefinition, op: str, constant: Any) -> Optional[Problem]:
    """Why one atom breaks its field's definition, or None when it agrees."""
    kind, name = definition.kind, definition.name
    members = constant if op in ("in", "not in") else (constant,)
    if op in ("in", "not in") and any(member is None for member in members):
        return Problem(f"field {name!r}: None may not appear in a list", "policy:none", name, "in-list")
    if constant is None and op != "truthy":
        if op not in ("==", "!="):
            return Problem(f"field {name!r}: None is compared only by == or !=", "policy:none", name, "ordered")
        if not definition.absent_allowed:
            return Problem(f"field {name!r}: compared with None, but its definition refuses absence", "policy:none",
                           name, "absence-refused")
        return None
    if kind == KIND_BOOL:
        if op == "truthy" or (op in ("==", "!=") and isinstance(constant, bool)):
            return None
        return Problem(f"field {name!r}: a bool field is tested by truthiness or == and != with True or False",
                       "policy:kind-mismatch", name)
    if kind == KIND_CATEGORY:
        if op == "truthy" or (op in ("==", "!=", "in", "not in")
                              and all(isinstance(member, str) for member in members)):
            return None
        return Problem(f"field {name!r}: a category field is compared with strings by ==, !=, in and not in",
                       "policy:kind-mismatch", name)
    # int and fixed
    if op != "truthy" and not all(isinstance(member, int) and not isinstance(member, bool)
                                  for member in members):
        return Problem(f"field {name!r}: a {kind} field is compared only with numbers", "policy:kind-mismatch", name)
    if kind == KIND_FIXED and op not in _ROUNDING_OPERATORS[definition.rounding]:
        allowed = " and ".join(sorted(_ROUNDING_OPERATORS[definition.rounding]))
        written = "a bare truthiness test" if op == "truthy" else f"{op!r}"
        return Problem(f"field {name!r}: rounding={definition.rounding} carries only {allowed}, so {written} "
                       f"would not decide on the canonical value as it does on the source value", "policy:rounding", name)
    if op != "truthy":
        for member in members:
            if not definition.minimum <= member <= definition.maximum:
                return Problem(f"field {name!r}: the constant {member} is outside its range "
                               f"{definition.minimum} to {definition.maximum}", "policy:threshold", name,
                               "constant-range" if kind == KIND_INT else "out-of-range")
    return None


# The Level M classifier's reasons (level_m.py) as the core's registered refusals (spec section 2.2):
# an operator outside the fragment is image:unknown-op, a value type outside it image:unknown-type, and a
# condition that is not an atom at all (a constant, a hard keyword) is outside Level M by name.
_LEVEL_M_CAUSE = {
    "string-ordering": "image:unknown-op",
    "substring-in": "image:unknown-op",
    "field-vs-field": "image:unknown-type",
    "nested-container": "image:unknown-type",
    "non-literal-collection": "image:unknown-type",
    "constant-only": "policy:not-level-m",
    "chained-comparison": "policy:shape",
}


def _float_literals(cond: str) -> Optional[List[str]]:
    """The source text of every float literal of a deterministic condition, or None when it has no syntax
    tree."""
    from prismpath.kernel import predicates
    if not predicates.is_deterministic(cond):
        return None
    expr = predicates._expr_of(cond)
    tree = predicates.expr_ast(cond)
    if tree is None:
        return None
    return [ast.get_source_segment(expr, node) or "" for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, float)]


def _level_m_problem(name: str, cond: str, reason: Optional[str]) -> Problem:
    cause = _LEVEL_M_CAUSE.get(reason or "")
    if cause is None:
        # disallowed-or-unparseable: a float constant on a field that is not fixed is a value type outside the
        # fragment, or a threshold past the exact decimal bounds, which the core refuses whatever the field;
        # anything else (a hard keyword as a name, syntax outside the grammar) is outside it by name
        floats = _float_literals(cond) or []
        if any(decimal_fraction(text.replace("_", "")) is None for text in floats):
            return Problem(f"{name}: {cond!r} holds a decimal literal past the exact bounds", "policy:threshold", None,
                           "digits")
        cause = "image:unknown-type" if floats else "policy:not-level-m"
    return Problem(f"{name}: {cond!r} is outside Level M ({reason}), and a flow that defines its fields routes "
                   f"only on Level M conditions", cause, None, reason)


def fragment_problems(graph) -> List[Problem]:
    """The problems of the flow's conditions that no definition can change (spec section 4, step 1): an
    operator or value type outside the fragment, a name outside it, and a decimal literal past the exact
    bounds. Reported beside a malformed definition, so a refusal names every cause the core could name
    first. A decimal literal within the bounds is left to the definitions, since on a fixed field it is
    lowered to an integer."""
    from prismpath.kernel import level_m, predicates
    problems: List[Problem] = []
    for name, node in graph.nodes.items():
        for _target, cond in node.edges:
            if not predicates.is_deterministic(cond) or predicates.is_semantic(cond):
                continue
            member, reason = level_m.is_level_m(cond)
            if member:
                continue
            problem = _level_m_problem(name, cond, reason)
            if _decided_without_definitions(problem, cond, reason):
                problems.append(problem)
    return problems


def _decided_without_definitions(problem: Problem, cond: str, reason: Optional[str]) -> bool:
    """Whether a Level M problem stands before the definitions are known: not when the classifier only
    objects to the syntax of a condition that holds decimal literals within the bounds, which on a fixed
    field are lowered to integers first."""
    return reason != "disallowed-or-unparseable" or problem.cause == "policy:threshold" or not _float_literals(cond)


def policy_problems(graph, definitions: Dict[str, FieldDefinition], skip=frozenset()) -> List[Problem]:
    """Every way the flow breaks the rules of SPEC section 4.5, in node order; empty when it obeys them.
    Each problem is a Problem, a str carrying its registered cause. `skip` names (node, edge index) pairs
    whose lowering already failed, so their unlowered constants are not reported a second time."""
    from prismpath.kernel import level_m, predicates
    problems: List[Problem] = []
    tested_for_absence = set()
    for name, node in graph.nodes.items():
        for index, (_target, cond) in enumerate(node.edges):
            if not predicates.is_deterministic(cond) or predicates.is_semantic(cond):
                continue
            unlowered = (name, index) in skip
            member, reason = level_m.is_level_m(cond)
            if not member and not unlowered:
                problems.append(_level_m_problem(name, cond, reason))
                continue
            tree = predicates.expr_ast(cond)
            if tree is None:
                continue
            if unlowered:
                # lowering failed on this edge, so its fixed fields still hold decimal literals: report what
                # the failure does not decide, the fragment problems no definition changes and the atoms on
                # every field that is not fixed, and leave the fixed fields to the lowering's own problem
                if not member:
                    problem = _level_m_problem(name, cond, reason)
                    if _decided_without_definitions(problem, cond, reason):
                        problems.append(problem)
                    continue
                try:
                    atoms = _atoms(level_m._desugar_chains(tree))
                except (AttributeError, KeyError, IndexError):
                    continue
                for field_name, op, constant in atoms:
                    definition = definitions.get(field_name)
                    if field_name in ENGINE_COUNTERS or (definition is not None and definition.kind == KIND_FIXED):
                        continue
                    if definition is None:
                        problems.append(Problem(f"{name}: {cond!r} reads {field_name!r}, which the flow does not "
                                                f"define", "image:field-index-oob", field_name))
                        continue
                    problem = _atom_problem(definition, op, constant)
                    if problem is not None:
                        problems.append(Problem(f"{name}: {cond!r}: {problem}", problem.cause, problem.field,
                                                problem.reason))
                    if constant is None and op in ("==", "!="):
                        tested_for_absence.add(field_name)
                continue
            for field_name, op, constant in _atoms(level_m._desugar_chains(tree)):
                if field_name in ENGINE_COUNTERS:
                    continue
                definition = definitions.get(field_name)
                if definition is None:
                    problems.append(Problem(f"{name}: {cond!r} reads {field_name!r}, which the flow does not define",
                                            "image:field-index-oob", field_name))
                    continue
                problem = _atom_problem(definition, op, constant)
                if problem is not None:
                    problems.append(Problem(f"{name}: {cond!r}: {problem}", problem.cause, problem.field,
                                            problem.reason))
                if constant is None and op in ("==", "!="):
                    tested_for_absence.add(field_name)
    for field_name, definition in sorted(definitions.items()):
        if definition.absent_allowed and field_name not in tested_for_absence:
            problems.append(Problem(f"field {field_name!r} allows absence but no edge tests it with == None or "
                                    f"!= None, so absence would only ever be observed by accident",
                                    "policy:absence-untested", field_name))
    return problems


def apply_definitions(graph) -> None:
    """Parse the flow's field definitions, lower its conditions in place, and refuse a flow that breaks
    a rule. A flow with no definitions is left exactly as it was. The refusal names every problem, the
    lowering's and the policy rules', each with its registered cause."""
    try:
        definitions = definitions_of(graph.meta)
    except FieldDefinitionError as error:
        problems = list(error.problems) + fragment_problems(graph)
        raise FieldDefinitionError(str(error), cause=error.cause, field=error.field, reason=error.reason,
                                   problems=problems) from None
    graph.fields = definitions
    if not definitions:
        return
    problems: List[Problem] = []
    failed = set()
    for name, node in graph.nodes.items():
        lowered = []
        for index, (target, cond) in enumerate(node.edges):
            try:
                lowered.append((target, lower_condition(cond, definitions)))
            except FieldDefinitionError as error:
                problems.extend(error.problems)
                failed.add((name, index))
                lowered.append((target, cond))
        node.edges = lowered
    problems += policy_problems(graph, definitions, failed)
    if problems:
        first = problems[0]
        raise FieldDefinitionError("the flow breaks its field definitions: " + "; ".join(problems),
                                   cause=first.cause, field=first.field, reason=first.reason, problems=problems)
