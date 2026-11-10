# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The oracle's check of a policy image, ported line for line from the Lean semantics (`loadPolicy`,
formal/Core/Policy.lean), so that a producer of evidence can decide what the oracle decides about an image
without running the oracle (docs/design/spec-verified-core.md, section 11).

`load_policy(image)` returns `None` when the oracle accepts the image, or the refusal as the oracle spells it
(`spellPolicy`, formal/Core/Main.lean): `(cause, code, field, reason)`, with `field` and `reason` None where
the refusal has none. `refuses_for_counter(image)` is Lean's `counterRefusal`: the oracle refuses the image
because a condition reads an engine counter (`policy:engine-counter`), which is the one refusal that marks a
case outside the core (section 1).

Every function names the Lean definition it ports; the order of the checks is Lean's, which is the order of
section 4. The document is read with the canon/2 reader (`prismpath.kernel.canon2`), which the frozen
vectors and the differential hold to Lean's `readBytes`. The port is held to the oracle on every case of a
differential run (`core_evidence.py scope-check`, and `prismpath/tests/test_core_evidence.py`).
"""
from __future__ import annotations

from typing import List, Optional, Tuple

EXACT_LIMIT = 2 ** 53 - 1
FORMAT_TAG = "prismpath.core/1"
MAX_COND_DEPTH = 50
MAX_SCALE = 10 ** 9
ENGINE_COUNTERS = ("visits", "error_count")
HARD_KEYWORDS = ("False", "None", "True", "and", "as", "assert", "async", "await", "break", "class", "continue",
                 "def", "del", "elif", "else", "except", "finally", "for", "from", "global", "if", "import", "in",
                 "is", "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try", "while", "with", "yield")
ORDER_OPS = ("<", "<=", ">", ">=")
OPS = ("<", "<=", ">", ">=", "==", "!=")

# PolicyErr.code and PolicyErr.cause (formal/Core/Eval.lean)
CODES = {"policy:unreadable": 89, "policy:shape": 90, "image:unknown-op": 74, "image:unknown-type": 75,
         "policy:not-level-m": 91, "policy:definition": 92, "image:field-index-oob": 76,
         "policy:engine-counter": 93, "policy:kind-mismatch": 94, "policy:rounding": 95, "policy:threshold": 96,
         "policy:none": 97, "policy:absence-untested": 98}


class Refused(Exception):
    """One `PolicyErr`, spelled as `spellPolicy` spells it."""

    def __init__(self, cause: str, field: Optional[str] = None, reason: Optional[str] = None):
        super().__init__(cause)
        self.cause, self.field, self.reason = cause, field, reason

    def spelled(self) -> Tuple[str, int, Optional[str], Optional[str]]:
        return (self.cause, CODES[self.cause], self.field, self.reason)


def _shape(what):
    return Refused("policy:shape", None, what)


def _is_int(value) -> bool:
    return type(value) is int


def _is_str(value) -> bool:
    return type(value) is str


def _is_digit(char: str) -> bool:
    """`isDigit`: ASCII digits only."""
    return "0" <= char <= "9"


def _is_alpha(char: str) -> bool:
    return "a" <= char <= "z" or "A" <= char <= "Z"


def is_ident(text: str) -> bool:
    """`isIdent`: `[A-Za-z_][A-Za-z0-9_]*`."""
    return bool(text) and (_is_alpha(text[0]) or text[0] == "_") and all(
        _is_alpha(char) or _is_digit(char) or char == "_" for char in text[1:])


def is_target(text: str) -> bool:
    """`isTarget`: `[A-Za-z0-9_-]+`."""
    return bool(text) and all(_is_alpha(char) or _is_digit(char) or char in "_-" for char in text)


# Past this many significant digits a value is only ever compared with bounds far smaller (plus or minus
# 2^53 times at most 10^9, or an exponent bound of 30), so it is held as a value of the same sign past them;
# this keeps Python's limit on converting very long digit strings out of the way without changing any
# comparison the checks make.
_WIDE = 40


def _digits_value(digits: str) -> int:
    """`digitsValue` for every comparison the checks make: exact up to `_WIDE` significant digits."""
    body = digits.lstrip("0")
    return int(body or "0") if len(body) <= _WIDE else 10 ** _WIDE


def _span_digits(chars: str) -> Tuple[str, str]:
    at = 0
    while at < len(chars) and _is_digit(chars[at]):
        at += 1
    return chars[:at], chars[at:]


# ----------------------------------------------------------------- exact decimal text
def parse_decimal(text: str):
    """`parseDecimal`: (neg, digits, frac_len, exp_written, sig), or None."""
    rest = text
    neg = False
    if rest[:1] == "-":
        neg, rest = True, rest[1:]
    elif rest[:1] == "+":
        rest = rest[1:]
    int_part, rest = _span_digits(rest)
    frac_part = ""
    if rest[:1] == ".":
        frac_part, rest = _span_digits(rest[1:])
    if not int_part and not frac_part:
        return None
    exponent = 0
    if rest[:1] in ("e", "E"):
        rest = rest[1:]
        eneg = False
        if rest[:1] == "-":
            eneg, rest = True, rest[1:]
        elif rest[:1] == "+":
            rest = rest[1:]
        exp_digits, rest = _span_digits(rest)
        if not exp_digits:
            return None
        exponent = -_digits_value(exp_digits) if eneg else _digits_value(exp_digits)
    if rest:
        return None
    every = int_part + frac_part
    # the digits' value is read only when the literal is in bounds, at most 28 significant digits
    return (neg, _digits_value(every), len(frac_part), exponent, len(every.lstrip("0")))


def dec_in_bounds(dec) -> bool:
    """`decInBounds`."""
    return dec[4] <= 28 and abs(dec[3]) <= 30


def dec_scaled(dec, scale: int) -> Optional[int]:
    """`Dec.scaled`: the decimal times the scale as an integer, or None off the grid."""
    neg, digits, frac_len, exponent, _sig = dec
    m = digits * scale
    t = exponent - frac_len
    if t >= 0:
        value = m * 10 ** t
    elif m % 10 ** (-t) == 0:
        value = m // 10 ** (-t)
    else:
        return None
    return -value if neg else value


def is_canonical_int_text(text: str) -> bool:
    """`isCanonicalIntText`: `0` or `-?[1-9][0-9]*`."""
    if text == "0":
        return True
    body = text[1:] if text[:1] == "-" else text
    return bool(body) and body[0] != "0" and all(_is_digit(char) for char in body)


# ----------------------------------------------------------------- decoding an image
def decode_const(j):
    """`decodeConst`: ('int', n), ('dec', dec), ('bool', b), ('str', s), ('none',)."""
    if isinstance(j, list):
        if len(j) == 2 and j[0] == "num" and _is_int(j[1]):
            return ("int", j[1])
        if len(j) == 2 and j[0] == "num" and _is_str(j[1]):
            text = j[1]
            if is_canonical_int_text(text):
                n = -_digits_value(text[1:]) if text[:1] == "-" else _digits_value(text)
                if n > EXACT_LIMIT or n < -EXACT_LIMIT:
                    return ("int", n)
                raise _shape("integer-as-string")
            dec = parse_decimal(text)
            if dec is not None:
                if any(char in ".eE" for char in text):
                    if dec_in_bounds(dec):
                        return ("dec", dec)
                    raise Refused("policy:threshold", "", "digits")
                raise _shape("number-spelling")
            raise _shape("number-text")
        if len(j) == 2 and j[0] == "bool" and type(j[1]) is bool:
            return ("bool", j[1])
        if len(j) == 2 and j[0] == "str" and _is_str(j[1]):
            return ("str", j[1])
        if len(j) == 1 and j[0] == "none":
            return ("none",)
        if len(j) == 2 and j[0] == "field" and _is_str(j[1]):
            raise Refused("image:unknown-type", None, "field-vs-field")
        if len(j) >= 1 and j[0] == "list":
            raise Refused("image:unknown-type", None, "nested-container")
    raise Refused("image:unknown-type", None, "constant")


def check_name(name: str) -> None:
    """`checkName`."""
    if not is_ident(name) or name in HARD_KEYWORDS:
        raise Refused("policy:not-level-m", None, "name")


def decode_cond(j):
    """`decodeCond`, arm by arm in Lean's order."""
    if isinstance(j, list) and j and _is_str(j[0]):
        tag, n = j[0], len(j)
        if n == 1 and tag == "always":
            return ("always",)
        if n == 1 and tag == "never":
            return ("never",)
        if n == 2 and tag == "truthy" and _is_str(j[1]):
            check_name(j[1])
            return ("truthy", j[1])
        if n == 4 and tag == "cmp" and _is_str(j[1]) and _is_str(j[2]):
            check_name(j[1])
            if j[2] not in OPS:
                raise Refused("image:unknown-op", None, "operator")
            const = decode_const(j[3])
            if j[2] in ORDER_OPS and const[0] == "str":
                raise Refused("image:unknown-op", None, "string-ordering")
            return ("cmp", j[1], j[2], const)
        if n == 3 and tag in ("in", "not in") and _is_str(j[1]):
            if isinstance(j[2], list):
                check_name(j[1])
                return ("in" if tag == "in" else "nin", j[1], [decode_const(k) for k in j[2]])
            raise Refused("image:unknown-op", None, "membership-not-in-a-list")
        if n == 2 and tag == "not":
            return ("not", decode_cond(j[1]))
        if n >= 3 and tag in ("and", "or"):
            return (tag, [decode_cond(operand) for operand in j[1:]])
    raise _shape("condition")


def cond_depth(cond) -> int:
    """`Cond.depth`."""
    tag = cond[0]
    if tag in ("always", "never"):
        return 0
    if tag == "truthy":
        return 1
    if tag in ("cmp", "in", "nin"):
        return 2
    if tag == "not":
        return cond_depth(cond[1]) + 1
    return max(cond_depth(operand) for operand in cond[1]) + 1


def decode_rule(j):
    """`decodeRule`."""
    if not isinstance(j, dict):
        raise _shape("rule")
    if not all(key in ("target", "when") for key in j):
        raise _shape("rule-key")
    if not _is_str(j.get("target")) or "when" not in j:
        raise _shape("rule")
    if not is_target(j["target"]):
        raise _shape("target")
    cond = decode_cond(j["when"])
    if cond_depth(cond) > MAX_COND_DEPTH:
        raise Refused("policy:not-level-m", None, "depth")
    return (j["target"], cond)


def decode_image(j):
    """`decodeImage`: (fields as (name, text) in document order, rules)."""
    if not isinstance(j, dict):
        raise _shape("image")
    if not all(key in ("format", "fields", "rules") for key in j):
        raise _shape("image-key")
    tag, fields, rules = j.get("format"), j.get("fields"), j.get("rules")
    if not (_is_str(tag) and isinstance(fields, dict) and isinstance(rules, list)):
        raise _shape("image")
    if tag != FORMAT_TAG:
        raise _shape("format")
    if not all(_is_str(text) for text in fields.values()):
        raise _shape("definition-not-text")
    return list(fields.items()), [decode_rule(rule) for rule in rules]


# ----------------------------------------------------------------- field definitions
def is_py_ws(char: str) -> bool:
    """`isPyWs`: Python's `str.isspace`."""
    n = ord(char)
    return (0x09 <= n <= 0x0D or 0x1C <= n <= 0x20 or n in (0x85, 0xA0, 0x1680) or 0x2000 <= n <= 0x200A
            or n in (0x2028, 0x2029, 0x202F, 0x205F, 0x3000))


def split_words(text: str) -> List[str]:
    """`splitWords`."""
    words, current = [], []
    for char in text:
        if is_py_ws(char):
            if current:
                words.append("".join(current))
                current = []
        else:
            current.append(char)
    if current:
        words.append("".join(current))
    return words


OPTIONS = {"int": ("min", "max", "absent"), "fixed": ("scale", "rounding", "unit", "min", "max", "absent"),
           "bool": ("absent",), "category": ("absent",)}


def int_option(text: str) -> Optional[int]:
    """`intOption`: `[+-]?[0-9]+`."""
    body = text[1:] if text[:1] in ("-", "+") else text
    if not body or not all(_is_digit(char) for char in body):
        return None
    return -_digits_value(body) if text[:1] == "-" else _digits_value(body)


def parse_def(name: str, text: str) -> dict:
    """`parseDef`."""
    def bad(reason):
        return Refused("policy:definition", name, reason)
    if not is_ident(name):
        raise bad("name")
    if name in ENGINE_COUNTERS:
        raise bad("engine-counter")
    words = split_words(text)
    if not words:
        raise bad("empty")
    kind = words[0]
    if kind not in OPTIONS:
        raise bad("unknown-kind")
    options = {}
    for word in words[1:]:
        at = word.find("=")
        if at < 0 or not word[at + 1:]:
            raise bad("not-option")
        option, value = word[:at], word[at + 1:]
        if option not in OPTIONS[kind]:
            raise bad("option-not-taken")
        if option in options:
            raise bad("option-repeated")
        options[option] = value
    absent = options.get("absent", "refused")
    if absent not in ("refused", "allowed"):
        raise bad("absent")
    scale, rounding = 1, "exact"
    if kind == "fixed":
        if "scale" not in options or "rounding" not in options:
            raise bad("fixed-needs-scale-and-rounding")
        parsed = int_option(options["scale"])
        if parsed is None:
            raise bad("not-integer")
        if parsed < 1 or parsed > MAX_SCALE:
            raise bad("scale")
        if options["rounding"] not in ("floor", "ceiling", "exact"):
            raise bad("rounding")
        scale, rounding = parsed, options["rounding"]
    lo, hi = -EXACT_LIMIT, EXACT_LIMIT
    if "min" in options:
        lo = int_option(options["min"])
        if lo is None:
            raise bad("not-integer")
    if "max" in options:
        hi = int_option(options["max"])
        if hi is None:
            raise bad("not-integer")
    if not -EXACT_LIMIT <= lo <= hi <= EXACT_LIMIT:
        raise bad("range")
    return {"name": name, "kind": kind, "scale": scale, "rounding": rounding, "lo": lo, "hi": hi,
            "absent_ok": absent == "allowed"}


def parse_defs(fields) -> List[dict]:
    """`parseDefs`: in code point order of the names (`sortByName`), the first failure refusing."""
    return [parse_def(name, text) for name, text in sorted(fields, key=lambda item: item[0])]


# ----------------------------------------------------------------- lowering and the policy rules
def carries(rounding: str, op: Optional[str]) -> bool:
    """`carries`; None stands for truthiness and membership."""
    if rounding == "exact":
        return True
    if rounding == "floor":
        return op in (">=", "<")
    if rounding == "ceiling":
        return op in (">", "<=")
    return False


def lower_num(d: dict, const):
    """`lowerNum`."""
    fixed = d["kind"] == "fixed"
    if const[0] == "int":
        value = const[1] * d["scale"] if fixed else const[1]
        if value < d["lo"] or value > d["hi"]:
            raise Refused("policy:threshold", d["name"], "out-of-range" if fixed else "constant-range")
        return ("int", value)
    if const[0] == "dec":
        if not fixed:
            raise Refused("image:unknown-type", None, "float")
        value = dec_scaled(const[1], d["scale"])
        if value is None:
            raise Refused("policy:threshold", d["name"], "off-grid")
        if value < d["lo"] or value > d["hi"]:
            raise Refused("policy:threshold", d["name"], "out-of-range")
        return ("int", value)
    raise Refused("policy:kind-mismatch", d["name"])


def check_truthy(d: dict) -> None:
    """`checkTruthy`."""
    if d["kind"] == "fixed" and not carries(d["rounding"], None):
        raise Refused("policy:rounding", d["name"])


def check_cmp(d: dict, op: str, const):
    """`checkCmp`."""
    if const[0] == "none":
        if op not in ("==", "!="):
            raise Refused("policy:none", d["name"], "ordered")
        if not d["absent_ok"]:
            raise Refused("policy:none", d["name"], "absence-refused")
        return ("none",)
    kind = d["kind"]
    if kind in ("bool", "category"):
        own = "bool" if kind == "bool" else "str"
        if const[0] == own:
            if op in ("==", "!="):
                return const
            raise Refused("policy:kind-mismatch", d["name"])
        if const[0] == "dec":
            raise Refused("image:unknown-type", None, "float")
        raise Refused("policy:kind-mismatch", d["name"])
    fixed = kind == "fixed"
    if fixed and not carries(d["rounding"], op) and const[0] in ("int", "dec"):
        raise Refused("policy:rounding", d["name"])
    lowered = lower_num(d, const)
    if fixed and not carries(d["rounding"], op):
        raise Refused("policy:rounding", d["name"])
    return lowered


def lower_members(d: dict, consts) -> list:
    """`lowerMembers`."""
    out = []
    for const in consts:
        if const[0] == "none":
            raise Refused("policy:none", d["name"], "in-list")
        if d["kind"] == "category" and const[0] == "str":
            out.append(const)
        elif d["kind"] in ("int", "fixed"):
            out.append(lower_num(d, const))
        elif const[0] == "dec":
            raise Refused("image:unknown-type", None, "float")
        else:
            raise Refused("policy:kind-mismatch", d["name"])
    return out


def check_mem(d: dict, consts) -> list:
    """`checkMem`."""
    if any(const[0] == "none" for const in consts):
        raise Refused("policy:none", d["name"], "in-list")
    lowered = lower_members(d, consts)
    if d["kind"] == "fixed" and not carries(d["rounding"], None):
        raise Refused("policy:rounding", d["name"])
    return lowered


def defined(defs: List[dict], name: str) -> dict:
    """`defined`: an engine counter first, then the definition."""
    if name in ENGINE_COUNTERS:
        raise Refused("policy:engine-counter", name)
    for d in defs:
        if d["name"] == name:
            return d
    raise Refused("image:field-index-oob", name)


def lower_cond(defs: List[dict], cond):
    """`lowerCond`, depth first and left to right."""
    tag = cond[0]
    if tag in ("always", "never"):
        return cond
    if tag == "truthy":
        check_truthy(defined(defs, cond[1]))
        return cond
    if tag == "cmp":
        return ("cmp", cond[1], cond[2], check_cmp(defined(defs, cond[1]), cond[2], cond[3]))
    if tag in ("in", "nin"):
        return (tag, cond[1], check_mem(defined(defs, cond[1]), cond[2]))
    if tag == "not":
        return ("not", lower_cond(defs, cond[1]))
    return (tag, [lower_cond(defs, operand) for operand in cond[1]])


def none_tested(cond) -> List[str]:
    """`LCond.noneTested`."""
    tag = cond[0]
    if tag == "cmp" and cond[3][0] == "none":
        return [cond[1]]
    if tag == "not":
        return none_tested(cond[1])
    if tag in ("and", "or"):
        return [name for operand in cond[1] for name in none_tested(operand)]
    return []


def check_image(fields, rules) -> None:
    """`checkImage`: the definitions, every rule lowered in order, then rule 6 (`checkAbsence`)."""
    defs = parse_defs(fields)
    lowered = [lower_cond(defs, cond) for _target, cond in rules]
    tested = {name for cond in lowered for name in none_tested(cond)}
    for d in defs:
        if d["absent_ok"] and d["name"] not in tested:
            raise Refused("policy:absence-untested", d["name"])


def load_policy(image: bytes) -> Optional[Tuple[str, int, Optional[str], Optional[str]]]:
    """`loadPolicy` on the image's bytes: None when the oracle accepts it, else the oracle's spelling of the
    refusal, (cause, code, field, reason)."""
    from prismpath.kernel import canon2
    try:
        doc = canon2.loads(image)
    except canon2.Canon2Error as error:
        return Refused("policy:unreadable", None, error.rule).spelled()
    try:
        fields, rules = decode_image(doc)
        check_image(fields, rules)
    except Refused as refused:
        return refused.spelled()
    return None


def refuses_for_counter(image: bytes) -> bool:
    """Lean's `counterRefusal`: the oracle refuses the image for reading an engine counter."""
    refusal = load_policy(image)
    return refusal is not None and refusal[0] == "policy:engine-counter"
