# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Differential harness for the verified policy core (docs/design/spec-verified-core.md, section 8).

One generator writes random policy images and readings, well formed and malformed, biased toward
boundaries. Each case runs through the oracle and up to six legs (spec section 8 has the table):

  * lean:     the oracle compiled from the Lean semantics (`formal/.lake/build/bin/core-oracle --batch`);
  * python:   the reference, composed as the frozen field definition vectors compose it: `parser.parse`
              (which lowers and applies the policy rules), `field_definitions.system_boundary`, then
              `engine.first_deterministic`, with `field_definitions.policy_check` beside it; documents are
              read with the canon/2 reader `prismpath.kernel.canon2.loads`;
  * rust:     the Rust port, composed the same way by `prismpath-rs/examples/core_diff.rs`, reading with
              `prismpath_rs::canon2::read`;
  * js, go:   the second tier kernels (`formal/diff/core_diff_js.mjs`, `prismpath-go/cmd/core_diff`), which
              refuse every flow that defines its fields (D5) and read readings with their runtime's JSON;
  * c-interp, c-hdr: the table targets: the reference as host, `prismpath-hw/ppt_compile.py`, and the
              certified C evaluators `interp.c` and `ppt_eval.h` through `formal/diff/ppt_batch.c` (D6).

The image is a canon/2 document in the core's abstract syntax. The kernels read flows, not images, so
this module renders a well formed image to the flow text it means (`render`); an image that has no
faithful rendering is reported as unrenderable for those legs and compared on the Lean leg alone. Every
leg is an adapter around the implementation's own functions; no leg reimplements a rule.

Each difference is classified. The legs that read canon/2 must refuse an unreadable image or reading
with the oracle's rule; `reader-gap:<rule>` remains only for the two legs with no canon/2 reader. Scope
differences, refusing kernels and target limits are counted as such; anything else is
a finding, minimised to a small reproducer of the same kind.

    python formal/diff/core_diff.py --cases 100000 --seed 1          # the large run, every leg
    python formal/diff/core_diff.py --cases 2000 --seed 7 --quiet    # a quick run

Adding a leg is one entry in LEGS: a function from the list of cases to {id: result} in the normalized
shape `normalize_*` documents.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

ORACLE = ROOT / "formal" / ".lake" / "build" / "bin" / "core-oracle"
EXACT = 2 ** 53 - 1
FORMAT = "prismpath.core/1"
START = "core_decision"
# canon/2 document rules a leg without a canon/2 reader does not apply: for such a leg (READS_CANON2
# false) a difference that is only one of these is a reader gap, not a finding (spec section 3)
READER_GAP = {"float", "integer-range", "negative-zero", "duplicate-key", "depth"}
READS_CANON2 = {"python": True, "rust": True, "c-interp": True, "c-hdr": True}
# the second tier kernels read readings with their runtime's JSON (D5), which also accepts a lone
# surrogate escape (replacing it, in Go)
READER_GAP_SECOND_TIER = READER_GAP | {"lone-surrogate"}
# the legs whose refusals speak the cause registry (the second tier kernels do not)
CODED = {"python", "rust", "c-interp", "c-hdr"}

ALWAYS = {"always", "true", "else", "otherwise", "default", "_"}
NEVER = {"false", "never"}
FLIP = {"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "!=": "!="}


# ----------------------------------------------------------------- rendering an image as a flow
class Unrenderable(Exception):
    pass


def _ident(name) -> bool:
    import re
    return isinstance(name, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is not None


def _py_string(text: str) -> str:
    """A Python string literal for `text` that survives the flow's line structure."""
    out = ['"']
    for char in text:
        code = ord(char)
        if char == "\\":
            out.append("\\\\")
        elif char == '"':
            out.append('\\"')
        elif code < 0x20 or code == 0x7F or code in (0x85, 0x2028, 0x2029):
            out.append(f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}")
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def _const(k, rng) -> str:
    if not isinstance(k, list) or not k or not isinstance(k[0], str):
        raise Unrenderable("constant")
    tag = k[0]
    if tag == "num" and len(k) == 2:
        value = k[1]
        if isinstance(value, bool):
            raise Unrenderable("number")
        if isinstance(value, int):
            return str(value)
        if isinstance(value, str):
            import re
            if re.fullmatch(r"-?[1-9][0-9]*", value) or \
                    re.fullmatch(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?", value) and \
                    any(c in value for c in ".eE"):
                return value
        raise Unrenderable("number")
    if tag == "bool" and len(k) == 2 and isinstance(k[1], bool):
        return "True" if k[1] else "False"
    if tag == "str" and len(k) == 2 and isinstance(k[1], str):
        return _py_string(k[1])
    if tag == "none" and len(k) == 1:
        return "None"
    if tag == "field" and len(k) == 2 and _ident(k[1]):
        return k[1]
    raise Unrenderable("constant")


def _name(name) -> str:
    if not _ident(name):
        raise Unrenderable("name")
    return name


def _cond(c, rng, top=False) -> str:
    if not isinstance(c, list) or not c or not isinstance(c[0], str):
        raise Unrenderable("condition")
    tag = c[0]
    sp = " " if rng.random() < 0.8 else ""
    if tag == "truthy" and len(c) == 2:
        name = _name(c[1])
        return f"({name})" if (top and name.lower() in ALWAYS | NEVER) or rng.random() < 0.1 else name
    if tag == "cmp" and len(c) == 4 and isinstance(c[2], str):
        if c[2] not in FLIP:
            raise Unrenderable("operator")
        name, k = _name(c[1]), _const(c[3], rng)
        text = f"{k}{sp}{FLIP[c[2]]}{sp}{name}" if rng.random() < 0.25 else f"{name}{sp}{c[2]}{sp}{k}"
        return f"({text})" if rng.random() < 0.1 else text
    if tag in ("in", "not in") and len(c) == 3 and isinstance(c[2], list):
        name = _name(c[1])
        items = [_const(k, rng) for k in c[2]]
        if rng.random() < 0.3:
            body = "(" + ", ".join(items) + ("," if len(items) == 1 else "") + ")"
        else:
            body = "[" + ", ".join(items) + "]"
        return f"{name} {tag} {body}"
    if tag == "not" and len(c) == 2:
        inner = _cond(c[1], rng)
        if isinstance(c[1], list) and c[1] and c[1][0] in ("and", "or"):
            inner = f"({inner})"
        return f"not {inner}"
    if tag == "and" and len(c) == 3 and rng.random() < 0.3 and _chain_ok(c):
        # `a < x and x < b` written as the chain `a < x < b` (SPEC.md section 4.3 desugars it back)
        first, second = c[1], c[2]
        low = _const(first[3], rng)
        return f"{low}{sp}{FLIP[first[2]]}{sp}{_name(first[1])}{sp}{second[2]}{sp}{_const(second[3], rng)}"
    if tag in ("and", "or") and len(c) >= 3:
        parts = []
        for operand in c[1:]:
            text = _cond(operand, rng)
            if isinstance(operand, list) and operand and operand[0] in ("and", "or"):
                text = f"({text})"
            parts.append(text)
        return f" {tag} ".join(parts)
    raise Unrenderable("condition")


class _NoChain:
    """A random source that never chooses a chain."""

    def __init__(self, rng):
        self.rng = rng

    def random(self):
        value = self.rng.random()
        return value if value >= 0.3 else 0.3 + value

    def choice(self, items):
        return self.rng.choice(items)


def _chain_ok(c) -> bool:
    first, second = c[1], c[2]
    return (isinstance(first, list) and isinstance(second, list) and len(first) == 4 and len(second) == 4
            and first[0] == second[0] == "cmp" and first[1] == second[1] and first[2] in FLIP and second[2] in FLIP
            and first[2] not in ("==", "!=") and second[2] not in ("==", "!="))


def ir_depth(c) -> int:
    """The core's depth of a condition (spec section 2.4)."""
    if not isinstance(c, list) or not c:
        return 0
    if c[0] in ("not",) and len(c) == 2:
        return 1 + ir_depth(c[1])
    if c[0] in ("and", "or"):
        return 1 + max((ir_depth(x) for x in c[1:]), default=0)
    if c[0] == "truthy":
        return 1
    return 0 if c[0] in ("always", "never") else 2


def render(doc, rng) -> str:
    """The flow text an image means, or Unrenderable. Only the shape needed to write the text is
    checked here; every rule of the core is left to the implementation under test."""
    if not isinstance(doc, dict) or set(doc) != {"format", "fields", "rules"} or doc["format"] != FORMAT:
        raise Unrenderable("image")
    fields, rules = doc["fields"], doc["rules"]
    if not isinstance(fields, dict) or not isinstance(rules, list):
        raise Unrenderable("image")
    lines = ["---", "name: core", f"start: {START}"]
    breaks = {"\n", "\r", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", " ", " "}
    for name, text in fields.items():
        if not isinstance(text, str) or not name or ":" in name or any(c in breaks for c in name + text) \
                or name != name.strip() or name.startswith("-"):
            raise Unrenderable("definition")
        lines.append(f"field.{name}: {text}")
    lines += ["---", f"## {START}"]
    targets = []
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) != {"target", "when"} or not isinstance(rule["target"], str):
            raise Unrenderable("rule")
        import re
        target = rule["target"]
        if not re.fullmatch(r"[A-Za-z0-9_-]+", target):
            raise Unrenderable("target")
        when = rule["when"]
        if when == ["always"]:
            cond = rng.choice(["always", "else", "default", "when True"]) if rng.random() < 0.5 else "always"
        elif when == ["never"]:
            cond = "never"
        else:
            # a chain is shallower than its desugaring, so chains are written only well inside the bound
            chain_rng = rng if ir_depth(when) <= 50 else _NoChain(rng)
            cond = "when " + _cond(when, chain_rng, top=True)
        lines.append(f"-> {target}: {cond}")
        if target.lower() != START and target.lower() not in targets:
            targets.append(target.lower())
    for target in targets:
        lines.append(f"## {target}")
    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------- the generator
BOUNDS = [-EXACT, -EXACT + 1, -2 ** 31 - 1, -2 ** 31, -100, -5, -1, 0, 1, 5, 99, 100, 2 ** 31 - 1, 2 ** 31,
          EXACT - 1, EXACT]
SCALES = [1, 10, 100, 1000, 10000, 10 ** 9]
# Python's whitespace (str.isspace) that can reach a definition through the flow text, and U+FEFF, which is
# not whitespace in Python although JavaScript's trim strips it (D3)
WS = [" ", " ", " ", "  ", "\t", "\xa0", "　", "\x1f", "\u1680", "\u2000", "\u200a", "\u202f", "\u205f",
      "\x1f\x1f", "\ufeff"]


class Field:
    def __init__(self, name, kind, lo, hi, absent, scale=None, rounding=None):
        self.name, self.kind, self.lo, self.hi, self.absent = name, kind, lo, hi, absent
        self.scale, self.rounding = scale, rounding


def gen_field(rng, name):
    kind = rng.choice(["int", "int", "fixed", "fixed", "bool", "category"])
    absent = rng.random() < 0.3
    lo, hi = -EXACT, EXACT
    opts = []
    scale = rounding = None
    if kind in ("int", "fixed"):
        if rng.random() < 0.7:
            a, b = sorted([rng.choice(BOUNDS), rng.choice(BOUNDS)])
            lo, hi = a, b
            opts += [f"min={lo}", f"max={hi}"]
        elif rng.random() < 0.5:
            lo = rng.choice(BOUNDS)
            opts.append(f"min={lo}")
            hi = EXACT
    if kind == "fixed":
        scale = rng.choice(SCALES)
        rounding = rng.choice(["floor", "ceiling", "exact"])
        opts += [f"scale={scale}", f"rounding={rounding}"]
        if rng.random() < 0.5:
            opts.append("unit=" + rng.choice(["ratio", "usd", "s", "°C", "m/s"]))
    if absent:
        opts.append("absent=allowed")
    elif rng.random() < 0.2:
        opts.append("absent=refused")
    rng.shuffle(opts)
    sep = rng.choice(WS) if rng.random() < 0.15 else " "
    text = sep.join([kind] + opts)
    if rng.random() < 0.05:
        text = rng.choice(WS) + text + rng.choice(WS)
    field = Field(name, kind, lo, hi, absent, scale, rounding)
    if rng.random() < 0.08:
        text, field = bad_definition(rng, kind, text), None
    return text, field


def bad_definition(rng, kind, text):
    return rng.choice([
        "float", "", "int min=1.5", "int min=+3", "int min=007", "int min=٣", "int max=9007199254740992",
        "int min=-9007199254740992", "int min=5 max=4", "int min=0 min=1", "int scale=100", "int absent=maybe",
        "fixed scale=100", "fixed rounding=floor", "fixed scale=0 rounding=floor", "fixed scale=1000000001 rounding=floor",
        "fixed scale=0x10 rounding=floor", "fixed scale=100 rounding=round", "fixed scale=100 rounding=floor unit=",
        "bool min=0", "category scale=1", "Int", "int min", "int =3", "int min==3", text + " absent=allowed absent=refused",
        "fixed scale=10 rounding=exact min=-9007199254740991 max=9007199254740991",
    ])


def rand_name(rng, used):
    pool = ["x", "y", "rate", "level", "armed", "label", "_", "default", "a1", "B", "count", "temp", "z_z"]
    name = rng.choice(pool)
    if name in used:
        name = name + str(len(used))
    return name


def num_const(rng, field):
    """A numeric constant for an int or fixed field, near its boundaries."""
    if field.kind == "fixed":
        scale = field.scale
        anchor = rng.choice([field.lo, field.hi, field.lo + 1, field.hi - 1, 0, rng.randint(field.lo, field.hi)])
        choice = rng.random()
        if choice < 0.45:
            # an exact decimal of the anchor in source units
            whole, frac = divmod(abs(anchor), scale)
            digits = len(str(scale)) - 1
            sign = "-" if anchor < 0 else ""
            text = f"{sign}{whole}.{str(frac).zfill(digits)}" if digits else f"{sign}{whole}.0"
            if rng.random() < 0.2:
                text = text.rstrip("0") if "." in text and not text.endswith(".") else text
                if text.endswith(".") and rng.random() < 0.5:
                    text += "0"
            return ["num", text]
        if choice < 0.6:
            return ["num", rng.choice(["0.5", "0.85", "1.5", "0.00001", "-0.29", "1e-4", "1e3", ".5", "5.", "1.0",
                                       "0.000000000000000000000000001", "12345678901234567890123456789.0", "1e31",
                                       "9999999999999999999999999999e30", "-9999999999999999999999999999e-30", "1e-30",
                                       "1e30", "1E+30", "0e-31", "0.0", "-0.0", "000.5000", "1234567890123456789012345678.",
                                       ".0000000000000000000000000001", "1" + "0" * 27 + ".0", "+.5e-0", "-5.5E1"])]
        whole = anchor // scale + rng.choice([-1, 0, 0, 1])
        if rng.random() < 0.05:
            whole = rng.choice([1, -1]) * int("9" * rng.choice([16, 20, 40, 400]))
        if abs(whole) <= EXACT:
            return ["num", whole]
        return ["num", str(whole)]
    value = rng.choice([field.lo, field.hi, field.lo - 1, field.hi + 1, 0, rng.randint(field.lo, field.hi)])
    if abs(value) <= EXACT:
        return ["num", value]
    return ["num", str(value)]


STRINGS = ["a", "b", "", "é", "e\u0301", "\U0001f600", "x\ny", "quote\"", "apos'", "back\\slash", "\\x41",
           "\u2028", "A", "\x00", "\t", "\x7f", "\x85", "\ud7ff", "\ue000", "\uffff", "None", "True", "1", " a "]


def gen_atom(rng, fields):
    if not fields or rng.random() < 0.03:
        return ["truthy", rng.choice(["ghost", "x9", "visits"])] if rng.random() < 0.3 else \
            ["cmp", "ghost", "==", ["num", 1]]
    field = rng.choice(fields)
    name = field.name
    ops = ["<", "<=", ">", ">=", "==", "!="]
    r = rng.random()
    wrong = rng.random() < 0.1
    if field.absent and r < 0.15:
        return ["cmp", name, rng.choice(["==", "!=", "==", "<"] if wrong else ["==", "!="]), ["none"]]
    if field.kind in ("int", "fixed"):
        if field.kind == "fixed" and not wrong:
            ops = {"floor": [">=", "<"], "ceiling": [">", "<="], "exact": ops}[field.rounding]
        if r < 0.15 and (field.kind == "int" or field.rounding == "exact" or wrong):
            return ["truthy", name]
        if r < 0.3 and (field.kind == "int" or field.rounding == "exact" or wrong):
            items = [num_const(rng, field) for _ in range(rng.choice([0, 1, 2, 3]))]
            if rng.random() < 0.2 and items:
                items.append(items[0])
            if wrong:
                items.append(rng.choice([["none"], ["str", "1"], ["bool", True], ["num", "0.5"]]))
            return [rng.choice(["in", "not in"]), name, items]
        const = num_const(rng, field)
        if wrong:
            const = rng.choice([["bool", True], ["str", "3"], ["num", "2.5"], ["field", "other"], const])
        return ["cmp", name, rng.choice(ops), const]
    if field.kind == "bool":
        if r < 0.5 and not wrong:
            return ["truthy", name]
        const = ["bool", rng.random() < 0.5] if not wrong else rng.choice([["num", 1], ["str", "true"], ["bool", True]])
        return ["cmp", name, rng.choice(["==", "!="] if not wrong else ops), const]
    strings = ["a", "b", "", "é", "\U0001f600", "x\ny", "quote\"", "back\\slash", " ", "A"]
    if r < 0.2:
        return ["truthy", name]
    if r < 0.5:
        items = [["str", rng.choice(strings)] for _ in range(rng.choice([0, 1, 2, 3]))]
        if wrong:
            items.append(rng.choice([["num", 3], ["none"]]))
        return [rng.choice(["in", "not in"]), name, items]
    const = ["str", rng.choice(strings)] if not wrong else rng.choice([["num", 3], ["str", "m"]])
    return ["cmp", name, rng.choice(["==", "!="] if not wrong else ops), const]


def gen_cond(rng, fields, depth):
    r = rng.random()
    if depth <= 0 or r < 0.45:
        return gen_atom(rng, fields)
    if r < 0.6:
        return ["not", gen_cond(rng, fields, depth - 1)]
    return [rng.choice(["and", "or"])] + [gen_cond(rng, fields, depth - 1) for _ in range(rng.choice([2, 2, 3]))]


def deep_cond(rng, fields, target_depth):
    """A condition at a chosen depth near the bound of 50 (spec section 2.4): a `not` chain, or `and` and
    `or` nested on the left, on the right or alternately, which the flow text writes with parentheses
    (D2: a parser that counts its own recursion, or brackets, measures these differently)."""
    atom = gen_atom(rng, fields)
    base = 1 if atom[0] == "truthy" else 2
    cond = atom
    shape = rng.choice(["not", "not", "right", "left", "mixed"])
    for level in range(max(0, target_depth - base)):
        if shape == "not" or (shape == "mixed" and level % 3 == 0):
            cond = ["not", cond]
        else:
            other = gen_atom(rng, fields)
            tag = rng.choice(["and", "or"])
            right = shape == "right" or (shape == "mixed" and level % 2)
            cond = [tag, other, cond] if right else [tag, cond, other]
    return cond


def gen_policy(rng):
    fields, texts, used = [], {}, set()
    for _ in range(rng.choice([0, 1, 1, 2, 2, 3, 4])):
        name = rand_name(rng, used)
        used.add(name)
        text, field = gen_field(rng, name)
        texts[name] = text
        if field is not None:
            fields.append(field)
    if rng.random() < 0.02:
        texts[rng.choice(["visits", "error_count", "9x", "a-b", "é"])] = "int"
    rules = []
    for index in range(rng.choice([0, 1, 2, 3, 4, 5])):
        if rng.random() < 0.06:
            cond = deep_cond(rng, fields, rng.choice([25, 49, 50, 50, 51, 52, 53]))
        else:
            cond = gen_cond(rng, fields, rng.choice([0, 1, 2, 3]))
        rules.append({"target": rng.choice(["hit", "low", "gone", "miss", "Hit", "core_decision", "t-1"]), "when": cond})
    if rng.random() < 0.5:
        rules.append({"target": "miss", "when": ["always"] if rng.random() < 0.9 else ["never"]})
    # absence rule 6 is usually honoured
    for field in fields:
        if field.absent and rng.random() < 0.85:
            rules.insert(rng.randint(0, len(rules)), {"target": "gone", "when": ["cmp", field.name, "==", ["none"]]})
    image = {"format": FORMAT, "fields": texts, "rules": rules}
    return image, fields


def dumps(doc, rng):
    items = list(doc.items()) if isinstance(doc, dict) else None
    if items is not None and rng.random() < 0.5:
        rng.shuffle(items)
        doc = dict(items)
    return json.dumps(doc, ensure_ascii=rng.random() < 0.5, separators=(",", ":") if rng.random() < 0.5 else None)


def mutate_image(rng, image, text):
    """A malformed image: text level or shape level."""
    kind = rng.randrange(14)
    if kind == 0:
        return text.replace("prismpath.core/1", "prismpath.core/2", 1)
    if kind == 1:
        return text[: rng.randrange(1, len(text))]
    if kind == 2:
        return text[:-1] + ',"extra":1}'
    if kind == 3:
        return text[:-1] + ',"rules":[]}'
    if kind == 4:
        return text.replace('"num",', '"num",0.5,', 1) if '"num",' in text else text + "x"
    if kind == 5:
        return text.replace('["num",', '["num",1.0],["num",', 1) if '["num",' in text else "-0"
    if kind == 6:
        return '{"format":"prismpath.core/1","fields":{},"rules":[' + "[" * 130 + "]" * 130 + "]}"
    if kind == 7:
        return text.replace('"==",', '"=",', 1) if '"==",' in text else text.replace("{", "[", 1)
    if kind == 8:
        return text.replace('"cmp"', '"compare"', 1) if '"cmp"' in text else '{"format":"prismpath.core/1"}'
    if kind == 9:
        return '{"format":"prismpath.core/1","fields":{"x":"int"},"rules":[{"target":"hit","when":["cmp","x",">=",["num",9007199254740992]]}]}'
    if kind == 10:
        return '{"format":"prismpath.core/1","fields":{"x":"category"},"rules":[{"target":"hit","when":["cmp","x","==",["str","\\ud800"]]}]}'
    if kind == 11:
        return '{"format":"prismpath.core/1","fields":{"x":"int"},"rules":[{"target":"hit","when":["cmp","x","==",["num",-0]]}]}'
    if kind == 12:
        return text.replace('"target":', '"target": NaN, "t":', 1)
    return '{"format":"prismpath.core/1","fields":{"x":"int","x":"bool"},"rules":[{"target":"hit","when":["truthy","x"]}]}'


def gen_value(rng, field):
    if field is None:
        return rng.choice([1, "a", True, None, [1], {"k": 1}])
    r = rng.random()
    if r < 0.08:
        return None
    if r < 0.18:
        return rng.choice(["1", True, False, [], {}, "", 0, "a"]) if field.kind != "category" else rng.choice([1, True, [], None])
    if field.kind in ("int", "fixed"):
        return rng.choice([field.lo, field.hi, field.lo - 1, field.hi + 1, 0, 1, -1, rng.randint(field.lo, field.hi)])
    if field.kind == "bool":
        return rng.random() < 0.5
    return rng.choice(["a", "b", "", "é", "\U0001f600", "x\ny", "quote\"", "back\\slash", " ", "A", "z"])


def gen_reading(rng, fields, text_fields):
    doc = {}
    for field in fields:
        if rng.random() < 0.1:
            continue
        doc[field.name] = gen_value(rng, field)
    if rng.random() < 0.15:
        doc[rng.choice(["extra", "other", "visits"])] = rng.choice([1, "s", [1, 2], {"a": None}])
    for name in text_fields:
        if not any(field.name == name for field in fields) and rng.random() < 0.5:
            doc[name] = gen_value(rng, None)
    text = dumps(doc, rng)
    r = rng.random()
    if r < 0.03:
        return text.replace(": 0", ": 0.0", 1).replace(":0", ":0.0", 1) if "0" in text else "1.5"
    if r < 0.05:
        return text[:-1] + (', "x": -0}' if len(doc) else '"x": -0}')
    if r < 0.07:
        return text[:-1] + (', "y": 9007199254740993}' if len(doc) else '"y": 9007199254740993}')
    if r < 0.09 and doc:
        key = next(iter(doc))
        return text[:-1] + ", " + json.dumps(key) + ": null}"
    if r < 0.10:
        return rng.choice(["[]", "null", "3", '"s"', "", "{", '{"a":1}x', "NaN", '{"a":NaN}', '{"a":1e400}',
                           '{"a":"\\udc00"}', "[" * 200 + "]" * 200, '{"a":' + "[" * 129 + "]" * 129 + "}"])
    if r < 0.12:
        for field in fields:
            if field.kind in ("int", "fixed"):
                return text[:-1] + (", " if len(doc) else "") + json.dumps(field.name) + ": " + rng.choice(["3.0", "1e2", "8500.5", "-0.0"]) + "}" \
                    if field.name not in doc else text.replace(json.dumps(field.name) + ": ", json.dumps(field.name) + ": 1.0 , \"_q\": ", 1)
    return text


# invalid UTF-8: a stray continuation, overlong forms, an encoded surrogate, past U+10FFFF, truncated
BAD_UTF8 = [b"\xff", b"\x80", b"\xc0\xaf", b"\xc1\xbf", b"\xe0\x80\xaf", b"\xed\xa0\x80", b"\xf4\x90\x80\x80",
            b"\xf5\x80\x80\x80", b"\xe2\x82", b"\xf0\x9f\x98", b"\xf8\x88\x80\x80\x80"]
# valid but unusual UTF-8 between the opening brace and the first key: whitespace JSON does not allow
GOOD_UTF8 = ["\u00a0".encode(), "\ufeff".encode(), "\U0010ffff".encode(), "\u0085".encode()]


def gen_case(rng, ident):
    image, fields = gen_policy(rng)
    text = dumps(image, rng)
    if rng.random() < 0.12:
        text = mutate_image(rng, image, text)
    image_bytes = text.encode("utf-8")
    if rng.random() < 0.01:
        image_bytes = image_bytes.replace(b"{", b"{" + rng.choice(BAD_UTF8), 1)
    readings = [gen_reading(rng, fields, image["fields"]).encode("utf-8") for _ in range(rng.choice([1, 2, 4, 6, 8]))]
    if rng.random() < 0.02:
        index = rng.randrange(len(readings))
        readings[index] = readings[index][:1] + rng.choice(BAD_UTF8 + GOOD_UTF8) + readings[index][1:]
    return {"id": str(ident), "image": image_bytes, "readings": readings, "render_seed": rng.randrange(2 ** 31)}


# ----------------------------------------------------------------- the legs
def frames(cases, docs_of):
    """`case <id> <readings>` then the documents, each as its byte length and its bytes. The documents
    are the leg's head documents (the image, and the flow for a leg that reads one) and the readings."""
    out = bytearray()
    for case in cases:
        docs = docs_of(case)
        out += f"case {case['id']} {len(case['readings'])}\n".encode()
        for doc in docs:
            out += f"{len(doc)}\n".encode() + doc + b"\n"
    return bytes(out)


def normalize_reading(verdict):
    """('route', target) | ('contract', field, reason) | ('nomatch',) | ('unreadable', reason) | ('notobject',)"""
    if verdict["verdict"] == "route":
        return ("route", verdict["target"])
    cause = verdict["cause"]
    if cause == "route:contract-violation":
        return ("contract", verdict["field"], verdict["reason"])
    if cause == "route:no-matching-edge":
        return ("nomatch",)
    if cause == "reading:unreadable":
        return ("unreadable", verdict.get("reason", ""))
    if cause == "reading:not-object":
        return ("notobject",)
    if cause == "crash":
        return ("crash", verdict.get("reason", ""))
    return ("policy", cause)


def lean_leg(cases):
    if not ORACLE.exists():
        raise FileNotFoundError(f"{ORACLE} is not built: cd formal && lake build core-oracle")
    data = frames(cases, lambda case: [case["image"]] + case["readings"])
    result = subprocess.run([str(ORACLE), "--batch"], input=data, capture_output=True, check=True)
    out = {}
    for line in result.stdout.decode("utf-8").splitlines():
        row = json.loads(line)
        out[row["id"]] = row
    return out


def _render_for(case):
    from prismpath.kernel import canon2
    try:
        doc = canon2.loads(case["image"])
    except canon2.Canon2Error as error:
        return None, f"unreadable:{error.rule}"
    except RecursionError:
        return None, "crash:RecursionError"
    try:
        return render(doc, random.Random(case["render_seed"])), None
    except Unrenderable as why:
        return None, f"unrenderable:{why}"
    except RecursionError:
        return None, "unrenderable:recursion"


def python_reading(graph, raw):
    from prismpath.kernel import canon2, causes, engine, field_definitions

    def refuse(cause, **detail):
        return {"verdict": "refuse", "cause": cause, "code": causes.code(cause), **detail}

    try:
        doc = canon2.loads(raw)
    except canon2.Canon2Error as error:
        return refuse("reading:unreadable", reason=error.rule)
    except RecursionError:
        return {"verdict": "refuse", "cause": "crash", "reason": "RecursionError in canon2.loads"}
    if not isinstance(doc, dict):
        return refuse("reading:not-object")
    verdict = _python_verdict(graph, doc, refuse)
    try:
        check = field_definitions.policy_check(graph, doc)
    except Exception as error:   # noqa: BLE001
        return {"verdict": "refuse", "cause": "crash", "reason": f"policy_check {type(error).__name__}: {error}"[:200]}
    verdict["policy_check"] = "pass" if check is None else {"field": check[0], "reason": check[1]}
    return verdict


def _python_verdict(graph, doc, refuse):
    from prismpath.kernel import engine, field_definitions
    try:
        refused = field_definitions.system_boundary(graph, doc)
        if refused is not None:
            return refuse("route:contract-violation", field=refused[0], reason=refused[1])
        target, _cond = engine.first_deterministic(graph.nodes[graph.start].edges, doc)
    except Exception as error:   # noqa: BLE001 - an exception is itself the finding
        return {"verdict": "refuse", "cause": "crash", "reason": f"{type(error).__name__}: {error}"[:200]}
    if target is None:
        return refuse("route:no-matching-edge")
    return {"verdict": "route", "target": target}


def prepare(cases):
    """Render every image to its flow once, for every leg that reads flows."""
    for case in cases:
        case["flow"], case["flow_why"] = _render_for(case)


def python_leg(cases):
    from prismpath.kernel import causes
    from prismpath.kernel.field_definitions import FieldDefinitionError
    from prismpath.kernel.parser import parse
    out = {}
    for case in cases:
        flow, why = case["flow"], case["flow_why"]
        if flow is None and why.startswith("unreadable:"):
            out[case["id"]] = {"policy": "refused", "cause": "policy:unreadable", "reason": why.split(":", 1)[1],
                               "code": causes.code("policy:unreadable"), "causes": ["policy:unreadable"]}
            continue
        if flow is None:
            out[case["id"]] = {"policy": why}
            continue
        try:
            graph = parse(flow)
        except FieldDefinitionError as error:
            out[case["id"]] = {"policy": "refused", "reason": str(error)[:300], "cause": error.cause,
                               "code": error.code, "field": error.field, "policy_reason": error.reason,
                               "causes": [problem.cause for problem in error.problems]}
            continue
        except ValueError as error:
            out[case["id"]] = {"policy": "refused", "reason": str(error)[:300], "cause": None, "code": None,
                               "causes": []}
            continue
        except Exception as error:   # noqa: BLE001
            out[case["id"]] = {"policy": "crash", "reason": f"{type(error).__name__}: {error}"[:300]}
            continue
        out[case["id"]] = {"policy": "accepted", "defines": bool(graph.fields),
                           "readings": [python_reading(graph, raw) for raw in case["readings"]]}
    return out


RUST_EXAMPLE = None


def rust_binary():
    target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
    return target / "debug" / "examples" / "core_diff"


def rust_leg(cases):
    binary = rust_binary()
    if not binary.exists():
        subprocess.run(["cargo", "build", "-q", "-p", "prismpath-rs", "--example", "core_diff"], cwd=ROOT, check=True)
    data = frames(cases, lambda case: [case["image"], (case.get("flow") or "").encode("utf-8")] + case["readings"])
    result = subprocess.run([str(binary)], input=data, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError("rust leg failed: " + result.stderr.decode("utf-8", "replace")[-2000:])
    out = {}
    for line in result.stdout.decode("utf-8").splitlines():
        row = json.loads(line)
        out[row["id"]] = row
    return out


# ----------------------------------------------------------------- the second tier and table legs
_TOOLS = {}


def _tool_dir() -> Path:
    """A private build directory for the adapters this run compiles, removed when the process exits."""
    if "dir" not in _TOOLS:
        import atexit
        import shutil
        made = tempfile.mkdtemp(prefix="core_diff_tools_")
        atexit.register(shutil.rmtree, made, True)
        _TOOLS["dir"] = Path(made)
    return _TOOLS["dir"]


def _tool(name: str) -> Path:
    """Build an adapter once per run: the Go leg and the two C table drivers."""
    if name in _TOOLS:
        return _TOOLS[name]
    out = _tool_dir() / name
    hw = ROOT / "prismpath-hw"
    driver = ROOT / "formal" / "diff" / "ppt_batch.c"
    if name == "go":
        subprocess.run(["go", "build", "-o", str(out), "./cmd/core_diff"], cwd=ROOT / "prismpath-go", check=True)
    elif name == "c-hdr":
        subprocess.run(["cc", "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror", "-I", str(hw), "-DPPT_BATCH_HDR",
                        "-o", str(out), str(driver)], check=True)
    elif name == "c-interp":
        # interp.c's CLI modes are unused without its main, so its own warnings are not made errors here
        subprocess.run(["cc", "-O2", "-std=c11", "-Wall", "-Wextra", "-Wno-unused-function", "-Werror", "-I", str(hw),
                        "-DPPT_INTERP_NO_MAIN", "-o", str(out), str(driver), str(hw / "interp.c")], check=True)
    else:
        raise KeyError(name)
    _TOOLS[name] = out
    return out


def _second_tier(cases, command):
    data = frames(cases, lambda case: [case["image"], (case.get("flow") or "").encode("utf-8")] + case["readings"])
    result = subprocess.run(command, input=data, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(f"{command[0]} leg failed: " + result.stderr.decode("utf-8", "replace")[-2000:])
    out = {}
    for line in result.stdout.decode("utf-8").splitlines():
        row = json.loads(line)
        out[row["id"]] = row
    for case in cases:
        if case.get("flow") is None and case["flow_why"].startswith("unreadable:"):
            # these kernels read flows, not images; an image no flow is rendered from is not theirs to read
            out[case["id"]] = {"policy": "unrenderable"}
    return out


def js_leg(cases):
    """The JavaScript kernel (prismpath/portable/prismpath.mjs) through formal/diff/core_diff_js.mjs."""
    return _second_tier(cases, ["node", str(ROOT / "formal" / "diff" / "core_diff_js.mjs")])


def go_leg(cases):
    """The Go kernel (prismpath-go) through prismpath-go/cmd/core_diff."""
    return _second_tier(cases, [str(_tool("go"))])


def _ppt_compile():
    if "ppt" not in _TOOLS:
        import importlib.util
        spec = importlib.util.spec_from_file_location("ppt_compile", ROOT / "prismpath-hw" / "ppt_compile.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _TOOLS["ppt"] = module
    return _TOOLS["ppt"]


def table_leg(cases, variant):
    """The C table targets: the host (the Python reference) checks the policy, reads each reading with
    canon/2 and applies the system boundary, `prismpath-hw/ppt_compile.py` compiles the checked policy to a
    .ppt image and encodes each accepted reading's registers, and the certified C evaluator (`interp.c` or
    the embedded `ppt_eval.h`) picks the edge. The compiler's 32 bit limit (`int-out-of-i32`, SPEC.md 4.3)
    is a refusal of the compiler or of the register encoder, reported as `target-limit`, never a route."""
    from prismpath.kernel import canon2, causes, field_definitions
    from prismpath.kernel.field_definitions import FieldDefinitionError
    from prismpath.kernel.parser import Node, parse
    ppt = _ppt_compile()
    out, pending, data = {}, [], bytearray()

    def refuse(cause, **detail):
        return {"verdict": "refuse", "cause": cause, "code": causes.code(cause), **detail}

    for case in cases:
        flow, why = case["flow"], case["flow_why"]
        if flow is None:
            out[case["id"]] = ({"policy": "refused", "cause": "policy:unreadable", "reason": why.split(":", 1)[1],
                                "code": causes.code("policy:unreadable"), "causes": ["policy:unreadable"]}
                               if why.startswith("unreadable:") else {"policy": why})
            continue
        try:
            graph = parse(flow)
        except FieldDefinitionError as error:
            out[case["id"]] = {"policy": "refused", "reason": str(error)[:300], "cause": error.cause, "code": error.code,
                               "field": error.field, "policy_reason": error.reason, "causes": [problem.cause for problem in error.problems]}
            continue
        except ValueError as error:
            out[case["id"]] = {"policy": "refused", "reason": str(error)[:300], "cause": None, "code": None, "causes": []}
            continue
        # the core's targets are labels, the table's are nodes: each rule's edge gets a node of its own, and a
        # matched edge index is read back as the rule's label, so a label that is no node name still routes
        start = graph.nodes[graph.start]
        labels = [target for target, _cond in start.edges]
        start.edges = [(f"rule{index}", cond) for index, (_target, cond) in enumerate(start.edges)]
        for index in range(len(labels)):
            graph.nodes[f"rule{index}"] = Node(name=f"rule{index}")
        row = {"policy": "accepted", "defines": bool(graph.fields)}
        out[case["id"]] = row
        try:
            image = ppt.compile_flow(graph)
        except ppt.SubsetError as error:
            row["table"] = "target-limit" if error.reason == "int-out-of-i32" else "compile-refused"
            row["reason"] = str(error)[:200]
            continue
        blob = image.serialize()
        verdicts, registers = [], []
        for raw in case["readings"]:
            try:
                doc = canon2.loads(raw)
            except canon2.Canon2Error as error:
                verdicts.append(refuse("reading:unreadable", reason=error.rule))
                registers.append(b"")
                continue
            if not isinstance(doc, dict):
                verdicts.append(refuse("reading:not-object"))
                registers.append(b"")
                continue
            refused = field_definitions.system_boundary(graph, doc)
            if refused is not None:
                verdicts.append(refuse("route:contract-violation", field=refused[0], reason=refused[1]))
                registers.append(b"")
                continue
            try:
                registers.append(ppt.encode_regs(image, doc, node_idx=image.start))
                verdicts.append(None)
            except ppt.SubsetError as error:
                verdicts.append({"verdict": "refuse", "cause": "target-limit", "reason": str(error)[:120]})
                registers.append(b"")
        row["readings"] = verdicts
        pending.append((case["id"], labels, verdicts))
        data += f"case {case['id']} {len(registers)}\n".encode() + f"{len(blob)}\n".encode() + blob + b"\n"
        for regs in registers:
            data += f"{len(regs)}\n".encode() + regs + b"\n"
    if pending:
        command = [str(_tool(variant))]
        if variant == "c-interp":
            command.append(str(_tool_dir() / "image.ppt"))
        result = subprocess.run(command, input=bytes(data), capture_output=True)
        if result.returncode != 0:
            raise RuntimeError(f"{variant} leg failed: " + result.stderr.decode("utf-8", "replace")[-2000:])
        lines = {line.split(" ", 1)[0]: line.split(" ", 1)[1] if " " in line else ""
                 for line in result.stdout.decode().splitlines()}
        for ident, labels, verdicts in pending:
            answers = lines[ident].split(";") if verdicts else []
            for index, answer in enumerate(answers):
                if verdicts[index] is not None:
                    continue
                if answer.startswith("m "):
                    verdicts[index] = {"verdict": "route", "target": labels[int(answer.split()[1])]}
                elif answer == "n":
                    verdicts[index] = refuse("route:no-matching-edge")
                else:
                    verdicts[index] = {"verdict": "refuse", "cause": "target-error", "reason": answer}
    return out


LEGS = {"python": python_leg, "rust": rust_leg, "js": js_leg, "go": go_leg,
        "c-interp": lambda cases: table_leg(cases, "c-interp"), "c-hdr": lambda cases: table_leg(cases, "c-hdr")}
ALL_LEGS = tuple(LEGS)


# ----------------------------------------------------------------- comparison
def _uncoded(row) -> bool:
    """A refusal that carries no registered code, or a code the registry gives another name."""
    from prismpath.kernel import causes
    return row.get("cause") != "crash" and (row.get("code") is None or causes.code(row.get("cause")) != row.get("code"))


def classify(lean_row, other, leg):
    """[(class, detail)] for one case: 'agree', 'excluded:<why>', 'reader-gap:<rule>', 'scope:<what>', 'target-limit:<what>' or
    'finding:<what>'."""
    rows = []
    for verdict in [lean_row["policy"]] * (lean_row["policy"]["policy"] != "accepted") + lean_row["readings"]:
        if verdict.get("verdict", "refuse") == "refuse" and _uncoded(verdict):
            rows.append(("finding:uncoded", f"lean {verdict}"))
    if leg in CODED and other.get("policy") == "refused" and _uncoded(other):
        rows.append(("finding:uncoded", f"leg policy {other.get('cause')} {other.get('code')} {other.get('reason', '')[:120]}"))
    for verdict in other.get("readings", []) if leg in CODED else []:
        if verdict["verdict"] == "refuse" and verdict.get("cause") != "target-limit" and _uncoded(verdict):
            rows.append(("finding:uncoded", f"leg reading {verdict}"))
    return rows + _classify(lean_row, other, leg)


def _classify(lean_row, other, leg):
    lean_policy = lean_row["policy"]
    lean_ok = lean_policy["policy"] == "accepted"
    status = other["policy"]
    if other.get("cause") == "refusing-kernel":
        # D5: a kernel without field definitions refuses every flow that defines its fields, as SPEC.md 4.5
        # requires; where the oracle refuses too, both refuse
        return [("refusing-kernel", "accepted by the oracle")] if lean_ok else [("agree", "policy-refused")]
    if lean_ok and status == "accepted" and other.get("table") == "target-limit":
        # D6: the compiler refuses a checked policy with a constant outside 32 bits; a refusal, not a route
        return [("target-limit:compile", other.get("reason", ""))]
    if lean_ok and status == "accepted" and other.get("table") == "compile-refused":
        return [("finding:compile", other.get("reason", ""))]
    if status not in ("accepted", "refused"):
        if status.startswith("crash"):
            return [("finding:crash", status)]
        if lean_ok:
            return [("finding:harness", f"lean accepts an image the leg cannot read: {status}")]
        if lean_policy["cause"] == "policy:unreadable":
            return [(f"excluded:{status.split(':')[0]}", lean_policy.get("reason", ""))]
        return [(f"excluded:{status.split(':')[0]}", lean_policy["cause"])]
    if lean_ok != (status == "accepted"):
        if not lean_ok and lean_policy["cause"] == "policy:unreadable" and lean_policy.get("reason") in READER_GAP \
                and not READS_CANON2.get(leg, False):
            return [(f"reader-gap:{lean_policy['reason']}", "policy")]
        if not lean_ok and other.get("defines") is False:
            # a flow that defines no field takes the reference's inferred path (SPEC.md section 4.5,
            # last paragraph), where no rule of section 4.5 applies; it is outside the core
            return [("scope:inferred-path", "policy")]
        if not lean_ok and lean_policy["cause"] == "policy:engine-counter":
            # the engine's registers are not reading fields; the core is one decision and reads none
            return [("scope:engine-counter", "policy")]
        what = "lean refuses, leg accepts" if not lean_ok else "lean accepts, leg refuses"
        return [(f"finding:policy", f"{what}: {lean_policy.get('cause', '')} {lean_policy.get('reason', '')} "
                                    f"{lean_policy.get('field', '')} | {other.get('reason', '')}")]
    if not lean_ok:
        if lean_policy["cause"] == "policy:unreadable" or other.get("cause") == "policy:unreadable":
            if (lean_policy["cause"], lean_policy.get("reason")) != (other.get("cause"), other.get("reason")):
                return [("finding:policy", f"unreadable image: lean {lean_policy['cause']} {lean_policy.get('reason')} "
                                           f"| leg {other.get('cause')} {other.get('reason')}")]
        if "cause" not in other or (leg not in CODED and other.get("cause") is None):
            return [("agree", "policy-refused")]
        if other.get("cause") == lean_policy["cause"]:
            named = [(key, other_key) for key, other_key in (("field", "field"), ("reason", "policy_reason"))
                     if lean_policy.get(key) and lean_policy["cause"] != "policy:unreadable"]
            if leg in CODED and any(other.get(other_key) != lean_policy[key] for key, other_key in named):
                # one cause per refused policy, and the first problem is the same problem: where the oracle's
                # refusal names a field or a reason, every leg that speaks the registry names the same
                return [("finding:cause", f"policy cause lean {lean_policy['cause']} {lean_policy.get('reason', '')} "
                                          f"{lean_policy.get('field', '')} | leg {other.get('cause')} field "
                                          f"{other.get('field')} {other.get('policy_reason')} {other.get('reason', '')[:120]}")]
            return [("agree", "policy-refused")]
        if lean_policy["cause"] == "policy:engine-counter":
            # the engine's registers are outside the core (spec section 1): the oracle refuses the policy for
            # reading one, the reference and its ports route on them and name the policy's next problem
            return [("scope:engine-counter", "policy")]
        # D7, resolved (spec section 4 and 9): every leg names the first problem in the order of section 4,
        # so a policy both refuse for different causes is a finding
        return [("finding:cause", f"policy cause lean {lean_policy['cause']} {lean_policy.get('reason', '')} "
                                  f"{lean_policy.get('field', '')} | leg {other.get('cause')} {other.get('causes')} "
                                  f"{other.get('reason', '')[:160]}")]
    rows = []
    for lean_v, other_v in zip(lean_row["readings"], other["readings"]):
        a, b = normalize_reading(lean_v), normalize_reading(other_v)
        if "policy_check" in lean_v and "policy_check" in other_v and lean_v["policy_check"] != other_v["policy_check"]:
            rows.append(("finding:policy-check", f"lean {lean_v['policy_check']} vs leg {other_v['policy_check']}"))
        elif "policy_check" in lean_v and b[0] != "crash" and "policy_check" not in other_v and leg in ("python", "rust"):
            rows.append(("finding:policy-check", f"lean {lean_v['policy_check']} vs leg none"))
        if b[0] == "crash":
            rows.append(("finding:crash", b[1]))
        elif b[0] == "policy" and b[1] == "target-limit":
            # D6 on a reading: a value the 32 bit registers cannot hold is refused by the register encoder
            rows.append(("target-limit:reading", f"lean {a}"))
        elif b[0] == "policy" and b[1] == "target-error" and other_v.get("reason") == "e stack" and leg == "c-interp":
            # interp.c's operand stack is 64 deep and it exits on overflow; the driver refuses such an image
            rows.append(("target-limit:stack", f"lean {a}"))
        elif a == b or (a[0] == b[0] == "unreadable" and not READS_CANON2.get(leg, False)):
            rows.append(("agree", a[0]))
        elif a[0] == "unreadable" and a[1] in READER_GAP_SECOND_TIER and not READS_CANON2.get(leg, False):
            rows.append((f"reader-gap:{a[1]}", "reading"))
        else:
            rows.append(("finding:reading", f"lean {a} vs leg {b}"))
    return rows


def run(cases, legs=("python", "rust"), quiet=False):
    """Every case through the oracle and the named legs; the default is the two first tier legs, and
    `ALL_LEGS` adds the second tier kernels and the C table targets."""
    prepare(cases)
    lean = lean_leg(cases)
    results = {name: LEGS[name](cases) for name in legs}
    counts = {name: Counter() for name in legs}
    findings = []
    for case in cases:
        lean_row = lean[case["id"]]
        for name in legs:
            for cls, detail in classify(lean_row, results[name][case["id"]], name):
                counts[name][cls] += 1
                if cls.startswith("finding"):
                    findings.append((name, cls, detail, case))
    return lean, results, counts, findings


# ----------------------------------------------------------------- minimisation
def _still_differs(case, leg, cls, kind=None):
    try:
        _lean, _results, counts, found = run([case], legs=(leg,))
    except Exception:   # noqa: BLE001 - a candidate that breaks a leg is not a reproducer of this finding
        return False
    if kind is None:
        return counts[leg][cls] > 0
    return any(name == leg and found_cls == cls and finding_kind(detail) == kind for name, found_cls, detail, _c in found)


def minimise(case, leg, cls, kind=None):
    """Shrink a disagreeing case: fewer readings, rules, fields and smaller conditions, while it still
    shows the same kind of finding (`finding_kind`) on the same leg."""
    case = dict(case)
    _same = globals()["_still_differs"]

    def _still_differs(candidate, leg, cls):   # noqa: F811 - the same check, held to the finding's kind
        return _same(candidate, leg, cls, kind)
    # readings: keep one that shows it
    for raw in case["readings"]:
        candidate = dict(case, readings=[raw])
        if _still_differs(candidate, leg, cls):
            case = candidate
            break
    try:
        image = json.loads(case["image"].decode("utf-8"))
    except Exception:   # noqa: BLE001 - a text level image is already minimal enough to read
        return case
    if not isinstance(image, dict) or not isinstance(image.get("rules"), list):
        return case

    def with_image(img):
        return dict(case, image=json.dumps(img, ensure_ascii=False).encode("utf-8"))

    changed = True
    while changed:
        changed = False
        for index in range(len(image["rules"])):
            img = dict(image, rules=image["rules"][:index] + image["rules"][index + 1:])
            if _still_differs(with_image(img), leg, cls):
                image, case, changed = img, with_image(img), True
                break
        if changed:
            continue
        if isinstance(image.get("fields"), dict):
            for name in list(image["fields"]):
                img = dict(image, fields={k: v for k, v in image["fields"].items() if k != name})
                if _still_differs(with_image(img), leg, cls):
                    image, case, changed = img, with_image(img), True
                    break
        if changed:
            continue
        for index, rule in enumerate(image["rules"]):
            when = rule.get("when") if isinstance(rule, dict) else None
            if isinstance(when, list) and when and when[0] in ("not", "and", "or"):
                for sub in when[1:]:
                    rules = list(image["rules"])
                    rules[index] = dict(rule, when=sub)
                    img = dict(image, rules=rules)
                    if _still_differs(with_image(img), leg, cls):
                        image, case, changed = img, with_image(img), True
                        break
            if changed:
                break
    return case


def finding_kind(detail: str) -> str:
    """A short stable name for a finding, so a large run reports how many of each it saw."""
    import re
    if detail.startswith("policy cause lean ") and " field " in detail.split("| leg ", 1)[-1][:80]:
        match = re.match(r"policy cause lean (\S+) ", detail)
        return f"policy-field {match.group(1)}" if match else "policy-field"
    if detail.startswith("policy cause lean "):
        match = re.match(r"policy cause lean (\S+) .*\| leg (\S+) ", detail)
        return f"policy-cause {match.group(1)} vs {match.group(2)}" if match else "policy-cause"
    if "policy:not-level-m depth" in detail:
        return "depth-bound-not-applied"
    match = re.search(r"\| field \"[^\"]*\": (.*)$", detail)
    if match:
        text = match.group(1)
        if "\\u{1f}" in text or "\x1f" in text:
            return "definition-whitespace-u001f"
        return "definition:" + re.sub(r'"[^"]*"', "S", re.sub(r"[0-9]+", "N", text))[:60]
    return re.sub(r"[0-9]+", "N", detail)[:80]


def generate(count, seed):
    rng = random.Random(seed)
    return [gen_case(rng, index) for index in range(count)]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--cases", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--legs", default=",".join(ALL_LEGS))
    parser.add_argument("--chunk", type=int, default=5000)
    parser.add_argument("--report", help="write the findings and counts as JSON here")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)
    legs = tuple(args.legs.split(","))
    rng = random.Random(args.seed)
    total = {name: Counter() for name in legs}
    lean_counts = Counter()
    first_findings = {}
    kinds = Counter()
    done = 0
    while done < args.cases:
        size = min(args.chunk, args.cases - done)
        cases = [gen_case(rng, done + index) for index in range(size)]
        lean, _results, counts, findings = run(cases, legs)
        for row in lean.values():
            lean_counts["policy accepted" if row["policy"]["policy"] == "accepted" else "policy refused"] += 1
            for verdict in row["readings"]:
                lean_counts["reading " + (verdict["verdict"] if verdict["verdict"] == "route" else verdict["cause"])] += 1
                if verdict.get("policy_check") == "pass" and verdict.get("cause") == "route:contract-violation":
                    # D4: the system boundary refuses a field no rule reads, which the policy check passes
                    lean_counts["d4: policy check passes, system boundary refuses"] += 1
        for name in legs:
            total[name].update(counts[name])
        for leg, cls, detail, case in findings:
            kind = finding_kind(detail)
            kinds[(leg, kind)] += 1
            first_findings.setdefault((leg, cls, kind), (leg, cls, detail, case))
        done += size
    report = {"cases": args.cases, "seed": args.seed, "lean": dict(lean_counts),
              "legs": {name: dict(total[name]) for name in legs},
              "finding_kinds": {f"{leg} {kind}": count for (leg, kind), count in sorted(kinds.items())},
              "findings": []}
    for (leg, cls, _key), (_leg, _cls, detail, case) in sorted(first_findings.items(), key=lambda item: item[0]):
        small = minimise(case, leg, cls, finding_kind(detail))
        _l, _r, _c, again = run([small], legs=(leg,))
        report["findings"].append({"leg": leg, "class": cls, "kind": finding_kind(detail), "detail": detail,
                                   "reproducer_detail": [found[2] for found in again if found[0] == leg],
                                   "image": small["image"].decode("utf-8", "replace"),
                                   "readings": [raw.decode("utf-8", "replace") for raw in small["readings"]],
                                   "flow": small.get("flow")})
    if args.report:
        Path(args.report).write_text(json.dumps(report, indent=1, ensure_ascii=False) + "\n")
    if not args.quiet:
        print(json.dumps(report, indent=1, ensure_ascii=False)[:20000])
    readings = sum(value for key, value in lean_counts.items() if key.startswith("reading"))
    print(f"core_diff: {args.cases} cases, {readings} readings, seed {args.seed}")
    for name in legs:
        counter = total[name]
        agree = counter["agree"]
        gaps = sum(v for k, v in counter.items() if k.startswith("reader-gap") or k.startswith("scope"))
        excluded = sum(v for k, v in counter.items() if k.startswith("excluded"))
        found = sum(v for k, v in counter.items() if k.startswith("finding"))
        print(f"core_diff: lean vs {name}: {agree} agree, {gaps} reader gaps or scope, {excluded} excluded, {found} findings")
    for (leg, kind), count in sorted(kinds.items()):
        print(f"core_diff: finding {leg} {kind}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
