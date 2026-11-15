# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A `prismpath.core/1` policy image rendered as the flow text the reference kernel parses
(docs/design/spec-verified-core.md, sections 2 and 11).

The image is a canon/2 document in the core's abstract syntax; the kernels read flows, not images. `render`
writes the flow text an image means, or raises `Unrenderable` for an image with no faithful rendering. Only
the shape needed to write the text is checked here; every rule of the core is left to the kernel that parses
it. `render(doc, rng)` takes a random source and lets it choose among spellings that mean the same flow (a
flipped comparison, a chain, a tuple for a list, `else` for `always`, optional parentheses and spaces), which
is how the differential harness (`formal/diff/core_diff.py`, which imports this module) exercises every
parser on many spellings of one image. With no random source it writes the image's **canonical rendering**,
the plainest spelling of each choice, which is a function of the image alone.

The canonical rendering is what a core run stores beside each image (`cases.jsonl`, its `flow`), and
`flow_of` is how a producer writes it and how the evidence verifier (`prismpath.ledgers.core_evidence`)
recomputes it, so a run whose stored flow is not the rendering of its signed image is refused: the reference
decides from the flow, and a flow edited away from the image would have it decide another policy than the one
the authority signed. One implementation for the producer, the verifier and the differential. Standard
library and the kernel's canon/2 reader only.
"""
from __future__ import annotations

import re

FORMAT = "prismpath.core/1"
START = "core_decision"
ALWAYS = {"always", "true", "else", "otherwise", "default", "_"}
NEVER = {"false", "never"}
FLIP = {"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "!=": "!="}


class _Canonical:
    """The random source of the canonical rendering: every choice takes its plainest branch. Each choice in
    `render` takes the plain spelling when the draw is at least its threshold (0.1 for parentheses, 0.25 for
    a flipped comparison, 0.3 for a tuple or a chain, 0.5 for another word for `always`) and a space below
    0.8, so a constant draw of 0.5 is the plain spelling throughout; `choice` is never reached at 0.5."""

    def random(self):
        return 0.5

    def choice(self, items):
        return items[0]


CANONICAL = _Canonical()


class Unrenderable(Exception):
    pass


def _ident(name) -> bool:
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


def render(doc, rng=None) -> str:
    """The flow text an image means, or Unrenderable; with no `rng`, its canonical rendering. Only the shape
    needed to write the text is checked here; every rule of the core is left to the implementation under test."""
    rng = CANONICAL if rng is None else rng
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


def flow_of(image: bytes):
    """(flow, why) for an image's bytes: its canonical rendering and None, or None and why it has none
    (`unreadable:<rule>` for bytes the canon/2 reader refuses, `unrenderable:<what>` for a document with no
    faithful rendering)."""
    from prismpath.kernel import canon2
    try:
        doc = canon2.loads(image)
    except canon2.Canon2Error as error:
        return None, f"unreadable:{error.rule}"
    except RecursionError:
        return None, "unreadable:recursion"
    try:
        return render(doc), None
    except Unrenderable as why:
        return None, f"unrenderable:{why}"
    except RecursionError:
        return None, "unrenderable:recursion"
