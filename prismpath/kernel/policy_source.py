# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The readable source of a `prismpath.core/1` policy image, its compiler, and a classifier skeleton.

A core policy image (docs/design/spec-verified-core.md, section 2) is nested JSON. Its readable source, a
rules source, is a dialect of the Markdown flow format of SPEC.md and is specified in SPEC.md section 9. It
starts from the flow text the image already renders to (`core_render.render`, the canonical rendering a core
run stores and the evidence verifier recomputes), with the field definitions of section 4.5 in its front
matter and the Level M conditions of section 4.3 on its rules. It differs from a flow in how a rule names what
it decides: a cause by its registered name instead of its number, so `refuse agent:network` has a space where
a flow edge target cannot. The flow parser therefore refuses a rules source (`kernel/parser.RulesSourceError`)
rather than read its refusals as prose, and only this module reads one.

    ---
    name: agent_rules
    start: core_decision
    field.tool: category
    field.kill_by_pattern: bool
    ---
    ## core_decision
    -> refuse agent:kill-by-pattern: when kill_by_pattern
    -> allow: when tool == "read_file"

  * `field.<name>: <definition>` declares a field, as SPEC.md section 4.5 writes it (`bool`, `category`,
    `int min=1 max=1`, `fixed scale=100 rounding=floor`, with `absent=allowed` where a reading may omit it).
  * Every `-> <target>: <condition>` line under the start section is one rule, in order; the first rule
    whose condition holds decides. The target is `allow`, `refuse <cause name>` or `escalate <cause name>`
    (the name resolves to its code in `prismpath.kernel.causes`, so `refuse agent:kill-by-pattern` is the
    image's `refuse_105`), or another route name for an image that is not an agent's.
  * The condition is `always`, `never`, or `when` and one Level M expression over the declared fields: a
    field alone (true), `==` `!=` `<` `<=` `>` `>=` against a constant, `in` and `not in` a list of
    constants, joined by `and`, `or`, `not` and parentheses. Constants are numbers, strings, `True`,
    `False` and `None`.
  * Any other line under a heading is a note for the reader and is not part of the image.

`compile_source` turns the text into the image's canonical canon/2 bytes and has the image checked by the
port of the Lean oracle (`core_policy`), naming the line of the first problem; `render_source` writes the
source of an image; `render_source(image)` compiled again is the same bytes. `skeleton` writes the start of
a classifier for a source's fields. Standard library and the kernel only.
"""
from __future__ import annotations

import ast
import difflib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from prismpath.kernel import canon2, causes, core_policy, core_render

START = core_render.START
FORMAT = core_policy.FORMAT_TAG
ALWAYS = core_render.ALWAYS
NEVER = core_render.NEVER
DECISIONS = ("refuse", "escalate")
FRONT_KEYS = ("name", "start", "description")
_CODED = re.compile(r"^(refuse|escalate)_(\d+)$")
_READABLE = re.compile(r"^\s*(refuse|escalate)\s+(\S+?):(?:\s+(.*?))?\s*$")
_PLAIN = re.compile(r"^\s*([A-Za-z0-9_\-]+)\s*:\s*(.*?)\s*$")
_EDGE = re.compile(r"^\s*-?\s*->(.*)$")
_HEAD = re.compile(r"^\s*##\s+(.+?)\s*$")
_ANNO = re.compile(r"^\s*@(\w+)\s*\(")
_INT_TEXT = re.compile(r"[0-9]+")
_DEC_TEXT = re.compile(r"(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?")
_OPS = {ast.Eq: "==", ast.NotEq: "!=", ast.Lt: "<", ast.LtE: "<=", ast.Gt: ">", ast.GtE: ">="}
_FLIP = core_render.FLIP

# what each refusal of the core means, in the words of the person who wrote the rule
_CAUSE_WORDS = {
    "policy:shape": "the rule is not a shape the core reads",
    "policy:definition": "the field declaration is not one the core reads",
    "policy:not-level-m": "the rule is outside Level M",
    "policy:engine-counter": "the rule reads an engine counter, which a core policy may not",
    "policy:kind-mismatch": "the rule compares a field with a value of another kind",
    "policy:rounding": "the rule compares a fixed field in a direction its rounding does not carry",
    "policy:threshold": "a number in the rule is not one the field can hold",
    "policy:none": "the rule tests None where the field does not allow it",
    "policy:absence-untested": "the field allows absence but no rule tests it for None",
    "image:unknown-op": "the rule uses an operator the core does not have",
    "image:unknown-type": "the rule uses a value the core does not have",
    "image:field-index-oob": "the rule reads a field that is not declared",
    "policy:unreadable": "the image does not read as canon/2",
    "policy:not-canonical": "the image is not its canonical canon/2 bytes",
}
_REASON_WORDS = {
    "unknown-kind": "the kind must be bool, category, int or fixed",
    "empty": "the declaration is empty",
    "not-option": "an option must be written name=value",
    "option-not-taken": "this kind does not take that option",
    "option-repeated": "an option is written twice",
    "absent": "absent must be refused or allowed",
    "fixed-needs-scale-and-rounding": "a fixed field needs scale= and rounding=",
    "not-integer": "the option needs a whole number",
    "scale": "the scale must be from 1 to 1000000000",
    "rounding": "rounding must be floor, ceiling or exact",
    "range": "min must not exceed max, and both must lie within plus or minus 2^53 minus 1",
    "engine-counter": "visits and error_count are the engine's own counters",
    "name": "a name must be a Python identifier that is not a keyword",
    "depth": "the condition is nested deeper than 50",
    "string-ordering": "a string can only be compared with == or !=",
    "field-vs-field": "a field can only be compared with a constant, not another field",
    "nested-container": "a list cannot hold a list",
    "float": "a decimal number can only be compared with a fixed field",
    "out-of-range": "the number lies outside the field's min and max",
    "constant-range": "the number lies outside the field's min and max",
    "off-grid": "the number has more decimal places than the field's scale",
    "digits": "the number has more digits than an exact threshold carries",
    "ordered": "None can only be tested with == or !=",
    "absence-refused": "the field does not declare absent=allowed",
    "in-list": "None cannot be in a list",
}


class SourceError(ValueError):
    """The source does not compile. `problems` is a list of (line, message), line 0 for the whole source."""

    def __init__(self, problems: List[Tuple[int, str]], path: str = "<source>"):
        self.problems, self.path = problems, path
        super().__init__("\n".join(self.lines()))

    def lines(self) -> List[str]:
        return [f"{self.path}:{line}: {message}" if line else f"{self.path}: {message}"
                for line, message in self.problems]


@dataclass
class Compiled:
    """A compiled source: the image document and its canonical bytes, with the line of each field and rule
    and the warnings worth showing (a rule no reading can reach, a route the agent harness does not act on)."""
    doc: Dict[str, Any]
    image: bytes
    name: str
    field_lines: Dict[str, int]
    rule_lines: List[int]
    warnings: List[Tuple[int, str]] = field(default_factory=list)


# ----------------------------------------------------------------- targets
def cause_target(decision: str, cause_name: str) -> str:
    """`refuse_<code>` or `escalate_<code>` for a registered cause name; KeyError for any other name."""
    code = causes.code(cause_name)
    if code is None or code == causes.CAUSE_NONE:
        raise KeyError(cause_name)
    return f"{decision}_{code}"


def readable_target(target: str) -> str:
    """How the source writes an image's target: `refuse agent:network` for `refuse_106`."""
    match = _CODED.match(target)
    if match:
        name = causes.name(int(match.group(2)))
        if name is None:
            raise core_render.Unrenderable(f"target {target} names no registered cause")
        return f"{match.group(1)} {name}"
    if target in DECISIONS:
        raise core_render.Unrenderable(f"target {target} reads as a decision with no cause")
    return target


def _cause_hint(name: str) -> str:
    near = difflib.get_close_matches(name, [entry[1] for entry in causes._REGISTRY], n=1, cutoff=0.6)
    return f"; did you mean {near[0]}?" if near else ""


# ----------------------------------------------------------------- conditions
class _CondError(Exception):
    pass


def _number(expr: str, node) -> list:
    """A number constant from its source text, so a decimal keeps the spelling the author wrote."""
    sign = ""
    inner = node
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        sign = "-" if isinstance(node.op, ast.USub) else "+"
        inner = node.operand
        whole = ast.get_source_segment(expr, node) or ""
        if not isinstance(inner, ast.Constant) or whole[1:].strip() != (ast.get_source_segment(expr, inner) or ""):
            raise _CondError(f"write the sign directly on the number, not `{whole}`")
    text = ast.get_source_segment(expr, inner) or ""
    if isinstance(inner.value, bool) or not isinstance(inner.value, (int, float)):
        raise _CondError(f"`{text}` is not a number")
    if _INT_TEXT.fullmatch(text):
        value = int(text) * (-1 if sign == "-" else 1)
        if -core_policy.EXACT_LIMIT <= value <= core_policy.EXACT_LIMIT:
            return ["num", value]
        return ["num", str(value)]
    if _DEC_TEXT.fullmatch(text) and any(char in text for char in ".eE"):
        return ["num", sign + text]
    raise _CondError(f"the number `{text}` is not written in plain decimal digits")


def _const(expr: str, node) -> list:
    if isinstance(node, ast.Constant):
        value = node.value
        if value is None:
            return ["none"]
        if isinstance(value, bool):
            return ["bool", value]
        if isinstance(value, str):
            return ["str", value]
        if isinstance(value, (int, float)):
            return _number(expr, node)
        raise _CondError(f"`{ast.get_source_segment(expr, node)}` is not a number, a string, True, False or None")
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        return _number(expr, node)
    if isinstance(node, ast.Name):
        return ["field", node.id]          # the core refuses it (field-vs-field); kept so the check names it
    if isinstance(node, (ast.List, ast.Tuple)):
        raise _CondError("a list cannot hold a list")
    raise _CondError(f"`{ast.get_source_segment(expr, node)}` is not a constant")


def _compare(expr: str, left, op, right) -> list:
    if type(op) in (ast.In, ast.NotIn):
        if not isinstance(left, ast.Name):
            raise _CondError("`in` needs a field on its left")
        if not isinstance(right, (ast.List, ast.Tuple)):
            raise _CondError("`in` needs a list of constants on its right, like [\"a\", \"b\"]")
        return ["in" if isinstance(op, ast.In) else "not in", left.id, [_const(expr, elt) for elt in right.elts]]
    if type(op) not in _OPS:
        raise _CondError("compare with == != < <= > >=, `in` or `not in`")
    symbol = _OPS[type(op)]
    if isinstance(left, ast.Name):
        return ["cmp", left.id, symbol, _const(expr, right)]
    if isinstance(right, ast.Name):
        return ["cmp", right.id, _FLIP[symbol], _const(expr, left)]
    raise _CondError(f"`{ast.get_source_segment(expr, left)} {symbol} {ast.get_source_segment(expr, right)}` "
                     f"does not read a field")


def _cond(expr: str, node) -> list:
    if isinstance(node, ast.BoolOp):
        return ["and" if isinstance(node.op, ast.And) else "or"] + [_cond(expr, value) for value in node.values]
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return ["not", _cond(expr, node.operand)]
    if isinstance(node, ast.Name):
        return ["truthy", node.id]
    if isinstance(node, ast.Compare):
        operands = [node.left] + list(node.comparators)
        pairs = [_compare(expr, operands[at], node.ops[at], operands[at + 1]) for at in range(len(node.ops))]
        return pairs[0] if len(pairs) == 1 else ["and"] + pairs      # a chain, as SPEC.md section 4.3 desugars it
    if isinstance(node, ast.Constant):
        raise _CondError(f"`{ast.get_source_segment(expr, node)}` alone reads no field; write always or never")
    raise _CondError(f"`{ast.get_source_segment(expr, node)}` is not a field, a comparison, `in`, and, or, not")


def parse_condition(text: str) -> list:
    """The image's condition for a rule's condition text (`always`, `never`, `when <expression>`)."""
    trimmed = text.strip()
    lowered = trimmed.lower()
    if lowered in ALWAYS:
        return ["always"]
    if lowered in NEVER:
        return ["never"]
    if not lowered.startswith("when "):
        raise _CondError("the condition must be always, never, or start with when")
    expr = trimmed[5:].strip()
    if expr.lower() in ALWAYS:
        return ["always"]
    if expr.lower() in NEVER:
        return ["never"]
    try:
        node = ast.parse(expr, mode="eval").body
    except SyntaxError as error:
        raise _CondError(f"the expression does not read: {error.msg}") from None
    except (RecursionError, MemoryError):
        raise _CondError("the expression is nested too deeply") from None
    try:
        return _cond(expr, node)
    except RecursionError:
        raise _CondError("the expression is nested too deeply") from None


# ----------------------------------------------------------------- the source
def _target(raw: str, line: int, problems) -> Tuple[Optional[str], Optional[str]]:
    """(target, condition text) of the text after `->`, or (None, None) with a problem recorded."""
    readable = _READABLE.match(raw)
    if readable:
        decision, name, cond = readable.group(1), readable.group(2), readable.group(3) or ""
        try:
            target = cause_target(decision, name)
        except KeyError:
            problems.append((line, f"{name} is not a registered cause name{_cause_hint(name)}"))
            return None, None
        return target, cond
    plain = _PLAIN.match(raw)
    if not plain:
        problems.append((line, "a rule is written `-> allow: when ...`, `-> refuse <cause name>: when ...` or "
                               "`-> escalate <cause name>: when ...`, with a space after the colon"))
        return None, None
    target, cond = plain.group(1), plain.group(2)
    coded = _CODED.match(target)
    if coded:
        name = causes.name(int(coded.group(2)))
        hint = f"write `{coded.group(1)} {name}`" if name else f"code {coded.group(2)} is not registered"
        problems.append((line, f"name the cause, not its number: {hint}"))
        return None, None
    if target in DECISIONS:
        problems.append((line, f"`{target}` needs a cause name: `-> {target} <cause name>: when ...`"))
        return None, None
    return target, cond


def _front(lines: List[str], problems) -> Tuple[Dict[str, Tuple[str, int]], Dict[str, Tuple[str, int]], int]:
    """(front matter keys, field definitions, index of the first body line), each with its line."""
    if not lines or lines[0].strip() != "---":
        problems.append((1, "the source starts with a front matter block between two `---` lines"))
        return {}, {}, 0
    meta: Dict[str, Tuple[str, int]] = {}
    fields: Dict[str, Tuple[str, int]] = {}
    for at in range(1, len(lines)):
        text, line = lines[at], at + 1
        if text.strip() == "---":
            return meta, fields, at + 1
        if not text.strip():
            continue
        if ":" not in text:
            problems.append((line, "a front matter line is `key: value`"))
            continue
        key, value = text.split(":", 1)
        key, value = key.strip(), value.strip(" \t")
        if key.startswith("field."):
            name = key[len("field."):]
            if not name:
                problems.append((line, "a field declaration is `field.<name>: <kind>`"))
            elif name in fields:
                problems.append((line, f"the field {name} is declared twice (first on line {fields[name][1]})"))
            else:
                fields[name] = (value, line)
        elif key in FRONT_KEYS:
            if key in meta:
                problems.append((line, f"`{key}` is written twice"))
            meta[key] = (value.strip(), line)
        else:
            problems.append((line, f"`{key}` is not a front matter key: write field.<name>, name, start or description"))
    problems.append((1, "the front matter has no closing `---` line"))
    return meta, fields, len(lines)


def parse_source(text: str, path: str = "<source>") -> Compiled:
    """The image a source writes, before the core checks it. SourceError names every line it cannot read."""
    problems: List[Tuple[int, str]] = []
    lines = text.replace("\r\n", "\n").split("\n")     # a file saved with Windows line ends reads the same
    meta, fields, body = _front(lines, problems)
    start = meta.get("start", (None, 0))[0]
    if start is not None:
        start = start.lower().replace(" ", "_")
    section: Optional[str] = None
    seen: Dict[str, int] = {}
    rules, rule_lines, warnings = [], [], []
    for at in range(body, len(lines)):
        raw, line = lines[at], at + 1
        head = _HEAD.match(raw)
        if head:
            section = head.group(1).strip().lower().replace(" ", "_")
            if start is None:
                start = section
            if section in seen:
                problems.append((line, f"the section ## {section} appears twice (first on line {seen[section]})"))
            seen[section] = line
            continue
        if _ANNO.match(raw):
            problems.append((line, "annotations are not part of a core policy"))
            continue
        edge = _EDGE.match(raw)
        if not edge:
            continue                              # a note for the reader
        if section is None or section != start:
            where = f"under ## {section}" if section else "before any section"
            problems.append((line, f"a rule {where}: rules belong under ## {start or START}"))
            continue
        target, cond_text = _target(edge.group(1), line, problems)
        if target is None:
            continue
        if not cond_text:
            problems.append((line, "the rule has no condition after its colon"))
            continue
        try:
            cond = parse_condition(cond_text)
        except _CondError as error:
            problems.append((line, str(error)))
            continue
        if rules and rules[-1]["when"] == ["always"]:
            warnings.append((line, f"no reading reaches this rule: the rule on line {rule_lines[-1]} always holds"))
        if target != "allow" and not _CODED.match(target):
            warnings.append((line, f"`{target}` is a route, not allow, refuse or escalate; the agent harness "
                                   f"refuses a policy that names it"))
        rules.append({"target": target, "when": cond})
        rule_lines.append(line)
    if start is not None and start not in seen and not problems:
        problems.append((meta.get("start", (None, 1))[1] or 1, f"there is no ## {start} section to hold the rules"))
    if not rules and not problems:
        warnings.append((0, "the source has no rules: the core refuses every reading (route:no-matching-edge)"))
    if problems:
        raise SourceError(problems, path)
    doc = {"format": FORMAT, "fields": {name: value for name, (value, _line) in fields.items()}, "rules": rules}
    try:
        image = canon2.dumps(doc)
    except canon2.Canon2Error as error:
        line = next((rule_line for rule, rule_line in zip(rules, rule_lines) if not _writable(rule)), 0)
        words = ("the condition is nested too deeply (the core allows a depth of 50)" if error.rule == "depth"
                 else f"the rule has no canon/2 form ({error.rule})")
        raise SourceError([(line, words)], path) from None
    return Compiled(doc, image, meta.get("name", ("", 0))[0], {name: line for name, (_v, line) in fields.items()},
                    rule_lines, warnings)


def _writable(value) -> bool:
    try:
        canon2.dumps(value)
        return True
    except (canon2.Canon2Error, TypeError):
        return False


def _explain(refused: core_policy.Refused) -> str:
    words = _CAUSE_WORDS.get(refused.cause, refused.cause)
    detail = []
    if refused.field:
        detail.append(f"field {refused.field}")
    if refused.reason:
        detail.append(_REASON_WORDS.get(refused.reason, refused.reason))
    return f"{words} ({refused.cause}{': ' + ', '.join(detail) if detail else ''})"


def check(compiled: Compiled, path: str = "<source>") -> None:
    """The oracle's check of the compiled image (`core_policy`, in the order of its `loadPolicy`), with the
    refusal put on the line it is about: a rule's line, or the line declaring the field."""
    doc = compiled.doc

    def fail(line, refused):
        raise SourceError([(line, _explain(refused))], path)

    def field_line(refused, fallback=0):
        return compiled.field_lines.get(refused.field or "", fallback)

    decoded = []
    for rule, line in zip(doc["rules"], compiled.rule_lines):
        try:
            decoded.append(core_policy.decode_rule(rule))
        except core_policy.Refused as refused:
            fail(line, refused)
    try:
        defs = core_policy.parse_defs(list(doc["fields"].items()))
    except core_policy.Refused as refused:
        fail(field_line(refused), refused)
    lowered = []
    for (_target, cond), line in zip(decoded, compiled.rule_lines):
        try:
            lowered.append(core_policy.lower_cond(defs, cond))
        except core_policy.Refused as refused:
            fail(line, refused)
    tested = {name for cond in lowered for name in core_policy.none_tested(cond)}
    for definition in defs:
        if definition["absent_ok"] and definition["name"] not in tested:
            fail(compiled.field_lines.get(definition["name"], 0),
                 core_policy.Refused("policy:absence-untested", definition["name"]))
    refusal = core_policy.load_policy(compiled.image)
    if refusal is not None:                       # every check above passed, so this is not expected
        raise SourceError([(0, f"the core refuses the image: {refusal}")], path)
    from prismpath.kernel.field_definitions import FieldDefinitionError
    from prismpath.kernel.parser import parse
    try:
        parse(core_render.render(doc))            # the reference kernel reads what the oracle accepts
    except FieldDefinitionError as error:
        raise SourceError([(0, f"the reference kernel refuses the image: {error}")], path) from None


def compile_source(text: str, path: str = "<source>", *, checked: bool = True) -> bytes:
    """The canonical canon/2 bytes of the image a source writes (no line feed). With `checked`, the default,
    the core must accept the image; `checked=False` only lowers the text, for a refused image's round trip."""
    compiled = parse_source(text, path)
    if checked:
        check(compiled, path)
    return compiled.image


def compile_full(text: str, path: str = "<source>") -> Compiled:
    compiled = parse_source(text, path)
    check(compiled, path)
    return compiled


# ----------------------------------------------------------------- rendering
def read_image(raw) -> Dict[str, Any]:
    """An image document from its bytes (canonical, with or without the file's final line feed) or a dict."""
    if isinstance(raw, dict):
        return raw
    if raw.endswith(b"\n") and not raw.endswith(b"\n\n"):
        raw = raw[:-1]
    return canon2.loads(raw)


def render_source(image) -> str:
    """The source of an image: its canonical flow rendering (`core_render.render`) with each rule's cause
    named by its registered name. Raises core_render.Unrenderable for an image the source cannot carry."""
    doc = read_image(image)
    fields = doc.get("fields") if isinstance(doc, dict) else None
    for name, text in (fields.items() if isinstance(fields, dict) else ()):
        if isinstance(text, str) and (text != text.strip(" \t") or name != name.strip(" \t")):
            raise core_render.Unrenderable("definition")   # the source trims a declaration, so it cannot carry these
    flow = core_render.render(doc)
    lines = flow.split("\n")
    head = lines.index(f"## {START}")
    out = lines[:head + 1]
    for offset, rule in enumerate(doc["rules"]):
        text = lines[head + 1 + offset]
        prefix = f"-> {rule['target']}: "
        assert text.startswith(prefix), text
        out.append(f"-> {readable_target(rule['target'])}: {text[len(prefix):]}")
    return "\n".join(out) + "\n"


# ----------------------------------------------------------------- the classifier skeleton
def _compared(doc) -> Dict[str, List[Any]]:
    """Per field, the constants the rules compare it with, in first use order."""
    seen: Dict[str, List[Any]] = {}

    def walk(cond):
        tag = cond[0]
        if tag == "cmp":
            add(cond[1], [cond[3]])
        elif tag in ("in", "not in"):
            add(cond[1], cond[2])
        elif tag == "not":
            walk(cond[1])
        elif tag in ("and", "or"):
            for operand in cond[1:]:
                walk(operand)

    def add(name, consts):
        bucket = seen.setdefault(name, [])
        for const in consts:
            value = const[1] if len(const) > 1 else None
            if value not in bucket:
                bucket.append(value)

    for rule in doc["rules"]:
        walk(rule["when"])
    return seen


def _conservative(definition: dict):
    """The value a reading holds when the classifier cannot say: absence where the field allows it, else
    `unknown` for a category, False for a bool, and the lowest value a number field accepts (0 when that is
    in range)."""
    if definition["absent_ok"]:
        return None
    kind = definition["kind"]
    if kind == "category":
        return "unknown"
    if kind == "bool":
        return False
    return 0 if definition["lo"] <= 0 <= definition["hi"] else definition["lo"]


def skeleton(text: str, module: str, source_ref: str, path: str = "<source>") -> Tuple[str, str]:
    """(module text, test text): a classifier skeleton for a source's fields and the tests it starts with."""
    compiled = compile_full(text, path)
    defs = core_policy.parse_defs(list(compiled.doc["fields"].items()))
    compared = _compared(compiled.doc)
    title = compiled.name or module
    source_name = source_ref.replace("\\", "/").rsplit("/", 1)[-1]
    width = max([len(d["name"]) for d in defs] + [4]) + 2
    listing, values, todo = [], [], []
    for d in defs:
        about = compiled.doc["fields"][d["name"]]
        used = compared.get(d["name"], [])
        if d["kind"] == "category" and used:
            about += ": " + " | ".join(sorted(str(value) for value in used if value is not None))
        listing.append(f"  {d['name']:<{width}}{about}")
        values.append(f"        {d['name']!r}: {_conservative(d)!r},")
        todo.append(f"    # reading[{d['name']!r}] = ...")
    doc_listing = "\n".join(listing) if listing else "  (the source declares no fields)"
    module_text = f'''"""The classifier for the `{title}` policy: one raw call read into the typed fields the policy routes on.

This is TRUSTED CODE OUTSIDE THE VERIFIED CORE. The core (docs/design/spec-verified-core.md) decides one
reading against one signed policy image, and what is proved about that decision is proved about the
reading it is given. Whether the reading says truthfully what the call would do is this module's job
alone: a reading that understates what a call would do is allowed by a perfectly correct core. So keep it
small, deterministic (the same call and the same state give the same reading), conservative (a call it
cannot read is the unknown reading, never a guess), and tested on its own.

Every reading holds every field the policy defines, with no float and only the kinds the policy declares
(the values after a category are the ones the rules compare it with):

{doc_listing}

Written by `prismpath policy skeleton` from {source_name}. It is a starting point, not a classifier:
until `_classify` sets the fields from the call, every call is the unknown reading, every field at its
most conservative value.
"""
from __future__ import annotations

from typing import Any, Dict


def unknown_reading() -> Dict[str, Any]:
    """The reading of a call this classifier cannot read: every field at its most conservative value."""
    return {{
{chr(10).join(values)}
    }}


def classify(call: Any, config: Any) -> Dict[str, Any]:
    """The reading of one proposed call. Never raises: any call it cannot read in full is the unknown
    reading."""
    try:
        return _classify(call, config)
    except Exception:   # noqa: BLE001 - a classifier failure must fail closed, never open
        return unknown_reading()


def _classify(call: Any, config: Any) -> Dict[str, Any]:
    reading = unknown_reading()
    # Set each field from the call, and leave a field at its unknown value whenever the call does not say.
{chr(10).join(todo)}
    return reading
'''
    test_text = f'''"""The first tests of the `{module}` classifier, written by `prismpath policy skeleton` from
{source_name}. Add a case for every kind of call the classifier reads, with the reading it must give."""
import importlib.util
from pathlib import Path

from prismpath.kernel import canon2, core_reference, core_render, policy_source
from prismpath.kernel.parser import parse

HERE = Path(__file__).resolve().parent
SOURCE = HERE / {source_ref!r}
FIELDS = {sorted(compiled.doc["fields"])!r}

_spec = importlib.util.spec_from_file_location({module!r}, HERE / {module + ".py"!r})
classifier = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(classifier)


def decide(reading):
    """The core's verdict on a reading, under the policy compiled from its source."""
    image = policy_source.compile_source(SOURCE.read_text(encoding="utf-8"), str(SOURCE))
    graph = parse(core_render.render(canon2.loads(image)))
    return core_reference.python_reading(graph, canon2.dumps(reading))


def test_a_reading_holds_every_declared_field():
    assert sorted(classifier.classify({{}}, None)) == FIELDS


def test_a_call_it_cannot_read_is_the_unknown_reading():
    for call in (None, {{}}, [], "", {{"tool": object()}}):
        assert classifier.classify(call, None) == classifier.unknown_reading()


def test_the_unknown_reading_passes_the_boundary():
    verdict = decide(classifier.unknown_reading())
    assert verdict.get("cause") != "route:contract-violation", verdict


def test_the_unknown_reading_is_never_allowed():
    verdict = decide(classifier.unknown_reading())
    assert verdict["verdict"] == "refuse" or verdict["target"] != "allow", verdict
'''
    return module_text, test_text


# ----------------------------------------------------------------- command line
def add_parser(subparsers) -> None:
    """`prismpath policy compile | render | skeleton`."""
    policy_parser = subparsers.add_parser(
        'policy', help='Write a core policy as readable rules: compile the rules to the signed image\'s '
                       'canonical bytes, render an image back to rules, start a classifier for the fields')
    actions = policy_parser.add_subparsers(dest='policy_action', metavar='<action>', required=True)
    compile_parser = actions.add_parser('compile', help='compile a rules source to its prismpath.core/1 image, '
                                                        'checked by the core, in canonical canon/2 bytes')
    compile_parser.add_argument('source', help='the rules source (.rules.md)')
    compile_parser.add_argument('-o', '--out', default=None, help='write the image here (default standard output)')
    render_parser = actions.add_parser('render', help='write the rules source of a prismpath.core/1 image')
    render_parser.add_argument('image', help='the image (.core.json, or any canon/2 spelling of it)')
    render_parser.add_argument('-o', '--out', default=None, help='write the source here (default standard output)')
    skeleton_parser = actions.add_parser('skeleton', help='write a classifier skeleton and its first tests for a '
                                                          'rules source\'s fields')
    skeleton_parser.add_argument('source', help='the rules source (.rules.md)')
    skeleton_parser.add_argument('-o', '--out', required=True, help='the module to write (module.py)')
    skeleton_parser.add_argument('--test', default=None, help='the test to write (default test_<module>.py beside it)')
    skeleton_parser.add_argument('--force', action='store_true', help='overwrite files that exist')
    policy_parser.set_defaults(func=policy_cmd)


def _write(path: str, data: bytes) -> None:
    from prismpath import canon
    canon.atomic_write_bytes(path, data)


def policy_cmd(args) -> int:
    import os
    import sys

    def refuse(lines):
        for text in lines:
            print(f"prismpath policy {args.policy_action}: {text}", file=sys.stderr)
        return 2

    if args.policy_action == 'render':
        try:
            with open(args.image, "rb") as handle:
                raw = handle.read()
        except OSError as error:
            return refuse([f"{args.image}: {error.strerror}"])
        try:
            try:
                doc = read_image(raw)
            except canon2.Canon2Error as error:
                if error.rule != "not-canonical":
                    raise
                doc = canon2.loads(canon2.canonicalize(raw))
            text = render_source(doc)
        except canon2.Canon2Error as error:
            return refuse([f"{args.image} is not a canon/2 document ({error.rule})"])
        except (core_render.Unrenderable, KeyError, TypeError, ValueError) as error:
            return refuse([f"{args.image} has no rules source: {error}"])
        if args.out:
            _write(args.out, text.encode("utf-8"))
        else:
            sys.stdout.write(text)
        return 0

    try:
        with open(args.source, encoding="utf-8") as handle:
            text = handle.read()
    except (OSError, UnicodeDecodeError) as error:
        return refuse([f"{args.source}: {getattr(error, 'strerror', None) or error}"])
    try:
        if args.policy_action == 'compile':
            compiled = compile_full(text, args.source)
        else:
            module = os.path.splitext(os.path.basename(args.out))[0]
            test_path = args.test or os.path.join(os.path.dirname(args.out) or ".", f"test_{module}.py")
            if not module.isidentifier():
                return refuse([f"{args.out}: a module name must be a Python identifier"])
            existing = [p for p in (args.out, test_path) if os.path.exists(p)]
            if existing and not args.force:
                return refuse([f"{p} exists; pass --force to overwrite it" for p in existing])
            source_ref = os.path.relpath(os.path.abspath(args.source), os.path.dirname(os.path.abspath(test_path)))
            if source_ref.startswith(os.pardir + os.sep + os.pardir):
                source_ref = os.path.abspath(args.source)      # far away: the test names it outright
            module_text, test_text = skeleton(text, module, source_ref.replace(os.sep, "/"), args.source)
            _write(args.out, module_text.encode("utf-8"))
            _write(test_path, test_text.encode("utf-8"))
            print(f"wrote {args.out} and {test_path}", file=sys.stderr)
            return 0
    except SourceError as error:
        return refuse(error.lines())
    for line, message in compiled.warnings:
        print(f"prismpath policy compile: {args.source}:{line}: warning: {message}", file=sys.stderr)
    if args.out:
        _write(args.out, compiled.image + b"\n")
    else:
        sys.stdout.buffer.write(compiled.image + b"\n")
        sys.stdout.flush()
    return 0
