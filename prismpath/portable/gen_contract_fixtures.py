# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Freeze the worker output CONTRACT as language neutral vectors, generated from the Python reference
(`prismpath/kernel/contract.py`) so the Rust port is measured against it case by case.

    python -m prismpath.portable.gen_contract_fixtures    ->  conformance/contract.json

Two lists:
  * `derive`: a flow document and, from `derive_contract`, every node's fields in the order the node's
    edges first read them as `[field, spec]` pairs (a JSON object would lose that order, and the order is
    what the type gate reports violations in), the JSON Schema `to_json_schema` gives each node, and the
    text `describe` renders.
  * `validate`: a flow, one of its nodes and a worker output with the problems `validate_output` finds,
    in order. The engine stops only on the `type:` kind.

Every predicate here parses in the engine's own sandbox grammar or is deliberately outside it, because the
contract reads each `when` edge with `ast.parse` and so sees what the sandbox refuses (`f(y)`, `x.y`, a
sign on a field). One case pins each of the places the contract and the sandbox read an expression
differently. The integer literal beyond 2^53 minus 1 and the float beyond the double range that Rust refuses
are not here: Python derives them and Rust returns an error (DIVERGENCES.md).
"""
from __future__ import annotations

import json
import sys
import warnings
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from prismpath.kernel import contract  # noqa: E402
from prismpath.kernel.parser import parse  # noqa: E402

OUT = HERE / "conformance" / "contract.json"
VERSION = 1


def _flow(*nodes: str, name: str = "c", start: str = "n") -> str:
    """A flow document from node blocks; each block is `## name` then its edge lines."""
    return f"---\nname: {name}\nstart: {start}\n---\n" + "\n".join(nodes)


def _node(name: str, *edges: str) -> str:
    lines = "\n".join(f"-> t: {edge}" for edge in edges)
    return f"## {name}\nDo the work.\n{lines}\n" if edges else f"## {name}\nDone.\n"


# (name, flow): one node `n` per case unless the case needs more
DERIVE = [
    ("bare-name-is-boolean", _flow(_node("n", "when tests_pass"), _node("t"))),
    ("not-and-or-operands-are-boolean", _flow(_node("n", "when a and not b", "when c or d"), _node("t"))),
    ("bool-literal-equality", _flow(_node("n", "when flag == True", "when other != False"), _node("t"))),
    ("string-equality-is-an-enum", _flow(_node("n", 'when action == "contain"', "when action != 'ignore'"), _node("t"))),
    ("in-a-string-list-is-an-enum", _flow(_node("n", 'when action in ["a", "b"]', 'when action in ("c", "a")'), _node("t"))),
    ("ordering-is-a-ranged-number", _flow(_node("n", "when score >= 0.8", "when score < 3"), _node("t"))),
    ("numeric-enum", _flow(_node("n", "when priority == 3", "when priority in [1, 2]"), _node("t"))),
    ("a-ranged-number-has-no-closed-set", _flow(_node("n", "when level == 3", "when level > 9"), _node("t"))),
    ("an-integer-and-a-float-of-one-value-are-one-value", _flow(_node("n", "when x == 1 or x == 1.0 or x == 2.5"), _node("t"))),
    ("a-float-first-keeps-the-float", _flow(_node("n", "when x == 1.0 or x == 1"), _node("t"))),
    ("number-spellings", _flow(_node("n", "when x == 0x10 or x == 1_000 or x == 1e3 or x == 0o17 or x == 0b11"), _node("t"))),
    ("a-mixed-set-sorts-floats-then-ints-then-strings", _flow(_node("n", 'when x == "b" or x == 2 or x == 1.5 or x == "a" or x == 1'), _node("t"))),
    ("conflict-boolean-then-number", _flow(_node("n", "when flag", "when flag > 3"), _node("t"))),
    ("conflict-enum-then-number", _flow(_node("n", 'when x == "a"', "when x == 3"), _node("t"))),
    ("a-membership-in-a-name-types-nothing", _flow(_node("n", "when x in y"), _node("t"))),
    ("a-mixed-list-is-unknown", _flow(_node("n", 'when x in [1, "a"]'), _node("t"))),
    ("an-empty-list-is-unknown", _flow(_node("n", "when x in []", "when y not in ()"), _node("t"))),
    ("a-list-of-none-adds-no-type", _flow(_node("n", "when x in [None]"), _node("t"))),
    ("a-list-of-booleans-is-boolean", _flow(_node("n", "when x in [True, False]"), _node("t"))),
    ("none-and-ellipsis-equality-type-nothing", _flow(_node("n", "when x == None", "when y == ..."), _node("t"))),
    ("is-types-nothing", _flow(_node("n", "when x is None", "when y is not None"), _node("t"))),
    ("engine-fields-are-not-the-workers", _flow(_node("n", "when visits < 3 and error_count > 1 and error and error_type == 'x' and error_message", "when real"), _node("t"))),
    ("chained-comparison", _flow(_node("n", "when 1 < x < 5", "when a <= b <= c"), _node("t"))),
    ("two-names-type-the-left", _flow(_node("n", "when a == b"), _node("t"))),
    ("a-constant-on-the-left", _flow(_node("n", "when 3 < x", 'when "hi" == y'), _node("t"))),
    ("a-parenthesised-name", _flow(_node("n", "when (flag)", "when ((a)) and (not (b))"), _node("t"))),
    ("a-bool-op-in-an-operand-is-not-walked", _flow(_node("n", "when (a and b) == c"), _node("t"))),
    ("a-list-element-is-not-walked", _flow(_node("n", "when x in [a, b]"), _node("t"))),
    ("a-bare-tuple-types-nothing", _flow(_node("n", "when x, y"), _node("t"))),
    ("a-signed-integer-literal-is-a-number", _flow(_node("n", "when x == -3", "when y in [-3, -1, 2]", "when z == +7"), _node("t"))),
    ("a-signed-integer-literal-folds-like-the-engine-does", _flow(_node("n", "when a == -(-3)", "when b == -(5)", "when c == +-4", "when d != - 2", "when -3 == e"), _node("t"))),
    ("a-signed-float-or-field-or-bool-does-not-fold", _flow(_node("n", "when a == -1.5", "when b == -c", "when d == -True", "when e in [-1, -2.5]", "when f == ~3", "when g == -3 ** 2"), _node("t"))),
    ("a-signed-literal-still-gives-an-ordering-type", _flow(_node("n", "when x >= -5", "when -1 < y", "when z >= -0.5"), _node("t"))),
    ("a-call-is-not-walked-but-its-sibling-is", _flow(_node("n", "when f(x) > 3 and y"), _node("t"))),
    ("an-attribute-or-arithmetic-operand", _flow(_node("n", "when x.y == 1 and z", "when w + 1 > 2 and v", "when u == x + 1"), _node("t"))),
    ("a-subscript-and-a-conditional", _flow(_node("n", "when a[0] == 1 and b", "when (c if d else e) == 1 and f"), _node("t"))),
    ("a-comment-after-the-predicate", _flow(_node("n", "when x > 3 # large"), _node("t"))),
    ("a-comprehension-is-opaque", _flow(_node("n", "when x in [i for i in y] and z"), _node("t"))),
    ("a-lambda-is-opaque", _flow(_node("n", "when (lambda q: q)(1) and z"), _node("t"))),
    ("adjacent-strings-are-one-constant", _flow(_node("n", 'when x == "ab" "cd"'), _node("t"))),
    ("string-escapes", _flow(_node("n", r'when x == "a\tb" or x == "\x41" or x == "é" or x == r"\n" or x == "q\qq"'), _node("t"))),
    ("bytes-and-complex-constants-type-nothing", _flow(_node("n", 'when x == b"a"', "when y == 1j"), _node("t"))),
    ("a-fstring-is-opaque", _flow(_node("n", 'when x == f"{y}" and z'), _node("t"))),
    ("unicode-names", _flow(_node("n", 'when niño == "sí" and café'), _node("t"))),
    ("a-hard-keyword-name-is-a-syntax-error", _flow(_node("n", 'when class == "a" and z', "when ok"), _node("t"))),
    ("an-unparseable-predicate-is-skipped", _flow(_node("n", "when x ==", "when (a", "when ok"), _node("t"))),
    ("a-leading-zero-integer-is-a-syntax-error", _flow(_node("n", "when x == 007 and z", "when ok"), _node("t"))),
    ("keyword-edges-are-skipped", _flow(_node("n", "always", "else", "never", "when always", "when ok"), _node("t"))),
    ("semantic-error-and-event-edges-are-not-read", _flow(_node("n", "the answer is right", "on error when error_count > 2", "on event done", "on timeout", "when ok"), _node("t"))),
    ("a-node-with-no-edges", _flow(_node("n"), name="leaf")),
    ("two-nodes-and-document-order", _flow(_node("n", "when b and a"), _node("m", "when a == 1", "when c"), _node("t"))),
    ("the-same-field-on-two-edges-unions-its-values", _flow(_node("n", 'when a == "x"', 'when a == "y"', 'when a in ["y", "z"]'), _node("t"))),
    ("field-order-follows-the-edges", _flow(_node("n", "when zed", "when alpha > 1 and mid"), _node("t"))),
    ("case-is-kept-in-field-names", _flow(_node("n", "when Flag and flag"), _node("t"))),
    ("a-nested-not", _flow(_node("n", "when not not a", "when not (b == 3)"), _node("t"))),
    ("a-top-level-ternary-is-opaque", _flow(_node("n", "when a if b else c"), _node("t"))),
    ("a-power-and-bitwise-operand", _flow(_node("n", "when a | b > 1 and c", "when d ** 2 == 4 and e"), _node("t"))),
    ("a-negative-float-ordering-and-a-dict-operand", _flow(_node("n", "when x > 1.5e300", "when {1: 2} == y"), _node("t"))),
]

# (case name, derive case name, node, worker output): the problems validate_output finds
VALIDATE = [
    ("ok", "string-equality-is-an-enum", "n", {"text": "t", "action": "contain"}),
    ("wrong-type-boolean", "bare-name-is-boolean", "n", {"text": "t", "tests_pass": "yes"}),
    ("wrong-type-number-is-a-string", "ordering-is-a-ranged-number", "n", {"score": "high"}),
    ("wrong-type-number-is-a-bool", "ordering-is-a-ranged-number", "n", {"score": True, "x": 1}),
    ("wrong-type-enum-is-a-number", "string-equality-is-an-enum", "n", {"action": 7}),
    ("wrong-type-enum-is-a-list", "string-equality-is-an-enum", "n", {"action": ["a", "b"]}),
    ("wrong-type-with-a-quote-in-the-value", "string-equality-is-an-enum", "n", {"action": {"it's": "a \"b\""}}),
    ("a-float-where-a-boolean-is-read", "bare-name-is-boolean", "n", {"tests_pass": 2.5}),
    ("a-null-is-not-a-type-error", "bare-name-is-boolean", "n", {"tests_pass": None}),
    ("a-missing-field-is-a-soft-note", "bare-name-is-boolean", "n", {"text": "t"}),
    ("an-unrouted-enum-value", "string-equality-is-an-enum", "n", {"action": "other"}),
    ("an-unrouted-numeric-enum-value", "numeric-enum", "n", {"priority": 9}),
    ("a-routed-numeric-enum-value", "numeric-enum", "n", {"priority": 3}),
    ("a-null-where-an-enum-is-routed", "string-equality-is-an-enum", "n", {"action": None}),
    ("a-null-where-a-numeric-enum-is-routed", "numeric-enum", "n", {"priority": None}),
    ("two-problems-in-field-order", "field-order-follows-the-edges", "n", {"zed": 1, "alpha": "x"}),
    ("a-conflict-field-takes-the-first-type", "conflict-enum-then-number", "n", {"x": "a"}),
    ("a-mixed-set-note-lists-every-value", "a-mixed-set-sorts-floats-then-ints-then-strings", "n", {"x": "zzz"}),
    ("an-integer-is-routed-by-a-float-of-the-same-value", "an-integer-and-a-float-of-one-value-are-one-value", "n", {"x": 1}),
    ("unknown-type-is-not-constrained", "a-membership-in-a-name-types-nothing", "n", {"x": {"any": [1]}}),
    ("a-signed-routed-value-is-routed", "a-signed-integer-literal-is-a-number", "n", {"x": -3, "y": -1, "z": 7}),
    ("a-signed-unrouted-value-is-a-note", "a-signed-integer-literal-is-a-number", "n", {"x": -2, "y": 0, "z": -7}),
    ("a-node-with-no-contract", "a-node-with-no-edges", "n", {"anything": 1}),
]


def _pairs(graph) -> dict:
    """{node: [[field, spec], ...]} in Python's insertion order."""
    derived = contract.derive_contract(graph)
    return {node: [[field, spec] for field, spec in fields.items()] for node, fields in derived.items()}


def generate() -> dict:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")    # the unknown escape and the leading zero are the point
        derive = []
        by_name = {}
        for name, flow in DERIVE:
            graph = parse(flow)
            derived = contract.derive_contract(graph)
            by_name[name] = (flow, derived)
            derive.append({
                "name": name,
                "flow": flow,
                "contract": _pairs(graph),
                "schemas": {node: contract.to_json_schema(fields) for node, fields in derived.items()},
                "describe": contract.describe(derived),
            })
        validate = []
        for name, derive_name, node, fields in VALIDATE:
            flow, derived = by_name[derive_name]
            validate.append({
                "name": name,
                "flow": flow,
                "node": node,
                "fields": fields,
                "problems": contract.validate_output(derived.get(node, {}), fields),
            })
    return {
        "version": VERSION,
        "note": "contract.derive_contract, to_json_schema, describe and validate_output from the Python reference. "
                "`contract` lists [field, spec] pairs in the order the node's edges first read them; any "
                "implementation must reproduce each list, each schema, each description and each problem, in order.",
        "derive": derive,
        "validate": validate,
    }


def main() -> int:
    doc = generate()
    OUT.write_text(json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {OUT}  ({len(doc['derive'])} derive cases, {len(doc['validate'])} validate cases)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
