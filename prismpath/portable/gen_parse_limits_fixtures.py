# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Freeze the flow parser's INPUT BOUNDS as language neutral vectors, generated from the Python reference
(`prismpath/kernel/parser.py`: MAX_FLOW_BYTES, MAX_NODES, MAX_EDGES and the `ParseError` it raises) so the
Rust parser is measured against it case by case.

    python -m prismpath.portable.gen_parse_limits_fixtures    ->  conformance/parse_limits.json

Three lists:
  * `cases`: a flow document, the bounds it is parsed under (the three caps, small ones so a case stays a few
    lines) and the outcome: `{"ok": true, "start", "nodes": [[name, edge count], ...] in document order}` or
    `{"error": <ParseError message>, "error_class": "ParseError"}`. One case sits exactly at each cap and one
    just over it, and the rest pin where the reference counts: characters and not bytes, distinct node names
    and not headings, edge lines under a heading and not the ones before the first, the order the document
    reaches the caps in, and a cap of zero or below.
  * `defaults`: documents built from a rule (`kind` and `count`) and parsed under the default caps, a
    document exactly at each default cap and one just over, so a size too large to store is stated by the
    rule that builds it: `nodes` is `## n0` to `## n<count-1>`, `edges` is a heading and `count` edge lines,
    and `characters` is a heading and filler to `count` characters in all.
  * `env`: strings an environment variable may hold and what Python's `int()` makes of each (the reference
    reads its caps with it, once, when the module is imported); the Rust crate must read the same value or
    refuse it. The digits of other scripts and an integer beyond 64 bits are Python integers the crate refuses
    and are not here (DIVERGENCES.md).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from prismpath.kernel import parser  # noqa: E402

OUT = HERE / "conformance" / "parse_limits.json"
VERSION = 1


def _limits(*, size: int = 10_000, nodes: int = 100, edges: int = 100) -> dict:
    return {"max_flow_bytes": size, "max_nodes": nodes, "max_edges": edges}


def _case(name: str, flow: str, limits: dict) -> tuple:
    return name, flow, limits


def _at_and_over(name: str, text: str) -> list:
    """The document at a size cap of exactly its length (accepted) and at one character under it (refused)."""
    return [_case(f"{name}-at-the-cap", text, _limits(size=len(text))),
            _case(f"{name}-one-over-the-cap", text, _limits(size=len(text) - 1))]


CASES = [
    # -- the size, in characters: each document is parsed at a cap of exactly its length and one under it
    *_at_and_over("size-plain", "## a\nxx"),
    *_at_and_over("size-two-byte-characters-count-once", "## a\n\u00e9\u00e9\u00e9"),
    *_at_and_over("size-an-astral-character-counts-once", "## a\n\U0001f600\U0001f600\U0001f600"),
    *_at_and_over("size-front-matter-counts", "---\nname: x\n---\n## a\n"),
    *_at_and_over("size-carriage-returns-count", "## a\r\n-> b: x\r\n"),
    _case("size-empty-document-at-a-cap-of-zero", "", _limits(size=0)),
    _case("size-one-character-over-a-cap-of-zero", "x", _limits(size=0)),
    _case("size-empty-document-over-a-negative-cap", "", _limits(size=-1)),
    _case("size-is-checked-before-the-nodes", "## a\n## b\n## c\n", _limits(size=5, nodes=1)),
    _case("size-is-checked-before-the-edges", "## a\n-> b: x\n-> c: y\n", _limits(size=5, edges=1)),
    # -- the nodes, distinct names
    _case("nodes-exactly-at-the-cap", "## a\n## b\n## c\n", _limits(nodes=3)),
    _case("nodes-one-over-the-cap", "## a\n## b\n## c\n## d\n", _limits(nodes=3)),
    _case("nodes-a-repeated-heading-is-not-a-new-node", "## a\n## b\n## a\n", _limits(nodes=2)),
    _case("nodes-a-repeated-heading-then-a-new-one", "## a\n## b\n## a\n## c\n", _limits(nodes=2)),
    _case("nodes-names-are-lowered-and-spaces-become-underscores", "## A B\n## a_b\n## a b\n", _limits(nodes=1)),
    _case("nodes-two-spellings-of-two-names", "## A B\n## c\n## a_b\n", _limits(nodes=2)),
    _case("nodes-a-cap-of-zero-and-no-heading", "text only\n", _limits(nodes=0)),
    _case("nodes-a-cap-of-zero-and-one-heading", "## a\n", _limits(nodes=0)),
    _case("nodes-a-cap-of-one-and-one-heading", "## a\n-> a: x\n", _limits(nodes=1)),
    _case("nodes-a-negative-cap", "## a\n", _limits(nodes=-1)),
    _case("nodes-three-hashes-are-not-a-heading", "## a\n### b\n### c\n", _limits(nodes=1)),
    _case("nodes-a-heading-of-only-spaces-is-a-node-with-an-empty-name", "## a\n##   \n", _limits(nodes=1)),
    _case("nodes-two-hashes-alone-are-not-a-heading", "## a\n##\n##x\n", _limits(nodes=1)),
    _case("nodes-front-matter-names-are-not-nodes", "---\nname: x\nstart: a\n---\n## a\n## b\n", _limits(nodes=2)),
    # -- the edges, lines that match the edge pattern under a heading
    _case("edges-exactly-at-the-cap", "## a\n-> b: x\n-> c: y\n-> d: z\n", _limits(edges=3)),
    _case("edges-one-over-the-cap", "## a\n-> b: x\n-> c: y\n-> d: z\n-> e: w\n", _limits(edges=3)),
    _case("edges-are-counted-across-nodes", "## a\n-> b: x\n-> c: y\n## b\n-> a: z\n", _limits(edges=2)),
    _case("edges-before-the-first-heading-are-not-counted", "-> a: x\n-> b: y\n-> c: z\n## a\n-> b: w\n", _limits(edges=1)),
    _case("edges-in-the-front-matter-are-not-counted", "---\nname: x\nnote: -> a: b\n---\n## a\n-> b: w\n", _limits(edges=1)),
    _case("edges-a-bulleted-edge-counts", "## a\n- -> b: x\n-> c: y\n", _limits(edges=1)),
    _case("edges-lines-that-are-not-edges-do-not-count", "## a\nplain\n@note(x)\n-> b\n-> : x\n-> b: x\n", _limits(edges=1)),
    _case("edges-an-annotation-is-not-an-edge", "## a\n@emits(x)\n@checkpoint(unit=y)\n-> b: x\n", _limits(edges=1)),
    _case("edges-a-repeated-heading-keeps-the-count", "## a\n-> b: x\n-> c: y\n## a\n-> d: z\n", _limits(edges=2)),
    _case("edges-a-repeated-heading-within-the-cap", "## a\n-> b: x\n-> c: y\n## a\n-> d: z\n", _limits(edges=3)),
    _case("edges-a-cap-of-zero-and-no-edge", "## a\ntext\n", _limits(edges=0)),
    _case("edges-a-cap-of-zero-and-one-edge", "## a\n-> b: x\n", _limits(edges=0)),
    _case("edges-a-negative-cap", "## a\n", _limits(edges=-1)),
    # -- which cap the document reaches first
    _case("order-the-edges-first", "## a\n-> b: x\n-> c: y\n## b\n", _limits(nodes=1, edges=1)),
    _case("order-the-nodes-first", "## a\n## b\n-> x: y\n-> z: w\n", _limits(nodes=1, edges=1)),
    _case("order-the-second-edge-before-the-second-node", "## a\n-> b: x\n-> c: y\n## b\n", _limits(nodes=1, edges=1)),
    _case("order-the-second-node-before-the-second-edge", "## a\n-> b: x\n## b\n-> c: y\n", _limits(nodes=1, edges=1)),
    _case("order-nodes-at-the-cap-and-the-second-edge-over", "## a\n-> b: x\n## b\n-> c: y\n", _limits(nodes=2, edges=1)),
    # -- an ordinary document under ordinary bounds
    _case("a-small-document-within-every-cap", "---\nname: tiny\nstart: a\n---\n## a\nDo it.\n-> b: when ok\n-> a: else\n\n## b\nDone.\n",
          _limits()),
    _case("a-document-with-no-heading", "nothing here\n", _limits()),
]

DEFAULTS = [
    ("default-nodes-at-the-cap", "nodes", parser.MAX_NODES),
    ("default-nodes-one-over", "nodes", parser.MAX_NODES + 1),
    ("default-edges-at-the-cap", "edges", parser.MAX_EDGES),
    ("default-edges-one-over", "edges", parser.MAX_EDGES + 1),
    ("default-characters-at-the-cap", "characters", parser.MAX_FLOW_BYTES),
    ("default-characters-one-over", "characters", parser.MAX_FLOW_BYTES + 1),
]

ENV = ["5", "  7 ", "+8", "-3", "0", "00012", "1_000", "1__0", "_1", "1_", "", " ", "x", "1.5", "0x10", "1e3", "- 1", "+-1", "5\n",
       "2097152", "9223372036854775807"]


def build(kind: str, count: int) -> str:
    """The document a `defaults` rule stands for; the Rust test builds the same one."""
    if kind == "nodes":
        return "".join(f"## n{index}\n" for index in range(count))
    if kind == "edges":
        return "## a\n" + "-> a: x\n" * count
    if kind == "characters":
        return "## a\n" + "x" * (count - 5)
    raise ValueError(kind)


def _outcome(text: str) -> dict:
    try:
        graph = parser.parse(text)
    except parser.ParseError as error:
        return {"error": str(error), "error_class": type(error).__name__}
    return {"ok": True, "start": graph.start, "nodes": [[name, len(node.edges)] for name, node in graph.nodes.items()]}


def _under(limits: dict, text: str) -> dict:
    saved = parser.MAX_FLOW_BYTES, parser.MAX_NODES, parser.MAX_EDGES
    parser.MAX_FLOW_BYTES, parser.MAX_NODES, parser.MAX_EDGES = (limits["max_flow_bytes"], limits["max_nodes"], limits["max_edges"])
    try:
        return _outcome(text)
    finally:
        parser.MAX_FLOW_BYTES, parser.MAX_NODES, parser.MAX_EDGES = saved


def _int(raw: str) -> dict:
    try:
        return {"value": int(raw)}
    except ValueError:
        return {"refused": True}


def generate() -> dict:
    cases = [{"name": name, "flow": flow, "limits": limits, "expect": _under(limits, flow)} for name, flow, limits in CASES]
    defaults = []
    for name, kind, count in DEFAULTS:
        outcome = _outcome(build(kind, count))
        if outcome.get("ok"):                    # a stored outcome of 5,000 nodes would be the corpus' bulk
            outcome = {"ok": True, "node_count": len(outcome["nodes"]), "edge_count": sum(edges for _, edges in outcome["nodes"])}
        defaults.append({"name": name, "kind": kind, "count": count,
                         "limits": {"max_flow_bytes": parser.MAX_FLOW_BYTES, "max_nodes": parser.MAX_NODES, "max_edges": parser.MAX_EDGES},
                         "expect": outcome})
    return {
        "version": VERSION,
        "note": "kernel/parser.py parse under its input bounds. `cases` are small documents under small caps with the "
                "reference's outcome (the nodes with their edge counts, or the ParseError message); `defaults` are "
                "documents built from a rule (see the generator) under the default caps; `env` is what int() makes of the "
                "strings an environment variable may hold. Any implementation must give each outcome.",
        "cases": cases,
        "defaults": defaults,
        "env": [{"raw": raw, **_int(raw)} for raw in ENV],
    }


def main() -> int:
    doc = generate()
    OUT.write_text(json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {OUT}  ({len(doc['cases'])} cases, {len(doc['defaults'])} default cap cases, {len(doc['env'])} env strings)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
