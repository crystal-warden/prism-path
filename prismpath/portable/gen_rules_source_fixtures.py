# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Freeze the flow parser's RULES SOURCE REFUSAL as language neutral vectors, generated from the Python
reference (`prismpath/kernel/parser.py`: `RulesSourceError`, `RULES_LINE_RE`, `RULES_SUFFIX`) so the Rust,
Go and JavaScript flow parsers are measured against it case by case.

    python -m prismpath.portable.gen_rules_source_fixtures    ->  conformance/rules_source.json

Each case holds:
  * `name`: unique identifier
  * `filename`: optional path or file name (when set, generated via `parser.parse_file` on a file of that
    name; when null, generated via `parser.parse`)
  * `flow`: the markdown document text
  * `expect`: either `{"error": <RulesSourceError message>, "error_class": "RulesSourceError"}` or
    `{"ok": true, "start": <start node>, "nodes": [[node_name, [[target, condition], ...]], ...]}`.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from prismpath.kernel import parser  # noqa: E402

OUT = HERE / "conformance" / "rules_source.json"
VERSION = 1


def _case(name: str, flow: str, filename: str | None = None) -> tuple[str, str | None, str]:
    return name, filename, flow


CASES = [
    # -- rules-source inputs that must be refused
    _case(
        "refuse-rule-with-frontmatter",
        "---\nname: r\nstart: core_decision\nfield.tool: category\n---\n"
        "## core_decision\n-> refuse agent:network: when tool == \"connect\"\n-> allow: always\n",
    ),
    _case(
        "refuse-rule-without-frontmatter",
        "## core_decision\n-> refuse agent:network: when tool == \"connect\"\n-> allow: always\n",
    ),
    _case(
        "escalate-rule-bulleted-and-indented",
        "## core_decision\n  - -> escalate agent:push-escalated: when git_op == \"push\"\n",
    ),
    _case(
        "escalate-rule-at-end-of-line",
        "## core_decision\n-> escalate agent:review:\n",
    ),
    _case(
        "refuse-rule-simple-cause",
        "## s\n-> refuse policy: when x == 1\n",
    ),
    _case(
        "refuse-rule-before-any-heading",
        "-> refuse agent:network: when tool == \"connect\"\n## core_decision\n-> allow: always\n",
    ),
    _case(
        "refuse-rule-double-dash-arrow",
        "## s\n--> refuse agent:network: when x == 1\n",
    ),
    _case(
        "refuse-rule-after-valid-edge",
        "## core_decision\n-> allow: when safe == True\n-> refuse agent:network: when tool == \"connect\"\n",
    ),
    _case(
        "rules-md-filename-with-allow-only",
        "---\nstart: core_decision\n---\n## core_decision\n-> allow: always\n",
        filename="only_allow.rules.md",
    ),
    _case(
        "rules-md-filename-in-subdirectory",
        "## s\n-> allow: always\n",
        filename="policies/agent.rules.md",
    ),
    _case(
        "rules-md-filename-takes-precedence-over-rules-line",
        "## s\n-> refuse agent:network: when x == 1\n",
        filename="both.rules.md",
    ),
    # -- near-miss inputs that must still parse as ordinary flows
    _case(
        "rendered-refuse-code-edge",
        "---\nstart: core_decision\n---\n## core_decision\n-> refuse_106: when tool == \"connect\"\n-> allow: always\n",
    ),
    _case(
        "rendered-escalate-code-edge",
        "---\nstart: core_decision\n---\n## core_decision\n-> escalate_107: when git_op == \"push\"\n-> allow: always\n",
    ),
    _case(
        "normal-when-edge",
        "---\nname: tiny\nstart: s\n---\n## s\n-> next: when x\n## next\nDone.\n",
    ),
    _case(
        "edge-named-refuse-directly",
        "## s\n-> refuse: when bad\n## refuse\nStopped.\n",
    ),
    _case(
        "edge-named-escalate-directly",
        "## s\n-> escalate: when urgent\n## escalate\nHuman.\n",
    ),
    _case(
        "prose-mentioning-refuse",
        "## a\nWe refuse -> nothing here.\n-> refuse later on, then stop\nDo not escalate this line.\n",
    ),
    _case(
        "edge-refuse-with-space-before-colon",
        "## a\n-> refuse : when x == 1\n",
    ),
    _case(
        "prose-refuse-colon-inside-token-no-trailing-colon",
        "## a\n-> refuse agent:network when tool == \"connect\"\n",
    ),
    _case(
        "uppercase-refuse-is-not-a-rule",
        "## a\n-> REFUSE agent:network: when tool == \"connect\"\n",
    ),
    _case(
        "ordinary-md-filename",
        "---\nstart: core_decision\n---\n## core_decision\n-> refuse_106: when tool == \"connect\"\n-> next: when x\n",
        filename="ordinary.md",
    ),
    _case(
        "rules-md-substring-not-suffix",
        "## s\n-> next: when x\n",
        filename="my.rules.md.bak",
    ),
]


def _outcome(flow: str, filename: str | None) -> dict:
    try:
        if filename is None:
            graph = parser.parse(flow)
        else:
            with tempfile.TemporaryDirectory() as tmp_dir:
                target = Path(tmp_dir) / filename
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(flow, encoding="utf-8")
                graph = parser.parse_file(str(target))
    except parser.ParseError as error:
        return {"error": str(error), "error_class": type(error).__name__}
    return {
        "ok": True,
        "start": graph.start,
        "nodes": [[name, [[target, cond] for target, cond in node.edges]] for name, node in graph.nodes.items()],
    }


def generate() -> dict:
    cases = [
        {"name": name, "filename": filename, "flow": flow, "expect": _outcome(flow, filename)}
        for name, filename, flow in CASES
    ]
    return {
        "version": VERSION,
        "note": "kernel/parser.py rules-source refusal. Rules sources (a `.rules.md` filename or any line matching "
                "`-> refuse|escalate <cause>:`) are refused with RulesSourceError (a ParseError subclass) pointing "
                "to `prismpath policy compile`. Rendered code edges (`refuse_106:`), normal edges (`-> next: when x`) "
                "and prose mentioning refuse keep parsing as ordinary flows.",
        "cases": cases,
    }


def main() -> int:
    doc = generate()
    OUT.write_text(json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    refused = sum(1 for c in doc["cases"] if "error" in c["expect"])
    accepted = sum(1 for c in doc["cases"] if c["expect"].get("ok"))
    print(f"wrote {OUT}  ({len(doc['cases'])} cases: {refused} refused, {accepted} accepted)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
