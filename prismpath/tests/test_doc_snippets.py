# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Every flow and rules example in the specification and the guides reads as what it claims to be.

A fenced block with a `## ` heading and a `->` line is an example. One with a rules line (`-> refuse <cause>:`,
`-> escalate <cause>:`) or a `## core_decision` heading is a rules source, any other is a flow.

  * A flow example parses. One that starts with front matter and defines every node its edges name is
    complete and must validate with no error. Any other is an excerpt, which may name nodes it does not show.
  * A rules example with front matter must compile. One without is an excerpt, and each of its rules must
    still read (a registered cause, a condition the compiler reads).

A block that is only edge lines (`-> target: condition`) with no heading is checked as an excerpt of a flow.
"""
import re
from pathlib import Path

import pytest

from prismpath.kernel import analysis, parser
from prismpath.kernel import policy_source as ps

ROOT = Path(__file__).resolve().parents[2]
DOCS = [ROOT / "SPEC.md", ROOT / "README.md", ROOT / "GETTING_STARTED.md"] + sorted((ROOT / "docs" / "guides").glob("*.md"))
FENCE = re.compile(r"^\s*(```+|~~~+)\s*([A-Za-z0-9_+-]*)\s*$")
RULES = re.compile(r"^\s*-?\s*->\s*(refuse|escalate)\s+\S+?:\s|^\s*##\s+core_decision\s*$", re.M)
HEADING = re.compile(r"^\s*##\s", re.M)
EDGE = re.compile(r"^\s*-?\s*->\s*[A-Za-z0-9_\-]+\s*:", re.M)


def _blocks(path):
    lines = path.read_text(encoding="utf-8").split("\n")
    at = 0
    while at < len(lines):
        match = FENCE.match(lines[at])
        if not match:
            at += 1
            continue
        end = at + 1
        while end < len(lines) and not lines[end].strip().startswith(match.group(1)):
            end += 1
        yield at + 2, match.group(2), "\n".join(lines[at + 1:end]) + "\n"
        at = end + 1


def _examples():
    found = []
    for path in DOCS:
        if not path.is_file():
            continue
        for line, lang, text in _blocks(path):
            if lang not in ("", "markdown", "md"):
                continue
            if RULES.search(text):
                found.append((f"{path.relative_to(ROOT)}:{line}", "rules", text))
            elif EDGE.search(text) or (HEADING.search(text) and "->" in text):
                found.append((f"{path.relative_to(ROOT)}:{line}", "flow", text))
    return found


EXAMPLES = _examples()


def test_the_docs_hold_examples_of_both_kinds():
    kinds = [kind for _where, kind, _text in EXAMPLES]
    assert kinds.count("flow") >= 10 and kinds.count("rules") >= 2


@pytest.mark.parametrize("where,kind,text", EXAMPLES, ids=[where for where, _k, _t in EXAMPLES])
def test_every_example_reads_as_what_it_is(where, kind, text):
    complete = text.lstrip().startswith("---")
    if kind == "rules":
        if complete:
            ps.compile_full(text, where)
        else:
            ps.parse_source("---\n---\n## core_decision\n" + text, where)
        return
    graph = parser.parse(text)
    assert graph.nodes or not HEADING.search(text), where
    if complete and {target for node in graph.nodes.values() for target, _c in node.edges} <= set(graph.nodes):
        errors = [finding for finding in analysis.analyze(graph) if finding.severity == "error"]
        assert not errors, (where, [str(finding) for finding in errors])
