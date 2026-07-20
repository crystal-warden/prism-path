"""ci_report.py — the PR report: validate + fixtures + before/after Mermaid for changed flows.

`prismpath ci-report --base <ref>` finds the flow files changed since `<ref>`, runs the decidable
checks and the fixture tables on each, renders the flow's graph BEFORE (the base version) and
AFTER (the working tree) as Mermaid — which GitHub renders natively in a PR comment — and prints
one Markdown report. The GitHub Action posts it as a sticky comment; locally it's just a command.

This is the "money demo" as a living product: a PR that edits an edge shows its topology diff and
its routing-test verdict *in the conversation*, so a reviewer approves a process change the way
they approve code. Exit status: 1 if any changed flow has an error-severity finding or a failing
fixture row (the comment is information; the exit code is the gate).

Model-free by design: validate and the deterministic fixture rows need no model; fixture tables
whose rows hit the embedding tier are reported as "skipped (needs the [embeddings] extra)" rather
than failing the report on a kernel-only CI runner.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from typing import List, Optional

from prismpath import analysis
from prismpath.parser import parse_file
from prismpath.graph_export import to_mermaid
from prismpath import flow_test

MARKER = "<!-- prismpath-ci-report -->"


@dataclass
class FlowReport:
    path: str
    findings: list = field(default_factory=list)          # analysis findings (severity/code/node/message)
    tests_passed: Optional[int] = None                    # None = no fixture table
    tests_total: Optional[int] = None
    tests_skipped: str = ""                               # non-empty = why fixtures were skipped
    mermaid_before: Optional[str] = None                  # None = new flow in this PR
    mermaid_after: str = ""
    parse_error: str = ""

    @property
    def errors(self):
        return [f for f in self.findings if f.severity == "error"]

    @property
    def warnings(self):
        return [f for f in self.findings if f.severity != "error"]

    @property
    def ok(self):
        return not self.parse_error and not self.errors and \
            (self.tests_total is None or self.tests_passed == self.tests_total)


def _git(args: List[str], cwd: str = ".") -> str:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True).stdout


def changed_flows(base: str, cwd: str = ".") -> List[str]:
    """Flow files changed between `base` and the working tree: .md, not a fixture table, still
    present, and actually parseable as a flow with at least one edge (READMEs and papers are .md
    too — they are excluded by failing that bar, never by guessing from the filename)."""
    out = _git(["diff", "--name-only", base, "--", "*.md"], cwd)
    flows = []
    for rel in sorted(set(out.split())):
        if rel.endswith(".tests.md"):
            continue
        p = os.path.join(cwd, rel)
        if not os.path.isfile(p):
            continue                                       # deleted in this PR
        try:
            with open(p, encoding="utf-8") as f:
                head = f.read(512)
            # a flow BEGINS with front-matter declaring its start node; prose docs that merely
            # EMBED flow snippets in code fences (GETTING_STARTED and kin) fail this bar.
            if not (head.startswith("---") and "start:" in head.split("---")[1]):
                continue
            g = parse_file(p)
            if any(n.edges for n in g.nodes.values()):
                flows.append(rel)
        except Exception:
            continue                                       # ordinary markdown, not a flow
    return flows


def _base_mermaid(base: str, rel: str, cwd: str = ".") -> Optional[str]:
    try:
        text = _git(["show", f"{base}:{rel}"], cwd)
    except subprocess.CalledProcessError:
        return None                                        # new flow in this PR
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as f:
        f.write(text)
        tmp = f.name
    try:
        return to_mermaid(parse_file(tmp))
    except Exception:
        return None                                        # base version didn't parse; show only after
    finally:
        os.unlink(tmp)


def report_flow(rel: str, base: str, cwd: str = ".") -> FlowReport:
    r = FlowReport(path=rel)
    p = os.path.join(cwd, rel)
    try:
        graph = parse_file(p)
    except Exception as e:
        r.parse_error = str(e)
        return r
    r.findings = list(analysis.analyze(graph)) + analysis.analyze_composition(graph, p)
    r.mermaid_after = to_mermaid(graph)
    r.mermaid_before = _base_mermaid(base, rel, cwd)
    tests_path = flow_test.default_tests_path(p)
    if os.path.isfile(tests_path):
        try:
            tr = flow_test.run_tests(p, tests_path)
            r.tests_passed, r.tests_total = tr.passed, len(tr.results)
        except ImportError:
            r.tests_skipped = "fixture rows need the embedding tier — install the [embeddings] extra"
    return r


def render(reports: List[FlowReport]) -> str:
    """The sticky-comment Markdown. GitHub renders the ```mermaid fences as live diagrams, so the
    before/after IS the review surface for a topology change."""
    lines = [MARKER, "## Flow review — validate · fixtures · topology", ""]
    if not reports:
        return "\n".join(lines + ["No flow files changed in this PR."])
    lines += ["| flow | compiles | fixtures |", "|---|---|---|"]
    for r in reports:
        if r.parse_error:
            compiles = "💥 parse failed"
        elif r.errors:
            compiles = f"✗ {len(r.errors)} error(s)"
        elif r.warnings:
            compiles = f"⚠ {len(r.warnings)} advisory(ies)"
        else:
            compiles = "✅ clean"
        if r.tests_total is not None:
            fixtures = f"{'✅' if r.tests_passed == r.tests_total else '✗'} {r.tests_passed}/{r.tests_total}"
        elif r.tests_skipped:
            fixtures = "⏭ skipped"
        else:
            fixtures = "— none"
        lines.append(f"| `{r.path}` | {compiles} | {fixtures} |")
    for r in reports:
        lines += ["", f"### `{r.path}`"]
        if r.parse_error:
            lines += [f"```\nparse failed: {r.parse_error}\n```"]
            continue
        for f in r.findings:
            icon = "✗" if f.severity == "error" else "⚠"
            lines.append(f"- {icon} **{f.code}** [{f.node}] {f.message}")
        if r.tests_skipped:
            lines.append(f"- ⏭ {r.tests_skipped}")
        if r.mermaid_before is None:
            lines += ["", "<details><summary><b>Topology (new flow)</b></summary>", "",
                      "```mermaid", r.mermaid_after, "```", "", "</details>"]
        elif r.mermaid_before == r.mermaid_after:
            lines += ["", "<details><summary>Topology unchanged (worker prose / condition text edits only)</summary>",
                      "", "```mermaid", r.mermaid_after, "```", "", "</details>"]
        else:
            lines += ["", "<details open><summary><b>Topology changed — before → after</b></summary>",
                      "", "**before**", "```mermaid", r.mermaid_before, "```",
                      "", "**after**", "```mermaid", r.mermaid_after, "```", "", "</details>"]
    lines += ["", "_`prismpath ci-report` — validate + fixture tables are model-free; "
                  "the diagrams above are the actual routing topology, not an illustration._"]
    return "\n".join(lines)


def ci_report_cmd(args) -> int:
    reports = [report_flow(rel, args.base) for rel in changed_flows(args.base)]
    text = render(reports)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    else:
        print(text)
    return 0 if all(r.ok for r in reports) else 1


def add_parser(subparsers) -> None:
    p = subparsers.add_parser(
        'ci-report', help='Markdown PR report for changed flows: validate + fixtures + '
                          'before/after Mermaid (the Action posts it as a sticky comment)')
    p.add_argument('--base', required=True, help='git ref to diff against (the PR base sha/branch)')
    p.add_argument('--out', default=None, help='write the report here instead of stdout')
    p.set_defaults(func=ci_report_cmd)
