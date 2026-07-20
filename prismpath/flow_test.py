"""flow_test.py — `prismpath test`: assert a flow's routing from a Markdown fixture, no LLM needed.

Authors can't otherwise test a flow without running agents. Here the fixture is itself Markdown — a
table of (node, example outcome, fields, expected edge) — executed against the REAL router's
deterministic and embedding tiers (never the LLM). The PM writes the scenarios; CI asserts the
routing; every past mis-route becomes a regression case. Because each row is a (outcome -> edge)
judgement, `--emit-labels` drops out labeled routing data for calibration for free.

Fixture format (a GFM table, sibling file `<flow>.tests.md` by default):

    | node    | outcome                                   | fields          | expect    |
    |---------|-------------------------------------------|-----------------|-----------|
    | triage  | the bug is reproduced, root cause is clear|                 | implement |
    | run_tests | all 240 tests passed                    | tests_pass=true | done      |
    | run_tests | 3 tests still failing                   | tests_pass=false| debug     |

`fields` is `k=v` pairs (`;` or `,` separated; true/false/int/float coerced) exposed to the `when`
predicates; `visits` is an accepted field. Rows with only deterministic edges need no model at all.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import List, Optional

from prismpath.engine import first_deterministic
from prismpath.parser import parse_file
from prismpath import predicates


@dataclass
class CaseResult:
    node: str
    outcome: str
    expect: str
    got: Optional[str]
    ok: bool
    how: str            # "deterministic" | "embed" | "stuck" | "error"
    detail: str = ""


@dataclass
class TestReport:
    results: List[CaseResult] = field(default_factory=list)
    @property
    def passed(self):
        return sum(1 for r in self.results if r.ok)
    @property
    def failed(self):
        return sum(1 for r in self.results if not r.ok)
    @property
    def ok(self):
        return self.failed == 0 and bool(self.results)


# --- fixture parsing --------------------------------------------------------------------
def _coerce(v: str):
    s = v.strip()
    low = s.lower()
    if low in ("true", "false"):
        return low == "true"
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        pass
    return s.strip('"')


def _parse_fields(cell: str) -> dict:
    out = {}
    for part in re.split(r"[;,]", cell):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = _coerce(v)
    return out


def parse_tests(text: str) -> List[dict]:
    """Parse the first GFM table with a `node` and `expect` column into a list of case dicts."""
    rows = [ln for ln in text.splitlines() if ln.strip().startswith("|")]
    if len(rows) < 2:
        return []

    def cells(line):
        return [c.strip() for c in line.strip().strip("|").split("|")]

    header = [h.lower() for h in cells(rows[0])]
    if "node" not in header or "expect" not in header:
        return []
    idx = {name: header.index(name) for name in header}
    cases = []
    # skip the GFM separator row (|---|---|) only if present — never drop a data row.
    body = rows[1:]
    if body and all(re.fullmatch(r":?-{2,}:?", cc) for cc in cells(body[0]) if cc):
        body = body[1:]
    for line in body:
        c = cells(line)
        if len(c) < len(header):
            continue
        cases.append({
            "node": c[idx["node"]],
            "outcome": c[idx["outcome"]] if "outcome" in idx else "",
            "fields": _parse_fields(c[idx["fields"]]) if "fields" in idx else {},
            "expect": c[idx["expect"]],
        })
    return cases


def default_tests_path(flow_path) -> str:
    return os.path.splitext(os.fspath(flow_path))[0] + ".tests.md"


# --- runner -----------------------------------------------------------------------------
def _make_router(flow_path):
    """Embed-only router (no LLM). Uses the committed lockfile if one sits next to the flow, so
    tests are bit-for-bit reproducible; otherwise a live EmbeddingRouter."""
    from prismpath import lockfile
    from prismpath.router import EmbeddingRouter
    lp = lockfile.lock_path(flow_path)
    if os.path.exists(lp):
        try:
            return lockfile.locked_router(lockfile.load_lock(lp), verify=False)
        except Exception:
            pass
    return EmbeddingRouter()


def run_tests(flow_path, tests_path=None, router=None) -> TestReport:
    graph = parse_file(flow_path)
    tests_path = tests_path or default_tests_path(flow_path)
    with open(tests_path, encoding="utf-8") as _f:
        cases = parse_tests(_f.read())
    report = TestReport()
    lazy_router = router

    for case in cases:
        node = graph.nodes.get(case["node"])
        if node is None:
            report.results.append(CaseResult(case["node"], case["outcome"], case["expect"],
                                             None, False, "error", "no such node"))
            continue
        ctx = {**case["fields"], "visits": case["fields"].get("visits", 1)}
        dt, _ = first_deterministic(node.edges, ctx)
        if dt is not None:
            got, how = dt, "deterministic"
        else:
            sem = [(t, c) for t, c in node.edges if predicates.is_semantic(c)]
            if not sem:
                report.results.append(CaseResult(case["node"], case["outcome"], case["expect"],
                                                 None, False, "stuck", "no edge matched"))
                continue
            if lazy_router is None:
                lazy_router = _make_router(flow_path)     # only load a model if an embed case needs it
            got, how = lazy_router.route(case["outcome"], sem, node.instruction).target, "embed"
        report.results.append(CaseResult(case["node"], case["outcome"], case["expect"],
                                         got, got == case["expect"], how))
    return report


def emit_labels(report: TestReport, flow_name: str, path) -> int:
    """Write each case as a labeled routing record (the Sprint-0 / Area-4 label format)."""
    n = 0
    with open(path, "a", encoding="utf-8") as f:
        for r in report.results:
            f.write(json.dumps({
                "flow": flow_name, "node": r.node, "outcome_text": r.outcome,
                "chosen": r.got, "label": r.expect, "label_source": "flow_test",
                "mechanism": r.how, "correct": r.ok}) + "\n")
            n += 1
    return n
