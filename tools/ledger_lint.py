#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""ledger_lint — enforce docs/research/LEDGER_STANDARDS.md on the evidence ledger.

Checks the `### #N —` prose rows for:
  1. DATE     — header date is month-granularity `Month YYYY` (no `YYYY-MM-DD` in prose)  [hard]
  2. NUMBER   — rows are contiguous and unique (no gaps, no duplicates)                    [hard]
  3. SCHEMA   — each row has Claim / Method / Result / Provenance                          [hard]
  4. CAVEAT   — an unreconciled "pending / not yet / still …" caveat lacking `Closed by #N`  [review]

Usage:
    python tools/ledger_lint.py [docs/research/supporting-evidence.md] [--strict] [--json]

Default is report mode (exit 0). `--strict` exits non-zero when any HARD violation remains — the
docs-overhaul definition of done. CAVEAT findings are a manual review list; they never fail the build
(some caveats are legitimately still open). Wire this into CI as a blocking `--strict` gate only once
the overhaul brings the hard count to zero (LEDGER_STANDARDS §7).
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

DEFAULT_LEDGER = "docs/research/supporting-evidence.md"

MONTHS = ("January", "February", "March", "April", "May", "June", "July", "August",
          "September", "October", "November", "December")
MONTH_DATE_RE = re.compile(r"^(?:" + "|".join(MONTHS) + r") \d{4}$")
ISO_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
ROW_HEAD_RE = re.compile(r"^### #(\d+)\s+—\s+(.*)$")
TRAILING_PAREN_RE = re.compile(r"\(([^()]*)\)\s*$")
CLOSED_RE = re.compile(r"Closed (?:by|in) #\d+", re.IGNORECASE)

# Phrases that read as un-done work; flagged for review unless the row also carries a `Closed by #N`.
CAVEAT_PHRASES = (
    "pending a privileged run", "pending a hardware retest", "pending a", "still pending",
    "remains pending", "not yet earned", "not yet built", "not yet run",
    "still element-wise", "not double-buffered", "built but not", "staged, not committed",
)

REQUIRED_SECTIONS = ("Claim", "Method", "Result", "Provenance")


def parse_rows(text: str):
    """Yield {n, title, date, body} for each `### #N —` prose row."""
    lines = text.splitlines()
    heads = [(line_number, head_match) for line_number, line in enumerate(lines) if (head_match := ROW_HEAD_RE.match(line))]
    for idx, (line_no, head_match) in enumerate(heads):
        row_number = int(head_match.group(1))
        title = head_match.group(2).strip()
        dm = TRAILING_PAREN_RE.search(title)
        date = dm.group(1).strip() if dm else None
        end = heads[idx + 1][0] if idx + 1 < len(heads) else len(lines)
        # stop the body at the next top-level `## ` section too
        for body_line_index in range(line_no + 1, end):
            if lines[body_line_index].startswith("## ") and not lines[body_line_index].startswith("### "):
                end = body_line_index
                break
        body = "\n".join(lines[line_no:end])
        yield {"n": row_number, "title": title, "date": date, "body": body, "line": line_no + 1}


def lint(text: str) -> dict:
    rows = list(parse_rows(text))
    hard, review = [], []

    # 1. dates
    for row in rows:
        if row["date"] is None:
            hard.append({"check": "DATE", "row": row["n"], "line": row["line"],
                         "detail": "row header has no trailing (date)"})
        elif ISO_DATE_RE.search(row["date"]) or not MONTH_DATE_RE.match(row["date"]):
            hard.append({"check": "DATE", "row": row["n"], "line": row["line"],
                         "detail": f"date {row['date']!r} is not month-granularity 'Month YYYY'"})

    # 2. numbering
    nums = [row["n"] for row in rows]
    seen = set()
    for row_number in nums:
        if row_number in seen:
            hard.append({"check": "NUMBER", "row": row_number, "detail": f"duplicate row #{row_number}"})
        seen.add(row_number)
    if nums:
        lo, hi = min(nums), max(nums)
        missing = sorted(set(range(lo, hi + 1)) - set(nums))
        if missing:
            hard.append({"check": "NUMBER", "detail": f"gaps in #{lo}–#{hi}: "
                         + ", ".join(f"#{missing_number}" for missing_number in missing)})

    # 3. schema
    for row in rows:
        missing = [section for section in REQUIRED_SECTIONS if f"{section}:" not in row["body"]]
        if missing:
            hard.append({"check": "SCHEMA", "row": row["n"], "line": row["line"],
                         "detail": "missing section(s): " + ", ".join(missing)})

    # 4. caveats (review only)
    for row in rows:
        low = row["body"].lower()
        if CLOSED_RE.search(row["body"]):
            continue
        hits = sorted({phrase for phrase in CAVEAT_PHRASES if phrase in low})
        if hits:
            review.append({"check": "CAVEAT", "row": row["n"], "line": row["line"],
                           "detail": "unreconciled caveat phrase(s): " + ", ".join(hits)
                           + " — classify per LEDGER_STANDARDS §3 (Closed by #N / rephrase / confirm open)"})

    return {"rows": len(rows), "hard": hard, "review": review}


def main(argv) -> int:
    args = [argument for argument in argv if not argument.startswith("--")]
    strict = "--strict" in argv
    as_json = "--json" in argv
    path = Path(args[0]) if args else Path(DEFAULT_LEDGER)
    report = lint(path.read_text())

    if as_json:
        print(json.dumps(report, indent=1))
    else:
        print(f"ledger_lint: {path} — {report['rows']} prose rows; "
              f"{len(report['hard'])} hard, {len(report['review'])} review")
        for finding in report["hard"]:
            row_number = finding.get("row")
            print(f"  HARD  {finding['check']:<6} {('#'+str(row_number)) if row_number else '':<5} {finding['detail']}")
        for finding in report["review"]:
            print(f"  REVIEW {finding['check']:<5} #{finding['row']:<4} {finding['detail']}")
        if not report["hard"] and not report["review"]:
            print("  clean.")

    return 1 if (strict and report["hard"]) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
