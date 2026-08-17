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
    heads = [(i, m) for i, l in enumerate(lines) if (m := ROW_HEAD_RE.match(l))]
    for idx, (line_no, m) in enumerate(heads):
        n = int(m.group(1))
        title = m.group(2).strip()
        dm = TRAILING_PAREN_RE.search(title)
        date = dm.group(1).strip() if dm else None
        end = heads[idx + 1][0] if idx + 1 < len(heads) else len(lines)
        # stop the body at the next top-level `## ` section too
        for j in range(line_no + 1, end):
            if lines[j].startswith("## ") and not lines[j].startswith("### "):
                end = j
                break
        body = "\n".join(lines[line_no:end])
        yield {"n": n, "title": title, "date": date, "body": body, "line": line_no + 1}


def lint(text: str) -> dict:
    rows = list(parse_rows(text))
    hard, review = [], []

    # 1. dates
    for r in rows:
        if r["date"] is None:
            hard.append({"check": "DATE", "row": r["n"], "line": r["line"],
                         "detail": "row header has no trailing (date)"})
        elif ISO_DATE_RE.search(r["date"]) or not MONTH_DATE_RE.match(r["date"]):
            hard.append({"check": "DATE", "row": r["n"], "line": r["line"],
                         "detail": f"date {r['date']!r} is not month-granularity 'Month YYYY'"})

    # 2. numbering
    nums = [r["n"] for r in rows]
    seen = set()
    for n in nums:
        if n in seen:
            hard.append({"check": "NUMBER", "row": n, "detail": f"duplicate row #{n}"})
        seen.add(n)
    if nums:
        lo, hi = min(nums), max(nums)
        missing = sorted(set(range(lo, hi + 1)) - set(nums))
        if missing:
            hard.append({"check": "NUMBER", "detail": f"gaps in #{lo}–#{hi}: "
                         + ", ".join(f"#{x}" for x in missing)})

    # 3. schema
    for r in rows:
        missing = [s for s in REQUIRED_SECTIONS if f"{s}:" not in r["body"]]
        if missing:
            hard.append({"check": "SCHEMA", "row": r["n"], "line": r["line"],
                         "detail": "missing section(s): " + ", ".join(missing)})

    # 4. caveats (review only)
    for r in rows:
        low = r["body"].lower()
        if CLOSED_RE.search(r["body"]):
            continue
        hits = sorted({p for p in CAVEAT_PHRASES if p in low})
        if hits:
            review.append({"check": "CAVEAT", "row": r["n"], "line": r["line"],
                           "detail": "unreconciled caveat phrase(s): " + ", ".join(hits)
                           + " — classify per LEDGER_STANDARDS §3 (Closed by #N / rephrase / confirm open)"})

    return {"rows": len(rows), "hard": hard, "review": review}


def main(argv) -> int:
    args = [a for a in argv if not a.startswith("--")]
    strict = "--strict" in argv
    as_json = "--json" in argv
    path = Path(args[0]) if args else Path(DEFAULT_LEDGER)
    report = lint(path.read_text())

    if as_json:
        print(json.dumps(report, indent=1))
    else:
        print(f"ledger_lint: {path} — {report['rows']} prose rows; "
              f"{len(report['hard'])} hard, {len(report['review'])} review")
        for f in report["hard"]:
            r = f.get("row")
            print(f"  HARD  {f['check']:<6} {('#'+str(r)) if r else '':<5} {f['detail']}")
        for f in report["review"]:
            print(f"  REVIEW {f['check']:<5} #{f['row']:<4} {f['detail']}")
        if not report["hard"] and not report["review"]:
            print("  clean.")

    return 1 if (strict and report["hard"]) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
