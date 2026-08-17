#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""arith_lint — recompute cross-artifact numeric ratios from the canonical fusion bench JSONs and
fail when a stored ratio is internally inconsistent, two files disagree, or a doc quotes a superseded
value without its append-only annotation.

Motivation: a 67.6x vs 66.9x drift sat live on the public site because the gates check schema, links,
and conformance, but nothing recomputes a ratio BETWEEN two artifacts. This closes that gap. It is the
third blocking step of the CI `docs:` job (docs/research/LEDGER_STANDARDS.md section 7).

Checks:
  1. SOURCE — every derived number a canonical JSON stores (its `ratios` block, O1/O2 bytes/decision)
              matches a recompute from that file's own component fields.                       [hard]
  2. CROSS  — a quantity claimed by two source files agrees (O1 bytes/decision).               [hard]
  3. DOC    — no superseded ratio (67.6x, 4.8x) appears in the docs near an OTLP/zstd anchor without
              an append-only annotation (ledger #95 deliberately keeps the pre-#84 numbers).   [hard]

Usage:
    python tools/arith_lint.py [--strict] [--json]
Default is report mode (exit 0). `--strict` exits non-zero on any hard finding.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
BENCH = BASE / "adapters" / "fusion" / "bench"
LEDGER = BASE / "docs" / "research" / "supporting-evidence.md"
PENDING = BASE / "docs" / "research" / "supporting-evidence.pending.md"


def _ledger_numeric_mentions():
    """A deliberately generous count of number-like tokens across the ledger + pending rows, so the
    coverage line states the ORDER-OF-MAGNITUDE gap honestly rather than implying broad rigor. Dates
    and `#NN` row ids are excluded; everything else (including counts) is kept, so this over-counts the
    true 'numeric claim' surface, which is the safe direction for an honesty statement."""
    txt = ""
    for f in (LEDGER, PENDING):
        if f.exists():
            txt += f.read_text()
    toks = re.findall(r"(?<![#\w.])\d[\d,]*(?:\.\d+)?", txt)
    return sum(1 for t in toks if not re.fullmatch(r"(19|20)\d\d", t.replace(",", "")))


def _load(name):
    return json.loads((BENCH / name).read_text())


def _close(a, b, tol):
    return abs(float(a) - float(b)) <= tol


# --- checks 1 + 2: recompute the source of truth ---------------------------------------------------

def check_sources():
    """Recompute each derived number from component fields and compare to what the JSON stores.
    Returns (hard_findings, recomputed_dict, o1_bytes_per_decision_from_results)."""
    hard = []
    otlp = _load("otlp_results.json")
    res = _load("results.json")
    n = res["n"]

    o1 = res["o1"]["wire_bytes_total"] / n                     # 1.516
    o2 = res["o2"]["wire_bytes_total"] / n                     # 0.516
    otlp_b = otlp["otlp_faithful"]["epoched_per_decision"]     # 101.372
    zstd_b = otlp["otlp_faithful"]["zstd19_per_decision"]      # 7.162
    min_b = otlp["otlp_minimal"]["epoched_per_decision"]       # 39.905
    b2 = res["b2"]["avg"]                                      # 68.1

    want = {
        "o1_B_per_decision": round(o1, 3),
        "o2_B_per_decision": round(o2, 3),
        "otlp_faithful_B_per_decision": round(otlp_b, 3),
        "otlp_over_o1": round(otlp_b / o1, 1),
        "otlp_zstd_over_o1": round(zstd_b / o1, 1),
        "otlp_minimal_over_o2": round(min_b / o2, 1),
        "otlp_over_b2_json": round(otlp_b / b2, 2),
    }
    have = otlp.get("ratios", {})
    for k, v in want.items():
        if k in have:
            tol = 0.05 if v > 5 else 0.01     # ratios quoted to 1 dp; B/dec quoted to 3 dp
            if not _close(have[k], v, tol):
                hard.append({"check": "SOURCE", "detail":
                             f"otlp_results.json ratios.{k} = {have[k]} but recompute = {v}"})
    return hard, want, round(o1, 3)


def check_cross(o1_from_results):
    otlp = _load("otlp_results.json")
    stored = otlp["ratios"]["o1_B_per_decision"]
    if not _close(stored, o1_from_results, 0.01):
        return [{"check": "CROSS", "detail":
                 f"O1 bytes/decision disagrees: otlp_results.json={stored} vs "
                 f"results.json recompute={o1_from_results}"}]
    return []


# --- check 3: superseded ratios in the docs --------------------------------------------------------

# A superseded ratio (the pre-#84, payload-only denominator) is legitimate ONLY where the ledger's
# append-only rule keeps it, which always carries an annotation. Match the ratio WITH its x/× suffix
# (so a bare "4.8" elsewhere never trips), then require an OTLP/zstd anchor nearby and no annotation.
SUPERSEDED = [(re.compile(r"\b67\.6\s*[x×]"), "66.9"),
              (re.compile(r"\b4\.8\s*[x×]"), "4.7")]
ANCHOR = re.compile(r"(?i)otlp|opentelemetry|zstd|smaller")
ANN = re.compile(r"(?i)originally|recorded|earlier|pre-#84|payload-only|payload only|#95|superseded|before the")
EXC = re.compile(r"(node_modules|/\.git/|\.venv|/venv|site-packages|__pycache__|\.pytest_cache"
                 r"|docs_health_report|/extern/|_retired|/attic/)")


def _md_files():
    out = []
    for dp, _, fn in os.walk(BASE):
        if EXC.search(dp + "/"):
            continue
        for f in fn:
            if f.endswith(".md"):
                p = os.path.join(dp, f)
                if not EXC.search(p):
                    out.append(p)
    return out


HEADING = re.compile(r"(?m)^#{1,6} ")
# CHANGELOG is append-only release history: a superseded number there records what was measured at
# that release, a historical fact rather than a live claim. Excluded from the DOC check.
DOC_SKIP = ("CHANGELOG.md",)


def _section(txt, pos):
    """The heading-delimited section enclosing `pos` (covers a whole ledger row: Claim .. Result)."""
    starts = [m.start() for m in HEADING.finditer(txt)]
    lo = max([s for s in starts if s <= pos], default=0)
    hi = min([s for s in starts if s > pos], default=len(txt))
    return txt[lo:hi]


def check_docs():
    hard = []
    for p in _md_files():
        rel = os.path.relpath(p, BASE)
        if any(rel.endswith(s) for s in DOC_SKIP):
            continue
        txt = open(p, encoding="utf-8", errors="ignore").read()
        for rx, canon in SUPERSEDED:
            for m in rx.finditer(txt):
                sec = _section(txt, m.start())
                if ANN.search(sec):          # append-only annotation somewhere in this row/section
                    continue
                if ANCHOR.search(sec):
                    line = txt.count("\n", 0, m.start()) + 1
                    hard.append({"check": "DOC", "detail":
                                 f"{rel}:{line} quotes superseded ratio {m.group(0).strip()} in an "
                                 f"OTLP/zstd section without an append-only annotation "
                                 f"(canonical {canon}x)"})
    return hard


def run():
    src, want, o1 = check_sources()
    return {"hard": src + check_cross(o1) + check_docs(), "recomputed": want}


def main(argv):
    strict = "--strict" in argv
    rep = run()
    if "--json" in argv:
        print(json.dumps(rep, indent=1))
    else:
        n_rc = len(rep["recomputed"])
        total = _ledger_numeric_mentions()
        print(f"arith_lint: recomputed {n_rc} canonical numbers; {len(rep['hard'])} hard")
        for f in rep["hard"]:
            print(f"  HARD  {f['check']:<6} {f['detail']}")
        if not rep["hard"]:
            print("  clean — every source ratio recomputes and no superseded value is unannotated.")
        print()
        print("  COVERAGE (read this before trusting the green):")
        print(f"    This lint recomputes {n_rc} cross-artifact ratios from the committed fusion")
        print( "    benches — the only ledger numbers derived from two on-disk JSONs. It cannot and")
        print( "    does not recompute the rest of the ledger's ~{} numeric mentions: those are"
              .format(total))
        print( "    single-source measurements (hardware runs, in-kernel certs, off-repo lab")
        print( "    artifacts) whose integrity rests on provenance + OTS anchoring, NOT recomputation.")
        print( "    Machine-checked coverage here is narrow by design; do not read it as ledger-wide.")
        print( "    Recomputed: " + ", ".join(sorted(rep["recomputed"])))
    return 1 if (strict and rep["hard"]) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
