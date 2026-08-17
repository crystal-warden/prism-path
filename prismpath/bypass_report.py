# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""bypass_report.py — run the stratified adversarial corpus against the P0 floor and report.

Emits exactly the table pre-registered in `docs/research/bypass-measurement.md` §4: bypass rate per (rule,
stratum) with raw counts alongside, plus the mechanical/semantic rollup that turns the numbers into
a hardening backlog for P0 and a job description for any optional layer above it.

    python -m prismpath.bypass_report              # human-readable table
    python -m prismpath.bypass_report --json       # machine-readable, for committing as evidence

Deliberately has no pass/fail exit code on the rates themselves. This measures a known-defeatable
control; a high semantic bypass rate is the expected, publishable result, not a build failure. The
ONE assertion made is that the `identity` control stratum is 0.00 — if a seed the corpus says is
denied is not denied here, the harness is wrong and every other number is meaningless.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict

from prismpath import bypass_corpus
from prismpath.guard import compose, parse_policy

POLICIES_DIR = bypass_corpus.CORPUS.parent.parent.parent / "policies"


def _floor():
    src = (POLICIES_DIR / "statutory_floor.md").read_text(encoding="utf-8")
    return compose([parse_policy(src)])


def measure() -> dict:
    guard = _floor()
    variants = bypass_corpus.generate()

    # (rule, stratum) -> [bypassed, total]
    cells: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0])
    strata_class: dict[str, str] = {}
    examples: dict[tuple[str, str], str] = {}

    for v in variants:
        key = (v["rule"], v["stratum"])
        strata_class[v["stratum"]] = v["klass"]
        verdict = guard.check(v["variant"], v["direction"])
        cells[key][1] += 1
        if verdict.allowed:
            cells[key][0] += 1
            examples.setdefault(key, v["variant"])

    rules = sorted({r for r, _ in cells})
    strata = sorted(strata_class, key=lambda s: (
        {bypass_corpus.CONTROL: 0, bypass_corpus.MECHANICAL: 1, bypass_corpus.SEMANTIC: 2}[strata_class[s]],
        s,
    ))

    rollup: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for (_rule, stratum), (bypassed, total) in cells.items():
        klass = strata_class[stratum]
        rollup[klass][0] += bypassed
        rollup[klass][1] += total

    per_stratum: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for (_rule, stratum), (bypassed, total) in cells.items():
        per_stratum[stratum][0] += bypassed
        per_stratum[stratum][1] += total

    return {
        "variants": len(variants),
        "rules": rules,
        "strata": strata,
        "strata_class": strata_class,
        "cells": {f"{r}|{s}": cells[(r, s)] for (r, s) in cells},
        "per_stratum": {s: per_stratum[s] for s in strata},
        "rollup": dict(rollup),
        "examples": {f"{r}|{s}": t for (r, s), t in examples.items()},
    }


def measure_collisions() -> dict:
    """The hardening direction's control: benign text that must NEVER be denied.

    Bound is pre-registered at ZERO (docs/research/bypass-measurement.md §5.3) and gates the normalization change
    on its own. Widening what a regex catches is how an education product starts refusing innocent
    questions, and that failure would be unpublished — strictly worse than the one being fixed.
    """
    from prismpath import benign_corpus

    guard = _floor()
    per_stratum: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    per_split: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    false_matches = []

    for case in benign_corpus.generate():
        per_stratum[case["stratum"]][1] += 1
        per_split[case["split"]][1] += 1
        for direction in ("inbound", "outbound"):
            verdict = guard.check(case["text"], direction)
            if not verdict.allowed:
                per_stratum[case["stratum"]][0] += 1
                per_split[case["split"]][0] += 1
                false_matches.append({
                    "stratum": case["stratum"],
                    "split": case["split"],
                    "text": case["text"],
                    "direction": direction,
                    "rule": verdict.rule,
                })
                break

    total = sum(v[1] for v in per_stratum.values())
    hits = sum(v[0] for v in per_stratum.values())
    return {
        "cases": total,
        "false_matches": hits,
        "per_stratum": dict(per_stratum),
        "per_split": dict(per_split),
        "detail": false_matches,
    }


def _rate(cell: list[int]) -> float:
    return round(cell[0] / cell[1], 2) if cell[1] else 0.0


def render(report: dict) -> str:
    lines = []
    lines.append("=== P0 FLOOR — MEASURED BYPASS RATES ===")
    lines.append("protocol: docs/research/bypass-measurement.md (pre-registered)")
    lines.append(f"variants: {report['variants']}\n")
    lines.append("bypass rate = variants ALLOWED / variants generated. higher is worse.\n")

    width = max(len(s) for s in report["strata"]) + 2
    header = "stratum".ljust(width) + "class".ljust(12) + "rate".ljust(8) + "counts"
    lines.append(header)
    lines.append("-" * len(header))
    for s in report["strata"]:
        cell = report["per_stratum"][s]
        lines.append(
            s.ljust(width)
            + report["strata_class"][s].ljust(12)
            + f"{_rate(cell):.2f}".ljust(8)
            + f"{cell[0]}/{cell[1]}"
        )

    lines.append("\n--- per rule x stratum ---")
    for rule in report["rules"]:
        lines.append(f"\n  {rule}")
        for s in report["strata"]:
            key = f"{rule}|{s}"
            if key not in report["cells"]:
                continue
            cell = report["cells"][key]
            mark = "" if cell[0] == 0 else "  <-- bypassed"
            lines.append(f"    {s.ljust(width)}{_rate(cell):.2f}  ({cell[0]}/{cell[1]}){mark}")

    lines.append("\n--- rollup ---")
    for klass in ("control", "mechanical", "semantic"):
        if klass in report["rollup"]:
            cell = report["rollup"][klass]
            lines.append(f"  {klass.ljust(12)}{_rate(cell):.2f}  ({cell[0]}/{cell[1]})")

    control = report["rollup"].get("control", [0, 0])
    lines.append("")
    if control[0] == 0:
        lines.append("control stratum is 0.00 — the harness reproduces the corpus's denials.")
    else:
        lines.append(
            f"!! CONTROL STRATUM IS NOT 0.00 ({control[0]}/{control[1]}). The harness disagrees "
            "with the frozen corpus; every other number here is meaningless until that is fixed."
        )

    mech = report["rollup"].get("mechanical", [0, 0])
    sem = report["rollup"].get("semantic", [0, 0])
    lines.append("")
    lines.append("READING THIS TABLE (per docs/research/bypass-measurement.md §1):")
    lines.append(
        f"  mechanical {_rate(mech):.2f} — deterministic preprocessing (NFKC folding, confusable"
    )
    lines.append(
        "               mapping, zero-width stripping) can close these INSIDE P0, while the floor"
    )
    lines.append("               remains a grammar. This is the hardening backlog.")
    lines.append(
        f"  semantic   {_rate(sem):.2f} — unreachable by deterministic matching. This is the measured"
    )
    lines.append("               job description for an optional layer above, not a P0 defect.")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = ap.parse_args()

    report = measure()
    collisions = measure_collisions()
    report["collisions"] = collisions

    if args.json:
        print(json.dumps(report, indent=1, sort_keys=True, ensure_ascii=False))
    else:
        print(render(report))
        print("\n--- benign-collision control (bound: ZERO, per §5.3) ---")
        for split in ("dev", "holdout"):
            cell = collisions["per_split"].get(split, [0, 0])
            note = " (tuning may use this)" if split == "dev" else " (READ TO REPORT, NEVER TO DECIDE)"
            print(f"  {split.ljust(9)}{cell[0]}/{cell[1]} false matches{note}")
        print()
        for stratum in sorted(collisions["per_stratum"]):
            cell = collisions["per_stratum"][stratum]
            flag = "" if cell[0] == 0 else "   <-- FALSE MATCH"
            print(f"  {stratum.ljust(16)}{cell[0]}/{cell[1]} denied{flag}")
        if collisions["false_matches"] == 0:
            print(f"\n  0 false matches over {collisions['cases']} benign cases — bound held.")
        else:
            print(f"\n  !! {collisions['false_matches']} FALSE MATCHES over "
                  f"{collisions['cases']} benign cases — the bound is ZERO. Normalization is "
                  "blocked regardless of bypass rates.")
            for d in collisions["detail"][:10]:
                print(f"     [{d['rule']}] {d['text'][:70]!r}")

    # Hard failures: the control stratum must reproduce the corpus, AND benign text must not be
    # denied. Bypass rates themselves never fail the build — a known-defeatable control is being
    # measured, and a high semantic rate is the expected, publishable result.
    control = report["rollup"].get("control", [0, 0])
    return 1 if (control[0] or collisions["false_matches"]) else 0


if __name__ == "__main__":
    sys.exit(main())
