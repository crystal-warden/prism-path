# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""check_translators.py: the Phase 2 gate. Every system's translation of every corpus policy is
written to `systems/<id>/generated/<policy>/` and every scenario is decided by the real system;
the observed (outcome, rule) is compared to the corpus expectation.

Row classes:
  MATCH        observed outcome and rule equal the neutral expectation
  MISMATCH     they differ on a scenario the system should express: a translator defect, fails the gate
  PROBE        an `undeclared_missing` scenario: what the system returns there IS the measurement
               (dimension A1); recorded, never counted as a failure
  DROPPED      the expected rule is one the translation declared it cannot express: measured
               inexpressibility, recorded, not a failure
  UNEXPRESSIBLE the whole policy is outside the system
Reports land in `systems/<id>/generated/conformance.json` and on stdout. Exit 1 on any MISMATCH.

Usage: python -m prismpath.comparisons.check_translators [--system ID ...] [--policy ID ...]
"""
from __future__ import annotations

import argparse
import importlib
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List

from prismpath.comparisons.harness import (SYSTEMS_DIR, Decision, gen_dir_for, load_policies,
                                          scenario_steps, write_translation)

KNOWN = ("prismpath", "opa", "cedar", "cerbos", "openfga")


def check_system(system: str, policies: List[Dict[str, Any]], write: bool = True) -> Dict[str, Any]:
    mod = importlib.import_module(f"prismpath.comparisons.systems.{system}")
    rows, summary = [], {"MATCH": 0, "MISMATCH": 0, "PROBE": 0, "DROPPED": 0, "UNEXPRESSIBLE": 0}
    for pol in policies:
        tr = mod.translate(pol)
        gen = write_translation(system, pol, tr)
        if not tr.expressible:
            for sid, kind, _inp, exp in scenario_steps(pol):
                rows.append({"policy": pol["id"], "scenario": sid, "kind": kind, "class": "UNEXPRESSIBLE",
                             "expected": exp, "observed": asdict(Decision("not_expressible"))})
                summary["UNEXPRESSIBLE"] += 1
            continue
        runner = mod.Runner(pol, gen)
        try:
            for sid, kind, inp, exp in scenario_steps(pol):
                decision = runner.decide(inp)
                if exp.get("rule") in tr.dropped_rules:
                    cls = "DROPPED"
                elif kind == "undeclared_missing":
                    cls = "PROBE"
                elif decision.observed == exp["outcome"] and decision.rule == exp["rule"]:
                    cls = "MATCH"
                else:
                    cls = "MISMATCH"
                rows.append({"policy": pol["id"], "scenario": sid, "kind": kind, "class": cls,
                             "expected": exp, "observed": asdict(decision)})
                summary[cls] += 1
        finally:
            runner.close()
    report = {"system": system, "summary": summary, "rows": rows}
    if write:   # the committed report is Phase 2 evidence; the test re derives without overwriting it
        (SYSTEMS_DIR / system / "generated" / "conformance.json").write_text(
            json.dumps(report, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--system", action="append", choices=KNOWN)
    ap.add_argument("--policy", action="append")
    args = ap.parse_args(argv)
    systems = args.system or [system for system in KNOWN if (SYSTEMS_DIR / system / "__init__.py").exists()]
    policies = load_policies()
    if args.policy:
        policies = [policy for policy in policies if policy["id"] in args.policy]
    failed = False
    for system in systems:
        rep = check_system(system, policies)
        sm = rep["summary"]
        print(f"{system:10} MATCH {sm['MATCH']:3}  MISMATCH {sm['MISMATCH']:3}  PROBE {sm['PROBE']:2}  "
              f"DROPPED {sm['DROPPED']:2}  UNEXPRESSIBLE {sm['UNEXPRESSIBLE']:2}")
        for row in rep["rows"]:
            if row["class"] in ("MISMATCH", "PROBE", "DROPPED"):
                observed = row["observed"]
                print(f"    {row['class']:9} {row['policy']}/{row['scenario']}: expected {row['expected']['outcome']}/{row['expected']['rule']}"
                      f" observed {observed['observed']}/{observed['rule']} cause={observed['cause']}")
        failed |= sm["MISMATCH"] > 0
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
