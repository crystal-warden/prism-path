# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Shared plumbing for the Group A runners: the result file writer (results/SCHEMA.md), evidence
directories, the pinned system versions (toolchain/TOOLCHAIN.md), and the harness commit."""
from __future__ import annotations

import datetime as _dt
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from prismpath.comparisons.harness import HERE, load_policies

RESULTS = HERE / "results"
SYSTEM_VERSION = {"prismpath": "repo@harness_commit", "opa": "1.20.2", "cedar": "4.12.0",
                  "cerbos": "0.55.0", "openfga": "1.19.0", "openlane": "docs-only",
                  "opa+glue": "1.20.2+glue", "cedar+glue": "4.12.0+glue", "cerbos+glue": "0.55.0+glue"}
GRADES = ("NATIVE", "WITH-WORK", "NOT")


def harness_commit() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True,
                              cwd=str(HERE), timeout=10).stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def evidence_dir(system: str, dimension: str) -> Path:
    d = RESULTS / system / "evidence" / dimension
    d.mkdir(parents=True, exist_ok=True)
    return d


def policy_by_id(pid: str) -> Dict[str, Any]:
    return next(p for p in load_policies() if p["id"] == pid)


def write_result(*, system: str, dimension: str, policy: str, scenario: str, expected: Optional[str],
                 observed: str, grade: str, idiomatic: bool, evidence_path: Path, notes: str,
                 glue: Optional[Dict[str, Any]] = None, measurements: Optional[Dict[str, Any]] = None) -> Path:
    assert grade in GRADES, grade
    if grade == "WITH-WORK":
        assert glue and all(k in glue for k in ("description", "components", "loc", "hours")), "WITH-WORK needs glue"
    doc: Dict[str, Any] = {
        "system": system,
        "system_version": SYSTEM_VERSION[system] if SYSTEM_VERSION[system] != "repo@harness_commit" else f"repo@{harness_commit()}",
        "dimension": dimension,
        "policy": policy,
        "scenario": scenario,
        "expected": expected,
        "observed": observed,
        "match": (expected is not None and observed == expected),
        "grade": grade,
        "idiomatic": idiomatic,
        "glue": glue,
        "evidence_path": str(evidence_path.relative_to(HERE.parent.parent)) if evidence_path.is_absolute() else str(evidence_path),
        "harness_commit": harness_commit(),
        "run_at": now_iso(),
        "notes": notes,
    }
    if measurements:
        doc["measurements"] = measurements
    out = RESULTS / system
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"{dimension}__{policy}__{scenario}.json"
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def sha256_file(p: Path) -> str:
    import hashlib
    return hashlib.sha256(p.read_bytes()).hexdigest()
