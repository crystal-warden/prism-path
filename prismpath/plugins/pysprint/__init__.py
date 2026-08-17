# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""pysprint — a Python gate plugin for the sprint control plane.

The browser gate (`gates.py`) proves a web app by loading it in a headless browser. This
plugin proves a *Python* project the way this repo proves everything else: it runs pytest and
the exit status is the verdict. It is the gate that lets a sprint improve the repo's own Python
modules (Mission Control being the first), with the frozen "every invariant has a gate" rule
applied literally — a unit is done when its acceptance test passes, never when the coder says so.

The gate seam (`docs/design/architecture.md` §3): the engine only ever touches the attribute
surface below, so the target's specifics live here and nowhere else.

Layout it expects in `SPRINT_PROJ`:
  - the module(s) under improvement (e.g. `mission_control.py`, `mission_control.html`)
  - `test_*.py` acceptance tests (the definition of done, operator-authored)
It runs `pytest` over the project dir with the project on `sys.path`, so `import mission_control`
resolves to the sandbox copy.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

# --- gate-plugin attribute surface (architecture.md §3) -----------------------
HAS_SPEC_LAYER = False                 # tests are operator-authored, not coder-generated per unit
ARCH_PATH = os.path.join(os.path.dirname(__file__), "ARCH.md")
LESSONS_PATH = os.path.join(os.path.dirname(__file__), "LESSONS.md")
RAG_INDEX = ""                         # no bundled index; SPRINT_RAG_INDEX may still be set
FILE_EXTS = (".py", ".html", ".css", ".txt", ".md")
SOURCE_DIRS = ("",)                    # flat project — sources live at the root
KG_SOURCE_DIRS = ("",)
CORE_DIR = ""
ENTRY_FILES = ()                       # no single entry point; the KG `produces` names the target
SPEC_SUFFIXES = ()                     # no spec layer (HAS_SPEC_LAYER False)
TESTABLE_DIRS = ("",)
PLANNER_NOTE = ("The target is a Python module improved test-first: each requirement already has "
                "a pytest acceptance test; make it pass without breaking the others.")
BUILD_RULES = (
    "Edit ONLY the file named by the current requirement's `produces`. Emit it WHOLE, as "
    "`FILE: <path>` then a fenced block. Do not add dependencies outside the Python standard "
    "library and what the module already imports. Do not edit the `test_*.py` files — they are "
    "the gate. Keep the module importable at all times (a syntax error fails every test)."
)
BUILD_RULES_SPEC = BUILD_RULES

_PYTEST_TIMEOUT = int(os.environ.get("PYSPRINT_TEST_TIMEOUT", "300"))
# pytest summary lines like "FAILED test_x.py::test_y - AssertionError: ..." and collection errors
_FAIL_RE = re.compile(r"^(FAILED|ERROR)\s+(\S+)", re.MULTILINE)


# Gate integrity: if PYSPRINT_FROZEN_TESTS names a directory, the gate runs the acceptance
# tests from THERE (module still imported from the sandbox via PYTHONPATH), so a coder that
# edits its own in-sandbox test copy gains nothing — the gate never runs the sandbox's tests.
# Unset -> the gate runs the project's own test_*.py (default, backward compatible).
_FROZEN = os.environ.get("PYSPRINT_FROZEN_TESTS", "")


def _test_files(proj: str) -> list:
    d = _FROZEN or proj
    return sorted(os.path.join(d, f) for f in os.listdir(d)
                  if f.startswith("test_") and f.endswith(".py"))


def validate(proj: str) -> dict:
    """Run the sandbox's pytest acceptance suite. Green iff pytest exits 0 with tests present.

    Returns the gate dict the sprint loop reads: `valid` plus a human-readable `errs` list whose
    entries name the failing test files (so `fix()` pastes the right source back to the coder).
    `oversized`/`biggest*` are reported for parity with the browser gate's dict shape.
    """
    tests = _test_files(proj)
    if not tests:
        return {"valid": False, "errs": ["no test_*.py acceptance tests in project"],
                "oversized": False, "oversized_file": "", "biggest": 0, "biggest_file": ""}

    env = dict(os.environ)
    env["PYTHONPATH"] = proj + os.pathsep + env.get("PYTHONPATH", "")
    try:
        r = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "--no-header", "-p", "no:cacheprovider", *tests],
            cwd=proj, env=env, capture_output=True, text=True, timeout=_PYTEST_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"valid": False, "errs": [f"pytest exceeded {_PYTEST_TIMEOUT}s (a hang or a "
                                         f"blocking call in the module under test)"],
                "oversized": False, "oversized_file": "", "biggest": 0, "biggest_file": ""}
    out = (r.stdout or "") + (r.stderr or "")

    biggest_file, biggest = "", 0
    for f in os.listdir(proj):
        p = os.path.join(proj, f)
        if os.path.isfile(p) and f.endswith(FILE_EXTS):
            n = os.path.getsize(p) // 4          # rough token estimate, gates.py convention
            if n > biggest:
                biggest, biggest_file = n, f

    if r.returncode == 0:
        return {"valid": True, "errs": [], "oversized": False, "oversized_file": "",
                "biggest": biggest, "biggest_file": biggest_file}

    errs = []
    for m in _FAIL_RE.finditer(out):
        errs.append(f"{m.group(1)} {m.group(2)}")
    if not errs:                                 # pytest died before reporting (import/syntax)
        tail = [ln for ln in out.splitlines() if ln.strip()][-6:]
        errs = tail or [f"pytest exited {r.returncode} with no parseable failures"]
    return {"valid": False, "errs": errs, "oversized": False, "oversized_file": "",
            "biggest": biggest, "biggest_file": biggest_file}
