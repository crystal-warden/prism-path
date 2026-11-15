# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""'Run any program as a worker' (docs/guides/workers.md), proven with two language workers, all on one contract (read stdin, print one JSON object, exit 0; a nonzero exit -> error tier):

  - Python  ci_gate.py      : a CI test / coverage gate
  - Rust    ci_gate.rs      : the SAME gate, second language (one job ports across languages, no flow change)

Python always runs. Rust runs only if rustc is installed, so a Python only run still
exercises the contract via the Python worker, and the compiled workers are recertified anywhere their
compiler exists."""
import os
import shutil
import subprocess
import sys

import pytest

from prismpath.kernel.parser import parse_file
from prismpath.kernel.engine import run
from prismpath.workers.cli_worker import cli_worker

from prismpath.tests._repo import repo_file

HERE = os.path.dirname(__file__)
EX = str(repo_file("prismpath", "examples", "cli_worker", "ci_gate.rs").parent)


def _route(flow, cmd, pass_state, seed):
    worker = cli_worker(cmd, pass_state=pass_state)
    return run(parse_file(os.path.join(EX, flow)), worker, state=seed, max_steps=5).path[-1]


def test_python_ci_gate():
    cmd = [sys.executable, os.path.join(EX, "ci_gate.py")]
    route = lambda report: _route("ci_gate.md", cmd, ["report"], {"report": report})   # noqa: E731
    assert route("tests=48 failed=0 coverage=91") == "ship"
    assert route("tests=48 failed=0 coverage=71") == "low_coverage"
    assert route("tests=48 failed=3 coverage=91") == "triage"
    assert route("build broke, no numbers") == "error_hold"       # unparseable -> nonzero exit -> error tier


@pytest.mark.cross_language
@pytest.mark.skipif(shutil.which("rustc") is None, reason="rust toolchain not installed")
def test_rust_ci_gate(tmp_path):
    binary = str(tmp_path / "ci_gate")
    subprocess.run(["rustc", "-O", os.path.join(EX, "ci_gate.rs"), "-o", binary], check=True)
    route = lambda report: _route("ci_gate.md", [binary], ["report"], {"report": report})  # noqa: E731
    assert route("tests=48 failed=0 coverage=91") == "ship"       # same flow as ci_gate.py, second language
    assert route("tests=48 failed=0 coverage=71") == "low_coverage"
    assert route("tests=48 failed=3 coverage=91") == "triage"
    assert route("build broke, no numbers") == "error_hold"
