# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""'Run any program as a worker' (docs/guides/workers.md), proven with four language workers across three
jobs, all on one contract (read stdin, print one JSON object, exit 0; a nonzero exit -> error tier):

  - Python  ci_gate.py      : a CI test / coverage gate
  - Rust    ci_gate.rs      : the SAME gate, second language (one job ports across languages, no flow change)
  - JS      log_alert.js    : log-line severity + latency alerting
  - Go      release_gate.go : a semver release gate

Python always runs. Node, Rust, and Go run only if their toolchain is installed, so CI (Python-only) still
exercises the contract via the Python worker, and the compiled workers are recertified anywhere their
compiler exists."""
import os
import shutil
import subprocess
import sys

import pytest

from prismpath.parser import parse_file
from prismpath.engine import run
from prismpath.cli_worker import cli_agent

HERE = os.path.dirname(__file__)
EX = os.path.abspath(os.path.join(HERE, "..", "examples", "cli_worker"))


def _route(flow, cmd, pass_state, seed):
    agent = cli_agent(cmd, pass_state=pass_state)
    return run(parse_file(os.path.join(EX, flow)), agent, state=seed, max_steps=5).path[-1]


def test_python_ci_gate():
    cmd = [sys.executable, os.path.join(EX, "ci_gate.py")]
    r = lambda report: _route("ci_gate.md", cmd, ["report"], {"report": report})   # noqa: E731
    assert r("tests=48 failed=0 coverage=91") == "ship"
    assert r("tests=48 failed=0 coverage=71") == "low_coverage"
    assert r("tests=48 failed=3 coverage=91") == "triage"
    assert r("build broke, no numbers") == "error_hold"       # unparseable -> nonzero exit -> error tier


@pytest.mark.skipif(shutil.which("rustc") is None, reason="rust toolchain not installed")
def test_rust_ci_gate(tmp_path):
    binary = str(tmp_path / "ci_gate")
    subprocess.run(["rustc", "-O", os.path.join(EX, "ci_gate.rs"), "-o", binary], check=True)
    r = lambda report: _route("ci_gate.md", [binary], ["report"], {"report": report})  # noqa: E731
    assert r("tests=48 failed=0 coverage=91") == "ship"       # same flow as ci_gate.py, second language
    assert r("tests=48 failed=0 coverage=71") == "low_coverage"
    assert r("tests=48 failed=3 coverage=91") == "triage"
    assert r("build broke, no numbers") == "error_hold"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_js_log_alert():
    cmd = ["node", os.path.join(EX, "log_alert.js")]
    r = lambda line: _route("log_alert.md", cmd, ["line"], {"line": line})         # noqa: E731
    assert r("ERROR api latency=1900ms db timeout") == "page_oncall"
    assert r("WARN api latency=1500ms") == "slow_warn"
    assert r("INFO request latency=120ms") == "archive"
    assert r("garbage with no level") == "error_hold"


@pytest.mark.skipif(shutil.which("go") is None, reason="go toolchain not installed")
def test_go_release_gate(tmp_path):
    binary = str(tmp_path / "release_gate")
    subprocess.run(["go", "build", "-o", binary, os.path.join(EX, "release_gate.go")], check=True)
    r = lambda frm, to: _route("release_gate.md", [binary], ["from", "to"], {"from": frm, "to": to})  # noqa: E731
    assert r("1.4.2", "2.0.0") == "block"
    assert r("1.4.2", "1.4.3") == "auto_publish"
    assert r("1.4.2", "1.5.0") == "needs_review"
    assert r("1.4.2", "x.y.z") == "error_hold"                # unparseable -> nonzero exit -> error tier
