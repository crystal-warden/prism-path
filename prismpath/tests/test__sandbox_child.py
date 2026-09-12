# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Tests for _sandbox_child module."""

import json
import subprocess
import sys


def test_subprocess_protocol_success():
    job = {
        "module": "prismpath.tests._sandbox_probes",
        "func": "ok",
        "node": "node_1",
        "instruction": "run probe",
        "state": {"k": "v"},
        "mem_mb": 256,
    }
    proc = subprocess.run(
        [sys.executable, "-m", "prismpath.workers._sandbox_child"],
        input=json.dumps(job),
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert proc.returncode == 0
    res = json.loads(proc.stdout)
    assert res["ok"] is True
    assert res["outcome"] == {"v": 1, "text": "ok"}


def test_subprocess_protocol_error_bad_module():
    job = {
        "module": "prismpath.nonexistent_module_12345",
        "func": "foo",
        "node": "n",
    }
    proc = subprocess.run(
        [sys.executable, "-m", "prismpath.workers._sandbox_child"],
        input=json.dumps(job),
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert proc.returncode == 1
    res = json.loads(proc.stdout)
    assert res["ok"] is False
    assert "ModuleNotFoundError" in res["error"] or "ImportError" in res["error"]


def test_subprocess_protocol_error_bad_json():
    proc = subprocess.run(
        [sys.executable, "-m", "prismpath.workers._sandbox_child"],
        input="invalid json content {{{",
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert proc.returncode == 1
    res = json.loads(proc.stdout)
    assert res["ok"] is False
    assert "bad job" in res["error"]


def test_subprocess_protocol_handler_exception():
    job = {
        "module": "prismpath.tests._sandbox_probes",
        "func": "write_file",
        "node": "n",
        "instruction": "",
        "state": {},  # missing 'target' key in state -> KeyError
    }
    proc = subprocess.run(
        [sys.executable, "-m", "prismpath.workers._sandbox_child"],
        input=json.dumps(job),
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert proc.returncode == 1
    res = json.loads(proc.stdout)
    assert res["ok"] is False
    assert "KeyError" in res["error"]
