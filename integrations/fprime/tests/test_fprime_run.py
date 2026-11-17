# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The end to end run in the F Prime reference deployment (run_scenario.py), skipped without an F Prime build.

It needs the PrismPathRef deployment built (`fprime-util build` in integrations/fprime) and F Prime's tools in a
virtual environment (the default is .cfs-build/fpvenv at the repository root, or FPRIME_VENV). Without them it skips,
saying why; the byte comparison with the cFS app's receipts does not need them (test_fprime_conformance.py).
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from integrations.fprime.tests import run_scenario

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]


def test_the_s1_sequence_through_the_gds_integration_test_api_and_the_ground_verification():
    pytest.importorskip("cryptography", reason="signing and verifying a core run needs the signing extra")
    venv = Path(os.environ.get("FPRIME_VENV", REPO / ".cfs-build" / "fpvenv"))
    if not run_scenario.tools_present(venv):
        pytest.skip("no built PrismPathRef deployment (fprime-util build in integrations/fprime) "
                    "or no F Prime tools virtual environment (FPRIME_VENV)")
    done = subprocess.run([sys.executable, str(HERE / "run_scenario.py"), "--fprime-venv", str(venv)],
                          capture_output=True, text=True, timeout=600)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "run_scenario: all checks passed" in done.stdout
