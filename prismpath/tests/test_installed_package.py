# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""What an installed package must carry: the runtime data the CLI reads, the corpora, the compiler
references, the Mission Control assets, and the console entry point. When the acceptance run sets
PRISMPATH_ACCEPTANCE_INSTALLED=1 the test also insists that the package resolved from a site-packages
directory, so a source tree on the path cannot shadow the wheel under test."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import prismpath

PACKAGE = Path(prismpath.__file__).resolve().parent
REQUIRED = [
    "kernel/ppt_compile.py",
    "telemetry/canary_verify.py",
    "portable/conformance/flows.json",
    "portable/conformance/predicates.json",
    "telemetry/conformance/decisions.json",
    "tests/fixtures/compiler/SHA256SUMS",
    "tests/fixtures/compiler/anchored/incident_severity.ppt",
    "tests/fixtures/reference_hashes.json",
    "tests/fixtures/kappa_dataset.jsonl",
    "tests/fixtures/alert_router.md",
    "tests/fixtures/broken/terminal_with_body.md",
    "mission_control/static/index.html",
    "mission_control/static/app.js",
    "mission_control/static/style.css",
    "mission_control/static/vendor/cytoscape.min.js",
    "mission_control/static/vendor/cytoscape.LICENSE",
    "gallery/pr_review/pr_review.md",
    "gallery/pr_review/pr_review.tests.md",
    "flows/wazuh_triage.md",
    "policies/p1_lockfile.json",
    "policies/statutory_floor.md",
    "nudges/APP_ARCHITECTURE.md",
    "plugins/pysprint/ARCH.md",
]


def test_required_package_data_is_present():
    missing = [path for path in REQUIRED if not (PACKAGE / path).exists()]
    assert not missing, f"missing from the installed package: {missing}"


def test_package_resolves_from_site_packages_when_acceptance_says_so():
    if os.environ.get("PRISMPATH_ACCEPTANCE_INSTALLED") != "1":
        return
    assert "site-packages" in PACKAGE.parts, f"prismpath imported from {PACKAGE}, not from an installation"


def test_console_entry_point_runs():
    executable = shutil.which("prismpath")
    if os.environ.get("PRISMPATH_ACCEPTANCE_INSTALLED") == "1":
        assert executable, "the prismpath console script is not on PATH"
    command = [executable, "--help"] if executable else [sys.executable, "-m", "prismpath", "--help"]
    completed = subprocess.run(command, capture_output=True, text=True)
    assert completed.returncode == 0
    assert "commands, by who runs them" in completed.stdout


def test_module_entry_points_run():
    for module in ("prismpath.kernel.ppt_compile", "prismpath.telemetry.canary_verify"):
        completed = subprocess.run([sys.executable, "-m", module, "--help"], capture_output=True, text=True)
        assert completed.returncode == 0, f"{module} --help failed: {completed.stderr}"
