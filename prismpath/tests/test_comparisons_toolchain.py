# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Phase 1 of the layer comparison: the comparator toolchain is at the PINNED versions.

The binaries live in a gitignored directory installed by toolchain/install.sh, so bare CI has none
of them and this module skips. On a box that has run the installer it asserts that every binary
reports exactly the version PREREGISTRATION's Phase 1 pinned, so a result file can never cite a
version the toolchain does not actually hold.
"""
import subprocess
from pathlib import Path

import pytest

from prismpath.tests._repo import repo_file, REPO_ROOT

BIN = REPO_ROOT / "prismpath" / "comparisons" / ".toolchain" / "bin"
PINS = {"opa": "1.20.2", "cedar": "4.12.0", "cerbos": "0.55.0", "openfga": "1.19.0"}
VERSION_ARGS = {"opa": ["version"], "cedar": ["--version"], "cerbos": ["--version"], "openfga": ["version"]}

pytestmark = pytest.mark.skipif(not BIN.is_dir(), reason="comparator toolchain not installed (toolchain/install.sh)")


def _version_output(name: str) -> str:
    exe = BIN / name
    if not exe.exists():
        pytest.skip(f"{name} not installed yet")
    out = subprocess.run([str(exe), *VERSION_ARGS[name]], capture_output=True, text=True, timeout=30)
    return out.stdout + out.stderr


@pytest.mark.parametrize("name", sorted(PINS))
def test_binary_reports_pinned_version(name):
    assert PINS[name] in _version_output(name), f"{name} is not at the pinned {PINS[name]}"


def test_install_script_pins_match_this_test():
    script = repo_file("prismpath", "comparisons", "toolchain", "install.sh").read_text()
    assert "OPA_VERSION=v" + PINS["opa"] in script
    assert "CEDAR_CLI_VERSION=" + PINS["cedar"] in script
    assert "CERBOS_VERSION=" + PINS["cerbos"] in script
    assert "FGA_VERSION=" + PINS["openfga"] in script
