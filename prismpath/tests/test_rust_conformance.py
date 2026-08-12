"""The Rust kernel must stay CONFORMANT — certification as a gate, not an event.

`prismpath-rs` was certified against the frozen vectors on 2026-07-29 and re-verified on every run
(now 1079/1079 predicates, 27/27 flows — `prismpath-rs/CONFORMANCE.md`). A one-time certificate decays the moment either
side changes; running the binary here makes drift a red test instead of a discovery. Together
with `test_portable_conformance.py` (Python ↔ .mjs) and `test_conformance_vectors.py` (vectors ↔
live Python), every implementation is re-certified on every pytest run.

Skips cleanly where cargo is not installed — the .mjs and Python gates still run there, and the
Rust gate runs wherever the crate can build at all.
"""
import shutil
import subprocess
from pathlib import Path

import pytest

CARGO = shutil.which("cargo")
pytestmark = pytest.mark.skipif(CARGO is None, reason="cargo not installed — Rust kernel untested here")

REPO_ROOT = Path(__file__).resolve().parents[2]
CRATE = REPO_ROOT / "prismpath-rs"
CORPUS = REPO_ROOT / "prismpath" / "portable" / "conformance"


def test_rust_kernel_is_conformant():
    proc = subprocess.run(
        [CARGO, "run", "-q", "--bin", "conformance", "--", str(CORPUS)],
        cwd=CRATE,
        capture_output=True,
        text=True,
        timeout=600,  # includes a possible cold compile
    )
    assert proc.returncode == 0, (
        "prismpath-rs diverged from the frozen kernel spec:\n"
        f"{proc.stdout}\n{proc.stderr}"
    )
    assert "CONFORMANT" in proc.stdout
