# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""tools/acceptance.sh removes the temporary directory it made on every exit: a pass, a failure and an
interruption, after printing the report; PRISMPATH_ACCEPTANCE_KEEP=1 keeps it, and a directory named by
--out is the caller's and stays. Driven over the Rust leg in a throwaway repository holding only the
script, with a stand in `cargo` on PATH that passes, fails or hangs, and TMPDIR pointed at a directory
of the test's own, so the check is that this directory is empty afterwards."""
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "acceptance.sh"
CRATES = ("prismpath-rs", "prismpath-telemetry-rs", "prismpath-hotswap-rs", "prismpath-preflight")

# A stand in cargo for the Rust leg's gates. pass: every command succeeds, `package` writes a crate file
# holding a tests directory and `metadata` describes the extracted candidates; fail: every command fails;
# hang: every command sleeps (the interruption case).
FAKE_CARGO = r'''
import json, os, sys, tarfile, io, time
from pathlib import Path
mode = os.environ["FAKE_CARGO_MODE"]
args = sys.argv[1:]
if mode == "fail":
    sys.exit(1)
if mode == "hang":
    time.sleep(120); sys.exit(1)
crates = %r
if args[:1] == ["package"] and "--list" in args:
    print("Cargo.toml\ntests/it.rs"); sys.exit(0)
if args[:1] == ["package"]:
    target = Path(os.environ["CARGO_TARGET_DIR"]) / "package"; target.mkdir(parents=True, exist_ok=True)
    for crate in crates:
        with tarfile.open(target / f"{crate}-0.0.0.crate", "w:gz") as tar:
            for name, data in ((f"{crate}-0.0.0/Cargo.toml", b"[package]\n"), (f"{crate}-0.0.0/tests/it.rs", b"")):
                info = tarfile.TarInfo(name); info.size = len(data); tar.addfile(info, io.BytesIO(data))
    sys.exit(0)
if args[:1] == ["metadata"]:
    here = Path.cwd()
    packages = [{"id": c, "name": c, "version": "0.0.0", "source": None, "dependencies": [],
                 "manifest_path": str(here / f"{c}-0.0.0" / "Cargo.toml")} for c in crates]
    print(json.dumps({"packages": packages, "resolve": {"nodes": [{"id": c, "dependencies": []} for c in crates]}}))
    sys.exit(0)
print("cargo 0.0.0 (stand in)"); sys.exit(0)
''' % (CRATES,)


@pytest.fixture
def repo(tmp_path):
    """A repository holding only the script, a bin directory with the stand in cargo, and a TMPDIR."""
    root = tmp_path / "repo"
    (root / "tools").mkdir(parents=True)
    shutil.copy(SCRIPT, root / "tools" / "acceptance.sh")
    git = ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(git + ["add", "-A"], check=True)
    subprocess.run(git + ["commit", "-q", "-m", "only the script"], check=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    cargo = bin_dir / "cargo"
    cargo.write_text(f"#!{sys.executable}\n{FAKE_CARGO}")
    cargo.chmod(0o755)
    temp = tmp_path / "tmp"
    temp.mkdir()
    return root, bin_dir, temp


def _env(bin_dir, temp, mode, **extra):
    env = dict(os.environ, PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}", TMPDIR=str(temp),
               FAKE_CARGO_MODE=mode, PYTHON=sys.executable)
    env.pop("PRISMPATH_ACCEPTANCE_KEEP", None)
    env.update(extra)
    return env


def _run(repo, mode, *args, **extra):
    root, bin_dir, temp = repo
    return subprocess.run(["bash", str(root / "tools" / "acceptance.sh"), "--leg", "rust", *args],
                          env=_env(bin_dir, temp, mode, **extra), capture_output=True, text=True, timeout=120)


def test_a_passing_run_leaves_nothing_behind(repo):
    completed = _run(repo, "pass")
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "RESULT: all gates passed" in completed.stdout
    assert list(repo[2].iterdir()) == []


def test_a_failing_run_leaves_nothing_behind_and_says_how_to_keep_it(repo):
    completed = _run(repo, "fail")
    assert completed.returncode == 1, completed.stdout + completed.stderr
    assert "RESULT: FAILED gates present" in completed.stdout
    assert "PRISMPATH_ACCEPTANCE_KEEP=1" in completed.stderr
    assert list(repo[2].iterdir()) == []


def test_keep_keeps_the_directory_and_out_is_the_callers(repo, tmp_path):
    completed = _run(repo, "fail", PRISMPATH_ACCEPTANCE_KEEP="1")
    kept = [path for path in repo[2].iterdir() if path.name.startswith("prismpath-acceptance-")]
    assert len(kept) == 1 and (kept[0] / "report.md").is_file(), completed.stderr
    shutil.rmtree(kept[0])
    named = tmp_path / "named-out"
    _run(repo, "fail", "--out", str(named))
    assert (named / "report.md").is_file()
    assert list(repo[2].iterdir()) == []


@pytest.mark.parametrize("signum, status", [(signal.SIGINT, 130), (signal.SIGTERM, 143)])
def test_an_interrupted_run_leaves_nothing_behind(repo, signum, status):
    root, bin_dir, temp = repo
    process = subprocess.Popen(["bash", str(root / "tools" / "acceptance.sh"), "--leg", "rust"],
                               env=_env(bin_dir, temp, "hang"), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        made = [path for path in temp.iterdir() if path.name.startswith("prismpath-acceptance-")]
        if made and (made[0] / "report.md").exists():
            break
        time.sleep(0.1)
    time.sleep(1)                                       # inside the hanging `cargo --version`
    os.killpg(process.pid, signum)                      # as a terminal delivers it, to the whole group
    process.communicate(timeout=60)
    assert process.returncode == status
    assert list(temp.iterdir()) == []
