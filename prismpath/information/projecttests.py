# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The `tests` information point: `tests_pass`, whether the project's own test command passes on a scratch copy of the
project with the edit applied (gate/escalate.py `run_project_tests` of the Context Cloud gate tracer).

  tests_pass   `true`, `false` or `not_run`. Restrictive value `false`.

`true` only when the command ran on the scratch copy and exited 0. `false` for every other end: a failing run, a
timeout, a command that cannot start, an edit that cannot be applied, a copy that cannot be made, a point with no
command, and any exception. `not_run` is not an error: it is what a point reads when it was not asked to spend the
time, because the tests are the slow fact. The caller decides that by giving the point `should_run`, a function of
the change, and a point with none runs nothing and reads `not_run`. No rule of the tracer's delegate policy routed on
`not_run`, and a policy that does should say what it means by it.

The command runs the project's code with the edit in it, which is the agent's code. The point does not confine it. The
caller gives a `command` that does (a sandbox, a memory cap, a timeout), and there is no default command: the tracer's
default was Context Cloud's own (`systemd-run`, `.venv`), and a default that runs agent written code unconfined is not
one to ship. This module imports no other prismpath package.
"""
from __future__ import annotations

import fnmatch
import os
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Optional, Sequence, Tuple

from prismpath.ports.information import Change, Evidence

NAME = "tests"
TESTS_PASS = ("true", "false", "not_run")
SUMMARY_MAX = 300


@dataclass
class TestConfig:
    """The project's test command. `command` is an argument list; `{project}` is the scratch copy and `{timeout}` the
    seconds. `link` names entries of the project that are linked into the copy, not copied (a virtual environment)."""
    __test__ = False                       # not a pytest class
    command: Sequence[str]
    timeout: int = 1500
    env: Dict[str, str] = field(default_factory=dict)
    link: Sequence[str] = ()
    skip: Sequence[str] = (".git", "__pycache__", ".pytest_cache", "*.pyc", ".mypy_cache", ".ruff_cache")


@dataclass
class TestsResult:
    __test__ = False
    ok: bool
    summary: str
    seconds: float = 0.0


def _reap(proc: subprocess.Popen) -> None:
    """Kill the command's whole process group and wait."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)
        except (ProcessLookupError, PermissionError):
            break
        try:
            proc.wait(timeout=5)
            break
        except subprocess.TimeoutExpired:
            continue
    try:
        proc.communicate(timeout=2)
    except Exception:  # noqa: BLE001
        pass


def run_project_tests(project_root: Path, relative: str, new_text: str, config: TestConfig,
                      scratch_parent: Optional[Path] = None) -> TestsResult:
    """Apply the edit (the file's new text) to a scratch copy of the project and run the test command there. Never
    raises: a failure to run is a false with the reason as its summary. The project itself is never touched."""
    started = time.time()
    scratch = Path(tempfile.mkdtemp(prefix="gate-tests-", dir=str(scratch_parent) if scratch_parent else None))
    try:
        copy = scratch / "project"
        top = Path(project_root)
        target = (copy / relative).resolve()
        if Path(relative).is_absolute() or copy.resolve() not in target.parents:
            return TestsResult(False, "the edited path is not inside the project", time.time() - started)

        def ignore(directory, names):
            drop = [n for n in names if any(fnmatch.fnmatch(n, pat) for pat in config.skip)]
            if Path(directory) == top:
                drop += [n for n in names if n in config.link]
            return drop

        shutil.copytree(project_root, copy, symlinks=True, ignore=ignore)
        for name in config.link:
            if (Path(project_root) / name).exists():
                os.symlink((Path(project_root) / name).resolve(), copy / name)
        if (copy / relative).is_symlink():
            return TestsResult(False, "the edited path is a link", time.time() - started)
        (copy / relative).write_text(new_text)
        cmd = [part.format(project=str(copy), timeout=config.timeout) for part in config.command]
        env = {**os.environ, "PYTHONPATH": str(copy), **config.env}
        proc = subprocess.Popen(cmd, cwd=copy, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env,
                                start_new_session=True)
        try:
            text, _err = proc.communicate(timeout=config.timeout + 10)
        except subprocess.TimeoutExpired:
            _reap(proc)
            return TestsResult(False, f"the test command did not finish in {config.timeout} s", time.time() - started)
        out = (text or "").strip().splitlines()
        summary = next((line.strip() for line in reversed(out) if line.strip()), "no output")
        return TestsResult(proc.returncode == 0, summary[:SUMMARY_MAX], time.time() - started)
    except BaseException as exc:  # noqa: BLE001 - any failure to run is a false
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        return TestsResult(False, f"the tests could not be run: {type(exc).__name__}: {exc}"[:SUMMARY_MAX],
                           time.time() - started)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


class ProjectTests:
    """The `tests` information point (see the module docstring)."""

    name = NAME
    fields = {"tests_pass": TESTS_PASS}
    restrictive = {"tests_pass": "false"}
    control_paths: Tuple[str, ...] = ()

    def __init__(self, project_root: Path, config: Optional[TestConfig] = None,
                 should_run: Optional[Callable[[Change], bool]] = None,
                 run: Callable[..., TestsResult] = run_project_tests):
        self.project_root, self.config, self.should_run, self._run = Path(project_root), config, should_run, run

    def facts(self, change: Change, budget_s: float) -> Evidence:
        try:
            if self.should_run is None or self.should_run(change) is not True:
                return Evidence({"tests_pass": "not_run"}, frozenset(), "", {})
            edit = getattr(change, "edit", None)
            if self.config is None:
                return self._false("no test command is configured")
            if edit is None or not isinstance(edit.relative, str) or not isinstance(edit.new, str):
                return self._false("the edit cannot be applied to a scratch copy")
            result = self._run(self.project_root, edit.relative, edit.new, self.config)
            value = "true" if result.ok is True else "false"
            return Evidence({"tests_pass": value}, frozenset(), "" if value == "true" else result.summary,
                            {"summary": result.summary, "seconds": round(result.seconds, 1)})
        except Exception as exc:   # noqa: BLE001 - a point that fails says nothing, which is its restrictive value
            return self._false(f"the point failed ({type(exc).__name__})")

    def _false(self, why: str) -> Evidence:
        return Evidence(dict(self.restrictive), frozenset(), why, {})
