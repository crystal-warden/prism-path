# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The `tests` information point: `tests_pass`, whether the project's own test command passes on a scratch copy of the
project with the edit applied (gate/escalate.py `run_project_tests` of the Context Cloud gate tracer).

  tests_pass   `true`, `false` or `not_run`. Restrictive value `false`.

`true` only when the command ran on the scratch copy, exited 0 and its last line is a pytest summary with at least one
test passed and none failed or in error (`passed`). `false` for every other end: a failing run, a
timeout, a command that cannot start, an edit that cannot be applied, a copy that cannot be made, a point with no
command, and any exception. `not_run` is not an error: it is what a point reads when it was not asked to spend the
time, because the tests are the slow fact. The caller decides that by giving the point `should_run`, a function of
the change, and a point with none runs nothing and reads `not_run`. No rule of the tracer's delegate policy routed on
`not_run`, and a policy that does should say what it means by it.

The command runs the project's code with the edit in it, which is the agent's code. The point does not confine it. The
caller gives a `command` that does (a sandbox, a memory cap, a timeout), and there is no default command: the tracer's
default was Context Cloud's own (`systemd-run`, `.venv`), and a default that runs agent written code unconfined is not
one to ship. The command gets a minimal environment (PATH, HOME at the scratch, LANG, PYTHONPATH) unless `inherit_env`.

`true` is NEVER enough alone. The run is judged by the code it runs, and the edit is part of that code: an edit can make
the tests pass or never reach them. An edit to a test file or a test configuration is not run (it reads false). A policy
that allows on `tests_pass` must also require what the facts of the other points say about the edit. A policy is held to
`not_run` allowing nothing `false` does not (prismpath/agent/target.py). This module imports no other prismpath package.
"""
from __future__ import annotations

import fnmatch
import os
import re
import shutil
import signal
import stat
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
MAX_COPY_BYTES = 200_000_000     # a project larger than this is not copied; the point reads false
MAX_COPY_FILES = 50_000
PASS_LINE = re.compile(r"^\W*(\d+) passed\b")
BAD_WORD = re.compile(r"\b(?:failed|errors?)\b")
CONFIG_NAMES = ("conftest.py", "pytest.ini", "tox.ini", "setup.cfg", "pyproject.toml", "noxfile.py", "sitecustomize.py",
                "usercustomize.py")


@dataclass
class TestConfig:
    """The project's test command. `command` is an argument list; `{project}` is the scratch copy and `{timeout}` the
    seconds. `link` names entries of the project that are linked into the copy, not copied (a virtual environment)."""
    __test__ = False                       # not a pytest class
    command: Sequence[str]
    timeout: int = 1500
    env: Dict[str, str] = field(default_factory=dict)
    link: Sequence[str] = ()
    inherit_env: bool = False          # the command gets only PATH, HOME, LANG and PYTHONPATH unless this is set
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


def is_test_path(relative: str) -> bool:
    """A path the tests themselves read as tests or configuration: an edit to one could make the run pass by itself."""
    parts = Path(relative).parts
    name = parts[-1] if parts else ""
    return (name in CONFIG_NAMES or name.startswith("test_") or name.endswith("_test.py")
            or any(part in ("tests", "test", "testing") for part in parts[:-1]) or name.startswith("."))


def passed(output: str, returncode: int) -> bool:
    """The runner exited 0 and its last line is a pytest summary with at least one test passed and none failed or in
    error. An exit 0 alone is not enough: an edit can end the process with 0 before a test runs."""
    if returncode != 0:
        return False
    lines = [line.strip() for line in (output or "").strip().splitlines() if line.strip()]
    if not lines:
        return False
    match = PASS_LINE.match(lines[-1])
    return bool(match) and int(match.group(1)) > 0 and not BAD_WORD.search(lines[-1])


def _tree_size_ok(top: Path, skip: Sequence[str], link: Sequence[str]) -> bool:
    total = files = 0
    for directory, names, entries in os.walk(top):
        names[:] = [n for n in names if not any(fnmatch.fnmatch(n, pat) for pat in skip)
                    and not (Path(directory) == top and n in link)]
        for entry in entries:
            files += 1
            try:
                total += os.lstat(os.path.join(directory, entry)).st_size
            except OSError:
                return False
            if files > MAX_COPY_FILES or total > MAX_COPY_BYTES:
                return False
    return True


def _write_inside(copy: Path, relative: str, text: str, link: Sequence[str]) -> Optional[str]:
    """Write `text` at `relative` under the scratch copy, or say why not. Every component that exists is checked with
    lstat and none may be a link, the first may not be one of the linked entries, no directory is made, and the file is
    opened with O_NOFOLLOW, so nothing is written outside the copy."""
    rel = Path(relative)
    if rel.is_absolute() or not rel.parts or any(part in ("", ".", "..") for part in rel.parts):
        return "the edited path is not a plain path inside the project"
    if rel.parts[0] in link:
        return "the edited path is inside a linked entry of the project"
    here = copy
    for part in rel.parts[:-1]:
        here = here / part
        try:
            mode = os.lstat(here).st_mode
        except OSError:
            return "a directory of the edited path does not exist"
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            return "a directory of the edited path is a link or not a directory"
    target = here / rel.parts[-1]
    try:
        if stat.S_ISLNK(os.lstat(target).st_mode):
            return "the edited path is a link"
    except FileNotFoundError:
        pass
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(target, flags, 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    return None


def run_project_tests(project_root: Path, relative: str, new_text: str, config: TestConfig,
                      scratch_parent: Optional[Path] = None) -> TestsResult:
    """Apply the edit (the file's new text) to a scratch copy of the project and run the test command there. Never
    raises: a failure to run is a false with the reason as its summary. The project itself is never written: the
    edited path is checked component by component in the copy (see `_write_inside`), and an edit to a test file or to a
    test configuration is not run (`is_test_path`). The copy counts against the command's timeout."""
    started = time.time()
    if is_test_path(relative):
        return TestsResult(False, "the edit is to a test file or test configuration", 0.0)
    scratch = Path(tempfile.mkdtemp(prefix="gate-tests-", dir=str(scratch_parent) if scratch_parent else None))
    try:
        copy = scratch / "project"
        top = Path(project_root)
        if not _tree_size_ok(top, config.skip, config.link):
            return TestsResult(False, "the project is too big to copy", time.time() - started)

        def ignore(directory, names):
            drop = [n for n in names if any(fnmatch.fnmatch(n, pat) for pat in config.skip)]
            if Path(directory) == top:
                drop += [n for n in names if n in config.link]
            return drop

        shutil.copytree(project_root, copy, symlinks=True, ignore=ignore)
        for name in config.link:
            if (Path(project_root) / name).exists():
                os.symlink((Path(project_root) / name).resolve(), copy / name)
        why = _write_inside(copy, relative, new_text, tuple(config.link))
        if why is not None:
            return TestsResult(False, why, time.time() - started)
        remaining = max(int(config.timeout - (time.time() - started)), 1)
        cmd = [part.format(project=str(copy), timeout=remaining) for part in config.command]
        base = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(scratch), "LANG": "C.UTF-8"}
        env = {**(os.environ if config.inherit_env else base), "PYTHONPATH": str(copy), **config.env}
        proc = subprocess.Popen(cmd, cwd=copy, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env,
                                start_new_session=True)
        try:
            text, _err = proc.communicate(timeout=remaining + 10)
        except subprocess.TimeoutExpired:
            _reap(proc)
            return TestsResult(False, f"the test command did not finish in {config.timeout} s", time.time() - started)
        out = (text or "").strip().splitlines()
        summary = next((line.strip() for line in reversed(out) if line.strip()), "no output")
        return TestsResult(passed(text, proc.returncode), summary[:SUMMARY_MAX], time.time() - started)
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
    no_evidence = {"tests_pass": ("not_run",)}
    control_paths: Tuple[str, ...] = ()

    def __init__(self, project_root: Path, config: Optional[TestConfig],
                 should_run: Callable[[Change], bool],
                 run: Callable[..., TestsResult] = run_project_tests):
        self.project_root, self.config, self.should_run, self._run = Path(project_root), config, should_run, run

    def facts(self, change: Change, budget_s: float) -> Evidence:
        try:
            if self.should_run(change) is not True:
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
