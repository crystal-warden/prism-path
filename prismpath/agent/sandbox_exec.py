# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Run one command inside bubblewrap, so that what it can reach is set by a profile and not by the command.

Every namespace is unshared, so the command has no view of the host's processes and, unless the profile
asks for a network, no network. The profile's read only paths are bound read only, the workspace is the
one read write path (at `/workspace`), `/tmp` is private and empty, the environment is empty but for a
fixed PATH and HOME, a new session removes the terminal, all capabilities are dropped, and the sandbox dies
with its parent.

It fails closed. A missing bwrap, or a bwrap that cannot set up its namespaces, raises `SandboxUnavailable`.
The command is never run without the sandbox.

`SandboxProfile` is the minimal type WP1 needs. The profile type compiled from a signed policy
(`prismpath/agent/profile.py`) replaces it.
"""
from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

BWRAP = "/usr/bin/bwrap"
MOUNT = "/workspace"


class SandboxUnavailable(RuntimeError):
    """bwrap is missing or could not start, so nothing was run."""


@dataclass(frozen=True)
class SandboxProfile:
    read_only: Tuple[str, ...] = ("/usr",)
    network: bool = False
    timeout_s: int = 30


@dataclass(frozen=True)
class SandboxResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False


def bwrap_argv(workspace: Path, profile: SandboxProfile, command: Sequence[str],
               extra_ro_binds: Sequence[Tuple[str, str]] = ()) -> List[str]:
    """The full bwrap command line. `extra_ro_binds` are (source, destination) pairs bound read only after
    the workspace, so they sit on top of it."""
    workspace = Path(os.path.realpath(workspace))
    argv = [BWRAP, "--unshare-all"]
    if profile.network:
        argv.append("--share-net")
    argv += ["--die-with-parent", "--new-session", "--cap-drop", "ALL",
             "--clearenv", "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "HOME", "/tmp",
             "--setenv", "LANG", "C.UTF-8", "--setenv", "GIT_CONFIG_NOSYSTEM", "1",
             "--setenv", "GIT_AUTHOR_NAME", "agent", "--setenv", "GIT_AUTHOR_EMAIL", "agent@workspace.invalid",
             "--setenv", "GIT_COMMITTER_NAME", "agent", "--setenv", "GIT_COMMITTER_EMAIL", "agent@workspace.invalid"]
    for path in profile.read_only:
        argv += ["--ro-bind", path, path]
    argv += ["--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/sbin", "/sbin",
             "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--bind", str(workspace), MOUNT]
    toolchain = workspace / ".toolchain"
    if toolchain.is_dir() and not toolchain.is_symlink():
        argv += ["--ro-bind", str(toolchain), MOUNT + "/.toolchain"]
    for source, destination in extra_ro_binds:
        argv += ["--ro-bind", source, destination]
    argv += ["--chdir", MOUNT, *command]
    return argv


def run_sandboxed(command: Sequence[str], workspace: Path, profile: Optional[SandboxProfile] = None,
                  stdin: Optional[bytes] = None) -> SandboxResult:
    """Run `command` (an argv list) in the sandbox and return what it did. A command that fails is a
    result. A sandbox that cannot start is `SandboxUnavailable`."""
    profile = profile or SandboxProfile()
    if not command:
        raise ValueError("an empty command")
    return _run(bwrap_argv(workspace, profile, command), profile.timeout_s, stdin)


def _run(argv: List[str], timeout_s: int, stdin: Optional[bytes]) -> SandboxResult:
    """Run a built bwrap line. `--info-fd` makes bwrap write a line once its sandbox exists, so a start
    failure (no user namespaces, a bad mount) is told apart from the command failing."""
    if not os.access(BWRAP, os.X_OK):
        raise SandboxUnavailable(f"{BWRAP} is missing or not executable, so the command was not run")
    read_fd, write_fd = os.pipe()
    argv = [argv[0], "--info-fd", str(write_fd), *argv[1:]]
    try:
        try:
            done = subprocess.run(argv, input=stdin, capture_output=True, timeout=timeout_s, pass_fds=(write_fd,))
            timed_out, returncode, out, err = False, done.returncode, done.stdout, done.stderr
        except subprocess.TimeoutExpired as expired:
            timed_out, returncode, out, err = True, -9, expired.stdout or b"", expired.stderr or b""
        except OSError as exc:
            raise SandboxUnavailable(f"{BWRAP} could not be started: {exc}") from exc
        finally:
            os.close(write_fd)
        info = os.read(read_fd, 65536)
    finally:
        os.close(read_fd)
    try:
        started = "child-pid" in json.loads(info.decode("utf-8", "replace") or "null")
    except (ValueError, TypeError):
        started = False
    if not started:
        raise SandboxUnavailable("bwrap did not start the sandbox: " + err.decode("utf-8", "replace")[:500])
    return SandboxResult(returncode, out, err, timed_out)
