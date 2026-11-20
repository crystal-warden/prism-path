# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Run one command inside bubblewrap, so that what it can reach is set by a profile and not by the command.

Every namespace is unshared, so the command has no view of the host's processes and, unless the profile
asks for a network, no network. The profile's read only paths are bound read only, the workspace is the
one read write path (at `/workspace`, or where the caller says), `/tmp` is private and empty, the environment
is empty but for a fixed PATH and HOME, a new session removes the terminal, all capabilities are dropped, and
the sandbox dies with its parent.

The profile is `prismpath.agent.profile.Profile`, the one type that `compile_profile` projects a signed
policy image onto: `ro_mounts` (a profile with the host's `/` there has the whole host read only, and read
write when `host_write` is set, with `/tmp`, `/proc`, `/dev` and the workspace on top; one with only the
system prefix has nothing else), `network`, `max_processes` and `timeout_s`. `rw_path` is a role (the
workspace); the caller says where it is mounted.

`max_processes` is enforced inside the sandbox by `ulimit -u` (RLIMIT_NPROC) in a small `bash` (dash has no `ulimit -u`) that then
`exec`s the command, because bwrap has no process limit of its own. The sandbox is a new user namespace, so
the count is of the processes started inside it, not of the host user's, and every capability is dropped, so
the limit cannot be raised again. `run_sandboxed` applies it; `bwrap_argv` stays the bare bwrap line (the
governed harness builds its own command around it). A fork past the limit fails with EAGAIN.

It fails closed. A missing bwrap, or a bwrap that cannot set up its namespaces, raises `SandboxUnavailable`.
The command is never run without the sandbox.

As a program, `python3 -I sandbox_exec.py --workspace W --cwd C --profile JSON COMMAND`, it runs one shell
command string under the profile and exits with the command's status. This is what the Claude Code hook
rewrites an allowed Bash call into (prismpath/agent/commands.py). A sandbox that cannot start exits 126 with
the reason on standard error and the command is not run.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

if __name__ == "__main__":      # run by path under `python -I`, which puts nothing on sys.path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from prismpath.agent.profile import Profile      # noqa: E402

BWRAP = "/usr/bin/bwrap"
MOUNT = "/workspace"
SHELL = "/usr/bin/bash"


class SandboxUnavailable(RuntimeError):
    """bwrap is missing or could not start, so nothing was run."""


@dataclass(frozen=True)
class SandboxResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False


def available() -> bool:
    """True when bwrap is there to be run (it may still fail to start; that is `SandboxUnavailable` at run)."""
    return os.access(BWRAP, os.X_OK)


def bwrap_argv(workspace: Path, profile: Profile, command: Sequence[str],
               extra_ro_binds: Sequence[Tuple[str, str]] = (), mount: str = MOUNT, cwd: str = "") -> List[str]:
    """The full bwrap command line. `extra_ro_binds` are (source, destination) pairs bound read only after
    the workspace, so they sit on top of it. The workspace is mounted at `mount` and the command starts in
    `cwd` (a path below the workspace, relative, or empty for its root)."""
    workspace = Path(os.path.realpath(workspace))
    argv = [BWRAP, "--unshare-all"]
    if profile.network:
        argv.append("--share-net")
    argv += ["--die-with-parent", "--new-session", "--cap-drop", "ALL",
             "--clearenv", "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "HOME", "/tmp",
             "--setenv", "LANG", "C.UTF-8", "--setenv", "GIT_CONFIG_NOSYSTEM", "1",
             "--setenv", "GIT_AUTHOR_NAME", "agent", "--setenv", "GIT_AUTHOR_EMAIL", "agent@workspace.invalid",
             "--setenv", "GIT_COMMITTER_NAME", "agent", "--setenv", "GIT_COMMITTER_EMAIL", "agent@workspace.invalid"]
    host = "/" in profile.ro_mounts
    if host and mount == MOUNT and not os.path.isdir(MOUNT):
        mount = str(workspace)      # a read only host root has no /workspace to mount on, so the workspace stays at its own path
    if host:                    # the whole host, read only (read write when the policy lets a change reach it)
        argv += ["--bind" if profile.host_write else "--ro-bind", "/", "/"]
    for path in profile.ro_mounts:
        if path != "/":
            argv += ["--ro-bind", path, path]
    if not host:
        argv += ["--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/sbin", "/sbin"]
        if os.path.isdir("/usr/lib64"):     # x86_64 finds its dynamic loader at /lib64; without it nothing starts
            argv += ["--symlink", "usr/lib64", "/lib64"]
    argv += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--bind", str(workspace), mount]
    toolchain = workspace / ".toolchain"
    if toolchain.is_dir() and not toolchain.is_symlink():
        argv += ["--ro-bind", str(toolchain), mount + "/.toolchain"]
    for source, destination in extra_ro_binds:
        argv += ["--ro-bind", source, destination]
    argv += ["--chdir", mount + ("/" + cwd.strip("/") if cwd.strip("/") else ""), *command]
    return argv


def limited(command: Sequence[str], max_processes: int) -> List[str]:
    """`command` run by a `bash` that first sets the process limit, then replaces itself with the command."""
    return [SHELL, "-c", f'ulimit -u {int(max_processes)} && exec "$@"', "bash", *command]


def run_sandboxed(command: Sequence[str], workspace: Path, profile: Optional[Profile] = None,
                  stdin: Optional[bytes] = None, mount: str = MOUNT, cwd: str = "") -> SandboxResult:
    """Run `command` (an argv list) in the sandbox and return what it did. A command that fails is a
    result. A sandbox that cannot start is `SandboxUnavailable`."""
    profile = profile or Profile()
    if not command:
        raise ValueError("an empty command")
    argv = bwrap_argv(workspace, profile, limited(command, profile.max_processes), mount=mount, cwd=cwd)
    return _run(argv, profile.timeout_s, stdin)


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


# ------------------------------------------------------------------------------------------ as a program
def profile_from_json(text: str) -> Profile:
    """The profile a canonical object names. Raises ValueError on anything that is not a profile."""
    from prismpath.agent import profile as profile_module
    obj = json.loads(text)
    if not isinstance(obj, dict) or obj.get("format") != profile_module.FORMAT:
        raise ValueError("not a prismpath.profile/1 object")
    return Profile(ro_mounts=tuple(obj["ro_mounts"]), rw_path=obj["rw_path"], host_write=bool(obj["host_write"]),
                   network=bool(obj["network"]), max_processes=int(obj["max_processes"]),
                   timeout_s=int(obj["timeout_s"]))


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="sandbox_exec.py")
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--cwd", default="", help="below the workspace, relative")
    parser.add_argument("--profile", required=True, help="a prismpath.profile/1 object as JSON")
    parser.add_argument("--timeout", type=int, default=None, help="seconds; the profile's timeout_s when not given")
    parser.add_argument("command", help="one shell command string")
    args = parser.parse_args(argv)
    try:
        profile = profile_from_json(args.profile)
        if args.timeout is not None:
            if args.timeout < 1:
                raise ValueError("the time limit is not positive")
            profile = dataclasses.replace(profile, timeout_s=args.timeout)
        workspace = os.path.realpath(args.workspace)
        rel = os.path.relpath(os.path.realpath(os.path.join(workspace, args.cwd)), workspace)
        if rel == ".." or rel.startswith("../"):
            raise ValueError("the working directory is outside the workspace")
        done = run_sandboxed([SHELL, "-c", args.command], Path(workspace), profile, stdin=b"", mount=workspace,
                             cwd="" if rel == "." else rel)
    except (SandboxUnavailable, ValueError, KeyError, TypeError) as exc:
        sys.stderr.write(f"PrismPath did not run this command: the sandbox could not be set up ({exc})\n")
        return 126
    sys.stdout.buffer.write(done.stdout)
    sys.stdout.buffer.flush()
    sys.stderr.buffer.write(done.stderr)
    if done.timed_out:
        sys.stderr.write(f"PrismPath stopped this command after {profile.timeout_s} seconds\n")
        return 124
    return done.returncode if done.returncode >= 0 else 128 - done.returncode


if __name__ == "__main__":
    sys.exit(main())
