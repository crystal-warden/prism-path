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
the reason on standard error and the command is not run. With `--observe-*` flags it also records what a
finished command's exit status and standard error show (prismpath/agent/observe.py), bound to the receipt of the
call; that record changes no output, no exit status and no decision.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

if __name__ == "__main__":      # run by path under `python -I`, which puts nothing on sys.path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from prismpath.agent import controls, landlock                           # noqa: E402
from prismpath.agent.profile import Profile, ProfileError      # noqa: E402

BWRAP = "/usr/bin/bwrap"
MOUNT = "/workspace"
PROXY_PORT = 3128                       # the relay's loopback port inside the sandbox (its own network namespace, so it cannot clash)
MODEL_SOCKET_IN = "/tmp/.pp-model.sock"     # the fixed local model route's socket (prismpath/agent/local_route.py)
PROXY_SOCKET_IN = "/tmp/.pp-egress.sock"    # where the proxy's unix socket appears inside; a bind mount cannot be unlinked from inside
RELAY = "/usr/bin/socat"
SHELL = "/usr/bin/bash"
BACKENDS = ("bwrap", "landlock")        # in the order the runner prefers them


class SandboxUnavailable(RuntimeError):
    """bwrap is missing or could not start, so nothing was run."""


@dataclass(frozen=True)
class SandboxResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    backend: str = "bwrap"


def available() -> bool:
    """True when bwrap is there to be run (it may still fail to start; that is `SandboxUnavailable` at run)."""
    return os.access(BWRAP, os.X_OK)


def bwrap_argv(workspace: Path, profile: Profile, command: Sequence[str],
               extra_ro_binds: Sequence[Tuple[str, str]] = (), mount: str = MOUNT, cwd: str = "",
               proxy_socket: str = "", extra_args: Sequence[str] = (),
               env: Sequence[Tuple[str, str]] = (), control_binds: Sequence[str] = ()) -> List[str]:
    """The full bwrap command line. `control_binds` are host paths below the workspace (its control paths,
    controls.py) bound read only over the writable workspace, at the same place below `mount`. `extra_ro_binds` are (source, destination) pairs bound read only after
    the workspace, so they sit on top of it. The workspace is mounted at `mount` and the command starts in
    `cwd` (a path below the workspace, relative, or empty for its root). A profile whose `net` is a proxy state
    needs `proxy_socket`, the host path of the proxy's unix socket, which is bound in; the sandbox keeps its
    own network namespace with only `lo`, and `--share-net` is never added for these states. The caller
    starts the relay (`with_relay`). `env` is (name, value) pairs set after the fixed ones, so they win, and
    `extra_args` are bwrap arguments placed after the workspace and proxy mounts and before `extra_ro_binds`
    (the launcher's private home and its staged files)."""
    workspace = Path(os.path.realpath(workspace))
    if profile.net != "none" and not proxy_socket:
        raise SandboxUnavailable("the profile asks for a proxy and no proxy socket was given, so the command was not run")
    argv = [BWRAP, "--unshare-all"]
    if profile.network and profile.net == "none":
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
    if profile.net != "none":
        proxy = f"http://127.0.0.1:{PROXY_PORT}"
        argv += ["--bind", os.path.realpath(proxy_socket), PROXY_SOCKET_IN]
        for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
            argv += ["--setenv", name, proxy]
        argv += ["--setenv", "NO_PROXY", "", "--setenv", "no_proxy", ""]
    for name, value in env:
        argv += ["--setenv", name, value]
    argv += list(extra_args)
    toolchain = workspace / ".toolchain"
    if toolchain.is_dir() and not toolchain.is_symlink():
        argv += ["--ro-bind", str(toolchain), mount + "/.toolchain"]
    for source in control_binds:
        rel = os.path.relpath(source, workspace)
        if rel != ".." and not rel.startswith("../") and os.path.lexists(source):
            argv += ["--ro-bind", source, mount + "/" + rel]
    for source, destination in extra_ro_binds:
        argv += ["--ro-bind", source, destination]
    argv += ["--chdir", mount + ("/" + cwd.strip("/") if cwd.strip("/") else ""), *command]
    return argv


def limited(command: Sequence[str], max_processes: int) -> List[str]:
    """`command` run by a `bash` that first sets the process limit, then replaces itself with the command."""
    return [SHELL, "-c", f'ulimit -u {int(max_processes)} && exec "$@"', "bash", *command]


def with_relay(command: Sequence[str], model_port: int = 0) -> List[str]:
    """`command` run after a `socat` relay from 127.0.0.1:PROXY_PORT to the bound proxy socket is listening.
    With `model_port`, a second relay from 127.0.0.1:model_port to the bound local model socket as well.
    The relays live in the sandbox's process namespace and die with it. One that does not come up
    within about five seconds stops the command, so nothing runs with a route it cannot reach."""
    ports = [(PROXY_PORT, PROXY_SOCKET_IN)] + ([(model_port, MODEL_SOCKET_IN)] if model_port else [])
    script = ""
    for port, sock in ports:
        script += f'{RELAY} TCP-LISTEN:{port},bind=127.0.0.1,fork,reuseaddr UNIX-CONNECT:{sock} & '
    for port, _sock in ports:
        script += (f'for i in $(seq 50); do grep -q ":{port:04X} .* 0A " /proc/net/tcp && break; sleep 0.1; done; '
                   f'grep -q ":{port:04X} .* 0A " /proc/net/tcp || {{ echo "the relay on port {port} did not start" >&2; exit 125; }}; ')
    script += 'exec "$@"'
    return [SHELL, "-c", script, "bash", *command]


def run_sandboxed(command: Sequence[str], workspace: Path, profile: Optional[Profile] = None,
                  stdin: Optional[bytes] = None, mount: str = MOUNT, cwd: str = "",
                  proxy_socket: str = "", control_binds: Sequence[str] = ()) -> SandboxResult:
    """Run `command` (an argv list) in the sandbox and return what it did. A command that fails is a
    result. A sandbox that cannot start is `SandboxUnavailable`."""
    profile = profile or Profile()
    if not command:
        raise ValueError("an empty command")
    inner = limited(command, profile.max_processes)
    if profile.net != "none":
        inner = limited(with_relay(command), profile.max_processes)
    argv = bwrap_argv(workspace, profile, inner, mount=mount, cwd=cwd, proxy_socket=proxy_socket, control_binds=control_binds)
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


# ------------------------------------------------------------------------------------------ the Landlock backend
def landlock_refusal(profile: Profile, workspace: Path) -> str:
    """Why the Landlock backend cannot run a call under `profile` here, or '' when it can. It never runs a profile it
    cannot hold to what bubblewrap would hold it to."""
    if landlock.abi_version() < 1:
        return "Landlock is not available on this kernel"
    if profile.network or profile.net != "none":
        return "the Landlock backend runs only profiles with no network"
    return ""


def _holes(workspace: Path) -> List[str]:
    """The paths below the workspace that must stay read only and that no read only mount protects: the control paths
    (existing ones, and the root ones that are missing, which a script must not create) and `.toolchain`."""
    holes = [path for path in controls.discover(workspace).binds
             if not (os.path.lexists(path) and controls.on_read_only_mount(path))]
    toolchain = Path(workspace) / ".toolchain"
    if toolchain.is_dir() and not toolchain.is_symlink() and not controls.on_read_only_mount(str(toolchain)):
        holes.append(str(toolchain))
    return holes


def _task_count() -> int:
    """How many tasks (threads) this user has in the process namespace: what RLIMIT_NPROC counts."""
    uid, total = os.getuid(), 0
    try:
        names = os.listdir("/proc")
    except OSError:
        return 0
    for name in names:
        if name.isdigit():
            try:
                if os.stat(f"/proc/{name}").st_uid == uid:
                    total += len(os.listdir(f"/proc/{name}/task"))
            except OSError:
                continue
    return total


def _children(pid: int) -> List[int]:
    found = []
    try:
        names = os.listdir("/proc")
    except OSError:
        return found
    for name in names:
        if name.isdigit():
            try:
                with open(f"/proc/{name}/stat", "rb") as handle:
                    rest = handle.read().rsplit(b")", 1)[1].split()
                if int(rest[1]) == pid:
                    found.append(int(name))
            except (OSError, ValueError, IndexError):
                continue
    return found


def _end_descendants(group: int, keep: int = 0) -> None:
    """Kill the command's process group and then whatever it left running (orphans came to this process, the subreaper),
    as the end of bubblewrap's PID namespace does."""
    me = os.getpid()
    try:
        os.killpg(group, signal.SIGKILL)
    except OSError:
        pass
    for _ in range(50):
        kids = [kid for kid in _children(me) if kid != keep]      # `keep` is the command's own process, reaped by its Popen
        for kid in kids:
            try:
                os.kill(kid, signal.SIGKILL)
                os.waitpid(kid, 0)
            except OSError:
                pass
        if not kids:
            return
        time.sleep(0.01)


def run_landlock(command: str, workspace: Path, profile: Optional[Profile] = None, stdin: Optional[bytes] = None,
                 cwd: str = "", net_rules: bool = True, seccomp: bool = True, scope_rules: bool = True) -> SandboxResult:
    """Run one shell command string with the Landlock backend (prismpath/agent/landlock.py): fork, confine the child,
    exec `bash -c`. The same inputs as `run_sandboxed` for a no network profile, and the same result. The three
    switches turn one layer off and exist for the tests that show each layer stops what it should on its own.
    A host or a profile that cannot be confined is `SandboxUnavailable`, and the command is not run."""
    profile = profile or Profile()
    workspace = Path(os.path.realpath(workspace))
    why = landlock_refusal(profile, workspace)
    if why:
        raise SandboxUnavailable(why + ", so the command was not run")
    abi = landlock.abi_version()
    where = workspace / cwd.strip("/") if cwd.strip("/") else workspace
    if not where.is_dir():
        raise SandboxUnavailable(f"the working directory {where} is not a directory, so the command was not run")
    scratch = None
    try:
        scratch = tempfile.mkdtemp(prefix="pp-call-", dir="/tmp" if os.access("/tmp", os.W_OK) else None)
    except OSError:
        scratch = None
    env = {"PATH": "/usr/bin:/bin", "HOME": scratch or "/nonexistent", "LANG": "C.UTF-8", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_AUTHOR_NAME": "agent", "GIT_AUTHOR_EMAIL": "agent@workspace.invalid",
           "GIT_COMMITTER_NAME": "agent", "GIT_COMMITTER_EMAIL": "agent@workspace.invalid"}
    if scratch:
        env["TMPDIR"] = scratch
    rules = landlock.rules_for(profile.ro_mounts, profile.host_write, str(workspace), scratch, holes=_holes(workspace))
    nproc = _task_count() + int(profile.max_processes)
    out, err, feed = tempfile.TemporaryFile(), tempfile.TemporaryFile(), None
    try:
        if stdin:
            feed = tempfile.TemporaryFile()
            feed.write(stdin)
            feed.seek(0)
        landlock.set_subreaper()
        err_r, err_w = os.pipe()
        job = json.dumps({"command": command, "cwd": str(where), "env": env, "abi": abi, "nproc": nproc, "errfd": err_w,
                          "rules": [[r.path, r.access] for r in rules],
                          "layers": {"net_rules": net_rules, "seccomp": seccomp, "scope_rules": scope_rules}})
        try:
            # a fresh interpreter applies the confinement and execs, so no thread of this process is forked mid lock
            proc = subprocess.Popen([sys.executable, "-I", str(Path(__file__).resolve()), "--landlock-child", job],
                                    stdin=feed if feed is not None else subprocess.DEVNULL, stdout=out, stderr=err,
                                    pass_fds=(err_w,), start_new_session=True)
        except OSError as exc:
            os.close(err_r)
            raise SandboxUnavailable(f"the Landlock sandbox could not be started: {exc}") from exc
        finally:
            os.close(err_w)
        try:
            problem = os.read(err_r, 4096)
        finally:
            os.close(err_r)
        if problem:
            proc.wait()
            _end_descendants(proc.pid, proc.pid)
            raise SandboxUnavailable("the Landlock sandbox could not be applied: " + problem.decode("utf-8", "replace"))
        timed_out = False
        try:
            returncode = proc.wait(timeout=profile.timeout_s)
        except subprocess.TimeoutExpired:
            timed_out = True
            _end_descendants(proc.pid, proc.pid)
            proc.wait()
            returncode = -9
        _end_descendants(proc.pid, proc.pid)
        out.seek(0)
        err.seek(0)
        return SandboxResult(returncode, out.read(), err.read(), timed_out, backend="landlock")
    finally:
        out.close()
        err.close()
        if feed is not None:
            feed.close()
        if scratch:
            import shutil
            shutil.rmtree(scratch, ignore_errors=True)


def _landlock_child(job_text: str) -> None:
    """The other half of `run_landlock`, run as `sandbox_exec.py --landlock-child JOB` in a fresh interpreter: confine
    this process, then replace it with `bash -c COMMAND`. Whatever fails is told to the parent over the error pipe and
    the command is not run. It does nothing the caller could not do by running the command itself, and it only narrows."""
    job = json.loads(job_text)
    errfd = int(job["errfd"])
    try:
        os.set_inheritable(errfd, False)        # closed by the exec, so the parent reads end of file when the command started
        os.closerange(3, errfd)
        os.closerange(errfd + 1, 1 << 16)
        os.chdir(job["cwd"])
        rules = [landlock.Rule(path, int(access)) for path, access in job["rules"]]
        layers = job["layers"]
        landlock.enforce(rules, job["abi"], net_rules=bool(layers["net_rules"]), seccomp=bool(layers["seccomp"]),
                         scope_rules=bool(layers["scope_rules"]), nproc=int(job["nproc"]))
        os.execve(SHELL, [SHELL, "-c", job["command"]], job["env"])
    except BaseException as exc:    # noqa: BLE001
        try:
            os.write(errfd, f"{type(exc).__name__}: {exc}".encode("utf-8", "replace")[:500])
        finally:
            os._exit(127)


def run_backend(backend: str, command: str, workspace: Path, profile: Profile, stdin: Optional[bytes] = None,
                mount: str = MOUNT, cwd: str = "", proxy_socket: str = "") -> SandboxResult:
    """Run one shell command string with the backend named. `auto` tries bubblewrap and, only when its sandbox could
    not be started (so nothing ran), Landlock; a host with neither is `SandboxUnavailable`. A named backend that is
    not available is `SandboxUnavailable` too, and never another backend."""
    if backend not in ("auto",) + BACKENDS:
        raise ValueError(f"unknown backend {backend!r}")
    if backend in ("bwrap", "auto"):
        made = controls.Controls()
        try:
            try:
                found = controls.discover(Path(os.path.realpath(workspace)))
                controls.materialize(found, made)      # so a missing `.claude/` or CLAUDE.md can be bound read only too
            except OSError as exc:
                raise SandboxUnavailable(f"the workspace's control paths cannot be protected ({exc}), so the command was not run") from exc
            return run_sandboxed([SHELL, "-c", command], workspace, profile, stdin=stdin, mount=mount, cwd=cwd,
                                 proxy_socket=proxy_socket, control_binds=found.binds)
        except SandboxUnavailable as first:
            if backend == "bwrap":
                raise
            if landlock_refusal(profile, workspace):
                raise first
        finally:
            made.remove_created()
    return run_landlock(command, workspace, profile, stdin=stdin, cwd=cwd)


# ------------------------------------------------------------------------------------------ as a program
def profile_from_json(text: str) -> Profile:
    """The profile a canonical object names. Raises ValueError on anything that is not a profile."""
    from prismpath.agent import profile as profile_module
    obj = json.loads(text)
    if not isinstance(obj, dict) or obj.get("format") not in (profile_module.FORMAT, profile_module.FORMAT_NET):
        raise ValueError("not a prismpath.profile/1 or /2 object")
    if (obj["format"] == profile_module.FORMAT_NET) != ("net" in obj):    # /2 is the format that carries net, and only it
        raise ValueError("the profile's format and its net field disagree")
    return Profile(ro_mounts=tuple(obj["ro_mounts"]), rw_path=obj["rw_path"], host_write=bool(obj["host_write"]),
                   network=bool(obj["network"]), max_processes=int(obj["max_processes"]),
                   timeout_s=int(obj["timeout_s"]), net=obj.get("net", "none"))


def main(argv: Optional[Sequence[str]] = None) -> int:
    if argv is None and len(sys.argv) == 3 and sys.argv[1] == "--landlock-child":
        _landlock_child(sys.argv[2])
        return 127
    parser = argparse.ArgumentParser(prog="sandbox_exec.py")
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--cwd", default="", help="below the workspace, relative")
    parser.add_argument("--profile", required=True, help="a prismpath.profile/1 or /2 object as JSON")
    parser.add_argument("--proxy-socket", default="", help="host path of the egress proxy's unix socket (for a proxy profile)")
    parser.add_argument("--timeout", type=int, default=None, help="seconds; the profile's timeout_s when not given")
    parser.add_argument("--backend", default="auto", choices=("auto",) + BACKENDS,
                        help="bwrap, landlock, or auto (bubblewrap, then Landlock where bubblewrap cannot start)")
    parser.add_argument("--observe-socket", default=None, help="the decider's unix socket, for a runner inside the agent sandbox")
    for flag in ("run", "session", "receipt", "image", "profile"):    # observe.py: bind what the command shows to its receipt
        parser.add_argument(f"--observe-{flag}", default=None)
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
        done = run_backend(args.backend, args.command, Path(workspace), profile, stdin=b"", mount=workspace,
                           cwd="" if rel == "." else rel, proxy_socket=args.proxy_socket)
    except (SandboxUnavailable, ValueError, KeyError, TypeError, ProfileError) as exc:
        sys.stderr.write(f"PrismPath did not run this command: the sandbox could not be set up ({exc})\n")
        return 126
    sys.stdout.buffer.write(done.stdout)
    sys.stdout.buffer.flush()
    sys.stderr.buffer.write(done.stderr)
    _observe(args, done)
    if done.timed_out:
        sys.stderr.write(f"PrismPath stopped this command after {profile.timeout_s} seconds\n")
        return 124
    return done.returncode if done.returncode >= 0 else 128 - done.returncode


def _observe(args, done: SandboxResult) -> None:
    """Record what the finished command showed, when the hook asked for it. An observation never changes the
    command's output or exit status, and a failure to record one only says so on standard error."""
    if args.observe_run is None and args.observe_socket is None:
        return
    try:
        from prismpath.agent import observe
        if args.observe_socket is not None:     # nested: the run directory is outside, the decider records it
            observe.send(args.observe_socket, args.observe_session, int(args.observe_receipt), args.observe_image,
                         args.observe_profile, done.returncode, done.stderr, done.timed_out, done.backend)
            return
        observe.record(args.observe_run, args.observe_session, int(args.observe_receipt), args.observe_image,
                       args.observe_profile, done.returncode, done.stderr, done.timed_out, done.backend)
    except Exception as exc:    # noqa: BLE001 - the command ran; the record is best effort and says so
        sys.stderr.write(f"PrismPath could not record an observation ({' '.join(str(exc).split())[:120]})\n")


if __name__ == "__main__":
    sys.exit(main())
