# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""`prismpath agent run -- PROGRAM [ARGS]`: the whole agent under the sandbox (agent-sandbox-plan, WP4).

Linux only, non interactive. The launcher stays outside, trusted. It

  1. checks bwrap and socat are there and fails closed (nothing is staged, nothing runs) when one is not;
  2. resolves the program to a real path once, on the host, and pins it: a program under the system prefix is
     run at its own path, any other is bound read only at /opt/agent/<name>, so a later change of PATH, a
     symlink or the workspace cannot swap it;
  3. stages a per run directory (mode 0700, under /var/tmp unless told) holding a read only settings.json with
     the PrismPath hook entries, the proxy's unix socket and its log, and, only when the caller names a file
     with `credential`, one copy of it. The agent sees it as CLAUDE_CONFIG_DIR on a private tmpfs home, with
     settings.json (and the credential) bound read only over it;
  4. builds the agent profile (system prefix read only, the workspace read write, `net` proxy_model) and binds
     the workspace's control paths read only on top of the writable workspace: `.claude/`, `.mcp.json`,
     `.git/config`, `.git/hooks/` and every CLAUDE.md, CLAUDE.local.md and AGENTS.md. A control file that does
     not exist yet is created empty so that it can be bound, and removed again at exit if it is still empty;
  5. starts the egress proxy (the interim allowlist unless the caller passes a decider) on the staged socket;
  6. runs the program under bwrap in a process group of its own, exits with its status, and on the way out stops
     the proxy, kills what is left of the process group, removes the staged directory and the empty control
     files it made.

Credentials. Nothing here reads or looks for a login or a key. `credential` is a path the caller names, copied
byte for byte to the staged directory (mode 0400) and bound read only, and it is off unless given.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Sequence, Tuple

from prismpath.agent import classifier, commands, egress, sandbox_exec
from prismpath.agent.profile import Profile

STAGE_BASE = "/var/tmp"
HOME_IN = "/home/agent"
CONFIG_IN = HOME_IN + "/.claude"
PROGRAM_DIR_IN = "/opt/agent"
CREDENTIAL_NAME = ".credentials.json"
MAX_PROCESSES = 512       # a placeholder until the spike measures the real peak (plan question 10)
AGENT_ENV = (("DISABLE_AUTOUPDATER", "1"), ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1"),
             ("ENABLE_CLAUDEAI_MCP_SERVERS", "false"))
ROOT_CONTROL_NAMES = ("CLAUDE.md", "CLAUDE.local.md", "AGENTS.md")


class LaunchError(commands.AgentError):
    """The run did not start, and the message says why and what to do."""


@dataclass
class Staged:
    root: Path
    config: Path
    settings: Path
    socket: Path
    log: Path
    credential: Optional[Path] = None


@dataclass
class Controls:
    """The workspace's control paths: what to bind read only, and what the launcher created to bind it."""
    binds: List[str] = field(default_factory=list)
    created_files: List[Path] = field(default_factory=list)
    created_dirs: List[Path] = field(default_factory=list)

    def remove_created(self) -> None:
        for path in self.created_files:
            try:
                if path.is_file() and not path.is_symlink() and path.stat().st_size == 0:
                    path.unlink()
            except OSError:
                pass
        for path in reversed(self.created_dirs):
            try:
                path.rmdir()
            except OSError:
                pass


# ------------------------------------------------------------------------------------------------ checks
def require_linux_tools() -> None:
    if not sys.platform.startswith("linux"):
        raise LaunchError("prismpath agent run works on Linux only; nothing was run")
    if not sandbox_exec.available():
        raise LaunchError(f"{sandbox_exec.BWRAP} (bubblewrap) is missing or not executable, so nothing was run; "
                          "install bubblewrap and try again")
    if not os.access(sandbox_exec.RELAY, os.X_OK):
        raise LaunchError(f"{sandbox_exec.RELAY} (socat) is missing or not executable, so nothing was run; "
                          "install socat and try again")


def resolve_program(program: str, env_path: Optional[str] = None) -> str:
    """The real path of the program, found now on the host. A name with no slash is looked up on PATH."""
    found = program if "/" in program else shutil.which(program, path=env_path)
    if not found:
        raise LaunchError(f"{program!r} was not found on PATH, so nothing was run")
    real = os.path.realpath(found)
    if not os.path.isfile(real) or not os.access(real, os.X_OK):
        raise LaunchError(f"{program!r} resolves to {real}, which is not an executable file, so nothing was run")
    return real


def pin_program(real: str, ro_mounts: Sequence[str]) -> Tuple[str, List[Tuple[str, str]]]:
    """(the path to run inside, the read only binds that put it there)."""
    for mount in ro_mounts:
        if real == mount or real.startswith(mount.rstrip("/") + "/"):
            return real, []
    inside = f"{PROGRAM_DIR_IN}/{os.path.basename(real)}"
    return inside, [(real, inside)]


# ----------------------------------------------------------------------------------------------- staging
def stage(settings: dict, credential: Optional[str], base: str = STAGE_BASE) -> Staged:
    """The per run directory. The caller removes it (`shutil.rmtree`) when done."""
    root = Path(tempfile.mkdtemp(dir=base, prefix="pp-agent-"))
    try:
        os.chmod(root, 0o700)
        config = root / "config"
        config.mkdir(mode=0o700)
        path = config / "settings.json"
        path.write_text(commands._settings_text(settings))
        os.chmod(path, 0o444)
        staged = Staged(root, config, path, root / "egress.sock", root / "egress.log")
        if credential is not None:
            source = Path(credential)
            if not source.is_file():
                raise LaunchError(f"the credential file {credential} is not a file, so nothing was run")
            target = config / CREDENTIAL_NAME
            shutil.copyfile(source, target)
            os.chmod(target, 0o400)
            staged.credential = target
        return staged
    except BaseException:
        shutil.rmtree(root, ignore_errors=True)
        raise


def prepare_controls(workspace: Path, out: Controls) -> Controls:
    """Make every control path of the workspace bindable. Existing ones are listed. Missing root ones are
    created empty (`.claude/` always, the three named files, `.mcp.json`, and `.git/config` and `.git/hooks/`
    when there is a `.git`, which is never created). What it creates is recorded in `out` as it goes."""
    def bind(path: Path) -> None:
        if not path.is_symlink():
            out.binds.append(str(path))

    existing = {classifier._fold(n): n for n in os.listdir(workspace)}
    for name in (".claude", ".mcp.json") + ROOT_CONTROL_NAMES:
        if classifier._fold(name) not in existing:
            path = workspace / name
            if name == ".claude":
                path.mkdir()
                out.created_dirs.append(path)
            else:
                path.touch()
                out.created_files.append(path)
            existing[classifier._fold(name)] = name
        bind(workspace / existing[classifier._fold(name)])
    git = workspace / ".git"
    if git.is_dir() and not git.is_symlink():
        config = git / "config"
        if not config.exists() and not config.is_symlink():
            config.touch()
            out.created_files.append(config)
        bind(config)
        hooks = git / "hooks"
        if not hooks.exists() and not hooks.is_symlink():
            hooks.mkdir()
            out.created_dirs.append(hooks)
        bind(hooks)
    for found in classifier._walk_names(str(workspace)):
        path = Path(found)
        if path.parent != workspace:        # the root ones are bound above
            bind(path)
    out.binds = list(dict.fromkeys(out.binds))
    return out


# ------------------------------------------------------------------------------------------------- launch
def launch(command: Sequence[str], workspace: str, credential: Optional[str] = None,
           egress_log: Optional[str] = None, stage_base: str = STAGE_BASE, max_processes: int = MAX_PROCESSES,
           decider: Callable = egress.interim_decider, resolver: Callable = egress.system_resolver,
           connect: Callable = egress.system_connect, hook: Optional[str] = None,
           env: Sequence[Tuple[str, str]] = (), on_start: Optional[Callable[[int], None]] = None) -> int:
    """Run `command` as the agent and return its exit status. `on_start(pid)` is for tests. Raises
    LaunchError, before anything runs, when the run cannot start."""
    require_linux_tools()
    if not command:
        raise LaunchError("no program given: prismpath agent run -- PROGRAM [ARGS]")
    root = Path(os.path.realpath(workspace))
    if not root.is_dir():
        raise LaunchError(f"the workspace {workspace} is not a directory, so nothing was run")
    profile = Profile(net="proxy_model", max_processes=max_processes)
    real = resolve_program(command[0])
    inside, program_binds = pin_program(real, profile.ro_mounts)
    settings = commands.merged_settings({}, hook if hook is not None else commands.hook_command())
    staged = stage(settings, credential, stage_base)
    controls = Controls()
    proxy = None
    proc = None
    try:
        prepare_controls(root, controls)
        proxy = egress.EgressProxy(staged.socket, staged.log, decider=decider, resolver=resolver, connect=connect).start()
        extra_args = ["--tmpfs", HOME_IN, "--tmpfs", CONFIG_IN]
        binds = list(program_binds)
        binds += [(path, path) for path in controls.binds]
        binds.append((str(staged.settings), CONFIG_IN + "/settings.json"))
        if staged.credential is not None:
            binds.append((str(staged.credential), f"{CONFIG_IN}/{CREDENTIAL_NAME}"))
        environment = [("HOME", HOME_IN), ("CLAUDE_CONFIG_DIR", CONFIG_IN), *AGENT_ENV, *env]
        inner = sandbox_exec.limited(sandbox_exec.with_relay([inside, *command[1:]]), profile.max_processes)
        argv = sandbox_exec.bwrap_argv(root, profile, inner, extra_ro_binds=binds, mount=str(root),
                                       proxy_socket=str(staged.socket), extra_args=extra_args, env=environment)
        read_fd, write_fd = os.pipe()
        argv = [argv[0], "--info-fd", str(write_fd), *argv[1:]]
        try:
            proc = subprocess.Popen(argv, pass_fds=(write_fd,), start_new_session=True)
        except OSError as exc:
            raise LaunchError(f"{sandbox_exec.BWRAP} could not be started: {exc}") from exc
        finally:
            os.close(write_fd)
        if on_start:
            on_start(proc.pid)
        status = _wait(proc)
        info = b""
        try:
            info = os.read(read_fd, 65536)
        finally:
            os.close(read_fd)
        try:
            started = "child-pid" in json.loads(info.decode("utf-8", "replace") or "null")
        except (ValueError, TypeError):
            started = False
        if not started:
            raise LaunchError("bwrap did not start the sandbox, so the program was not run (see its message above)")
        return status
    finally:
        _teardown(proc, proxy, staged, controls, egress_log)


def _wait(proc: subprocess.Popen) -> int:
    """Wait for the sandbox, passing INT, TERM and HUP on to its process group. Returns the shell style status."""
    def forward(signum, _frame):
        try:
            os.killpg(proc.pid, signum)
        except OSError:
            pass
    old = {sig: signal.signal(sig, forward) for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    try:
        while True:
            try:
                code = proc.wait()
                break
            except KeyboardInterrupt:
                continue
    finally:
        for sig, handler in old.items():
            signal.signal(sig, handler)
    return code if code >= 0 else 128 - code


def _teardown(proc, proxy, staged: Staged, controls: Controls, egress_log: Optional[str]) -> None:
    if proc is not None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)     # whatever the program left running; the group is ours alone
        except OSError:
            pass
        try:
            proc.wait(timeout=10)
        except Exception:   # noqa: BLE001
            pass
    if proxy is not None:
        proxy.close()
    if egress_log and staged.log.exists():
        try:
            target = Path(egress_log)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(staged.log, target)
        except OSError as exc:
            sys.stderr.write(f"PrismPath could not keep the egress log at {egress_log} ({exc})\n")
    shutil.rmtree(staged.root, ignore_errors=True)
    controls.remove_created()
