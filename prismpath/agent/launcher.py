# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""`prismpath agent run -- PROGRAM [ARGS]`: the whole agent under the sandbox.

Linux only, non interactive. The launcher stays outside, trusted. It

  1. checks bwrap and socat are there and fails closed (nothing is staged, nothing runs) when one is not;
  2. resolves the program to a real path once, on the host, and pins it: a program under the system prefix is
     run at its own path, any other is bound read only at /opt/agent/<name>, so a later change of PATH, a
     symlink or the workspace cannot swap it;
  3. stages a per run directory (mode 0700, under /var/tmp unless told) holding a read only settings.json with
     the PrismPath hook entries, the proxy's unix socket and its log, and, only when the caller names a file
     with `credential`, one copy of it. The agent sees it as CLAUDE_CONFIG_DIR on a private tmpfs home, with
     settings.json (and the credential) bound read only over it;
  4. loads the recorded policy (keys checked, attestation verified: `commands.load_checked`), compiles it to the agent
     profile (`compile_profile(image, "agent")`: the system prefix read only, the workspace read write, `net` from
     the allow set) and refuses to run when the image allows no connection to the model API. It binds
     the workspace's control paths read only on top of the writable workspace: `.claude/`, `.mcp.json`,
     `.git/config`, `.git/hooks/` and every CLAUDE.md, CLAUDE.local.md and AGENTS.md. A control file that does
     not exist yet is created empty so that it can be bound, and removed again at exit if it is still empty;
  4b. with `local_model` (http://HOST:PORT), also starts a fixed route to that one server (local_route.py): a
     unix socket in the staged directory forwarding to HOST:PORT only, and a relay inside at 127.0.0.1:PORT.
     It is not an exception in the proxy's private address rule, and each use is a line in the egress log;
  5. starts the decider (decider.py) on a second staged unix socket, bound in at /tmp/.pp-decider.sock, with the
     thin hook client (hook_client.py) staged beside settings.json, and starts the egress proxy on the staged socket
     with the policy gate (egress_policy.py): each CONNECT is read into a connect reading, decided by the active image
     and written as a receipt in a run of its own (`egress-<time>-<pid>`, sealed at exit), and a refusal is cause 130.
     A caller that passes `decider` (a test or an embedder with no recorded policy) gets a plain decider and no
     receipts, and the profile is `proxy_model`;
  5b. finds out which per call sandbox works inside (bubblewrap, else Landlock; sandbox_exec.BACKENDS), once, and tells the decider;
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
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Callable, List, Optional, Sequence, Tuple

from prismpath.agent import classifier, commands, controls as controls_module, decider as decider_module, egress, egress_policy, hook_client, local_route, sandbox_exec, sandbox_hook
from prismpath.agent.profile import Profile, ProfileError, compile_profile

STAGE_BASE = "/var/tmp"
HOME_IN = "/home/agent"
CONFIG_IN = HOME_IN + "/.claude"
PROGRAM_DIR_IN = "/opt/agent"
CREDENTIAL_NAME = ".credentials.json"
HOOK_CLIENT_NAME = "pp-hook.py"
DECIDER_SOCKET_IN = "/tmp/.pp-decider.sock"     # inside the sandbox; /tmp is a private tmpfs there
HOOK_PYTHON = "/usr/bin/python3"                # must exist inside: the system prefix is bound read only
PACKAGE_IN = "/opt/pp"                          # the prismpath package, bound read only, for the per call runner
RUNNER_IN = f"{PACKAGE_IN}/prismpath/agent/sandbox_exec.py"
PROBE_TIMEOUT_S = 30
BACKENDS = sandbox_exec.BACKENDS     # the per call backends, in order of preference; a test narrows it to force one
MAX_PROCESSES = 512       # the process limit inside the sandbox unless the caller names one; no measurement of a real agent's peak backs it
AGENT_ENV = (("DISABLE_AUTOUPDATER", "1"), ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1"),
             ("ENABLE_CLAUDEAI_MCP_SERVERS", "false"))
ROOT_CONTROL_NAMES = controls_module.ROOT_CONTROL_NAMES
Controls = controls_module.Controls


class LaunchError(commands.AgentError):
    """The run did not start, and the message says why and what to do."""


@dataclass
class Staged:
    root: Path
    config: Path
    settings: Path
    socket: Path
    log: Path
    decider_socket: Path
    credential: Optional[Path] = None
    hook_client: Optional[Path] = None


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
def client_hook_command() -> str:
    """The hook command under the launcher: the standard library client, run by the interpreter inside the sandbox.
    `|| exit 2` stays, so a client that cannot start is a block."""
    return f"{HOOK_PYTHON} -I {CONFIG_IN}/{HOOK_CLIENT_NAME} {DECIDER_SOCKET_IN} || exit 2"


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
        client = config / HOOK_CLIENT_NAME
        shutil.copyfile(hook_client.__file__, client)
        os.chmod(client, 0o444)
        staged = Staged(root, config, path, root / "egress.sock", root / "egress.log", root / "decider.sock",
                        hook_client=client)
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


def prepare_controls(workspace: Path, out: Controls, extra: Sequence[str] = ()) -> Controls:
    """Make every control path of the workspace bindable (`controls.discover` finds them, and the per call sandbox
    uses the same list). Existing ones are listed. Missing root ones are created empty (`.claude/` always, the three
    named files, `.mcp.json`, and `.git/config` and `.git/hooks/` when there is a `.git`, which is never created).
    `extra` are the zone index's control paths (zones.py), bound when they exist. What it creates is recorded in `out` as it goes."""
    controls_module.prepare(workspace, out, extra=extra)
    return out


EGRESS_LOG_NAME = "egress.log"


# ------------------------------------------------------------------------------------------------- launch
@dataclass(frozen=True)
class EgressSettings:
    """How the agent's network reaches out. `allowed_hosts` are the extra hosts the policy may allow, `local_model`
    is `http://HOST:PORT` of the one local model server with a fixed route, and `decider`, `resolver` and `connect`
    are for tests and embedders (a `decider` means no recorded policy, so a plain decider and no policy gate)."""
    allowed_hosts: Sequence[str] = ()
    local_model: Optional[str] = None
    decider: Optional[Callable] = None
    resolver: Callable = egress.system_resolver
    connect: Callable = egress.system_connect


@dataclass(frozen=True)
class Confinement:
    """What the agent's sandbox holds beside the workspace. `max_processes` is its process limit, `extra_ro` are host
    paths bound read only, and `env` are (name, value) pairs set last, so they win."""
    max_processes: int = MAX_PROCESSES
    extra_ro: Sequence[str] = ()
    env: Sequence[Tuple[str, str]] = ()


def launch(command: Sequence[str], workspace: str, credential: Optional[str] = None,
           egress_log: Optional[str] = None, stage_base: str = STAGE_BASE, home: Optional[str] = None,
           session: Optional[str] = None, hook: Optional[str] = None,
           egress_settings: EgressSettings = EgressSettings(), confinement: Confinement = Confinement(),
           on_start: Optional[Callable[[int], None]] = None) -> int:
    """Run `command` as the agent and return its exit status. `on_start(pid)` is for tests. Raises
    LaunchError, before anything runs, when the run cannot start."""
    local_model, decider, allowed_hosts = egress_settings.local_model, egress_settings.decider, egress_settings.allowed_hosts
    resolver, connect = egress_settings.resolver, egress_settings.connect
    max_processes, extra_ro, env = confinement.max_processes, confinement.extra_ro, confinement.env
    require_linux_tools()
    if not command:
        raise LaunchError("no program given: prismpath agent run -- PROGRAM [ARGS]")
    root = Path(os.path.realpath(workspace))
    if not root.is_dir():
        raise LaunchError(f"the workspace {workspace} is not a directory, so nothing was run")
    model_target = None
    if local_model:
        try:
            model_target = local_route.parse_target(local_model)
        except local_route.RouteError as exc:
            raise LaunchError(f"{exc}, so nothing was run") from exc
        if model_target[1] == sandbox_exec.PROXY_PORT:
            raise LaunchError(f"the local model port {sandbox_exec.PROXY_PORT} is the egress relay's port, so nothing was run")
    for path in extra_ro:
        if not os.path.exists(path):
            raise LaunchError(f"the read only path {path} does not exist, so nothing was run")
    gate = None
    zone_paths: Tuple[str, ...] = ()
    home_dir = Path(home) if home else commands.config_dir()
    if decider is None:
        profile, policy, store = _policy_profile(home_dir, max_processes)
        session = session or f"egress-{time.strftime('%Y%m%dT%H%M%S')}-{os.getpid()}"
        gate = egress_policy.PolicyGate(policy, store, session, root, profile, allowed_hosts, home=home_dir)
        decider = egress.refuse_all
        from prismpath.agent import zones as zone_module
        zone_paths = tuple(getattr(zone_module.information_point(home_dir, policy.image, root), "control_paths", ()))
    else:
        profile = Profile(net="proxy_model", max_processes=max_processes)
    real = resolve_program(command[0])
    inside, program_binds = pin_program(real, profile.ro_mounts)
    settings = commands.merged_settings({}, hook if hook is not None else client_hook_command())
    staged = stage(settings, credential, stage_base)
    controls = Controls()
    proxy = None
    model_route = None
    proc = None
    hook_decider = None
    nested = None
    try:
        prepare_controls(root, controls, zone_paths)
        proxy = egress.EgressProxy(staged.socket, staged.log, decider=decider, gate=gate, resolver=resolver, connect=connect).start()
        if model_target is not None:
            model_route = local_route.LocalModelRoute(staged.root / "model.sock", staged.log, *model_target).start()
        extra_args = ["--tmpfs", HOME_IN, "--tmpfs", CONFIG_IN]
        binds = list(program_binds)
        binds += [(path, path) for path in controls.binds]
        binds += [(os.path.realpath(path), os.path.realpath(path)) for path in extra_ro]
        if model_route is not None:
            binds.append((model_route.socket_path, sandbox_exec.MODEL_SOCKET_IN))
        if hook is None:    # the per call sandbox runs nested in this one, so its runner and the package it imports are bound read only
            binds.append((str(Path(sandbox_exec.__file__).resolve().parents[1]), f"{PACKAGE_IN}/prismpath"))
        binds.append((str(staged.settings), CONFIG_IN + "/settings.json"))
        binds.append((str(staged.hook_client), f"{CONFIG_IN}/{HOOK_CLIENT_NAME}"))
        if staged.credential is not None:
            binds.append((str(staged.credential), f"{CONFIG_IN}/{CREDENTIAL_NAME}"))
        environment = [("HOME", HOME_IN), ("CLAUDE_CONFIG_DIR", CONFIG_IN), *AGENT_ENV]
        if model_target is not None:    # a client that honours HTTP_PROXY would send the model route's traffic to the proxy
            environment += [("NO_PROXY", "127.0.0.1,localhost"), ("no_proxy", "127.0.0.1,localhost")]
        environment += list(env)
        inner = sandbox_exec.limited(sandbox_exec.with_relay([inside, *command[1:]], model_target[1] if model_target else 0), profile.max_processes)

        def outer(command_inside, extra_binds=()):
            return sandbox_exec.bwrap_argv(root, profile, command_inside,
                                           sandbox_exec.Mounts(extra_ro_binds=[*binds, *extra_binds], mount=str(root), extra_args=extra_args),
                                           proxy_socket=str(staged.socket), env=environment)
        if hook is None:    # the keys, the policy and the runs stay here; the sandbox only gets the socket
            nested = probe_nested(outer, root)
            hook_decider = decider_module.Decider(staged.decider_socket, env={**os.environ, "CLAUDE_PROJECT_DIR": str(root)},
                                                  nested=nested).start()
            binds.append((str(staged.decider_socket), DECIDER_SOCKET_IN))
        argv = outer(inner)
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
        if egress_log is None and gate is not None and gate.run is not None:
            egress_log = str(gate.run.dir / EGRESS_LOG_NAME)     # kept with the egress run's receipts unless a path was named
        _teardown(proc, (hook_decider, proxy, model_route), staged, controls, egress_log)
        _seal(gate.run if gate is not None else None, home_dir)


def probe_nested(outer: Callable, workspace: Path) -> sandbox_hook.Nested:
    """Which per call sandbox can run inside the agent sandbox on this host, found by running the real runner once per
    backend: the same outer sandbox, the system interpreter, the bound runner and the strictest bash profile, around
    `true`. The backends are tried in the owner's order (`sandbox_exec.BACKENDS`: bubblewrap, then Landlock) and the
    first that works is the answer, which the decider writes into every receipt and the runner is told to hold to.
    A host that forbids nested user namespaces (an AppArmor restriction, `user.max_user_namespaces`) fails the bubblewrap
    probe and, where Landlock works, runs the call under Landlock instead. A host where neither works, or a system
    interpreter too old for the package, shows up here and not as a failed call later, and the decider then denies every
    shell command with cause 129: the stricter answer, never the outer profile alone."""
    reasons = []
    for backend in BACKENDS:
        probe = [HOOK_PYTHON, "-I", RUNNER_IN, "--workspace", str(workspace), "--backend", backend, "--profile",
                 json.dumps(Profile().to_object(), sort_keys=True, separators=(",", ":")), "--", "true"]
        reason = ""
        try:
            done = sandbox_exec._run(outer(probe), PROBE_TIMEOUT_S, b"")
            if done.returncode == 0 and not done.timed_out:
                return sandbox_hook.Nested(HOOK_PYTHON, RUNNER_IN, DECIDER_SOCKET_IN, True, "", backend)
            reason = " ".join(done.stderr.decode("utf-8", "replace").split())[-200:] or f"exit status {done.returncode}"
        except sandbox_exec.SandboxUnavailable as exc:
            reason = " ".join(str(exc).split())[-200:]
        reasons.append(f"{backend}: {reason}")
    return sandbox_hook.Nested(HOOK_PYTHON, RUNNER_IN, DECIDER_SOCKET_IN, False, "; ".join(reasons)[-300:])


def _policy_profile(home: Path, max_processes: int):
    """(the agent profile, the policy, the store of runs) of the recorded policy, or a LaunchError saying what to fix."""
    try:
        policy, store = commands.load_checked(home)
        profile = compile_profile(policy, "agent")
    except commands.AgentError as exc:
        raise LaunchError(f"{exc}, so nothing was run") from exc
    except ProfileError as exc:
        raise LaunchError(f"the recorded policy does not compile to an agent profile ({exc}), so nothing was run") from exc
    if profile.net == "none":
        raise LaunchError("the recorded policy allows no connection to the model API, so the agent could not reach "
                          "its model and nothing was run; record a policy with a connect rule for model_api")
    return replace(profile, max_processes=max_processes), policy, store


def _seal(run, home: Path) -> None:
    """Seal the run the proxy's receipts went to, if it has any; a failure is said and does not change the exit status."""
    if run is None:
        return
    try:
        if run.is_open():
            run.seal(home)
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"PrismPath could not seal the egress run {run.session} ({exc}); `prismpath agent verify` seals it later\n")


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


def _teardown(proc, routes, staged: Staged, controls: Controls, egress_log: Optional[str]) -> None:
    if proc is not None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)     # whatever the program left running; the group is ours alone
        except OSError:
            pass
        try:
            proc.wait(timeout=10)
        except Exception:   # noqa: BLE001
            pass
    for route in routes:
        if route is not None:
            route.close()
    if egress_log and staged.log.exists():
        try:
            target = Path(egress_log)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(staged.log, target)
        except OSError as exc:
            sys.stderr.write(f"PrismPath could not keep the egress log at {egress_log} ({exc})\n")
    shutil.rmtree(staged.root, ignore_errors=True)
    controls.remove_created()
