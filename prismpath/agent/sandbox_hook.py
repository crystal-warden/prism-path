# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""What the Claude Code hook does to a Bash call the policy allowed: run it inside the sandbox the same policy compiles to.

The hook decides a call under the active attested image. For an allowed Bash call it then

  1. compiles the image to a profile (`prismpath.agent.profile.compile_profile`), which takes seconds, so the
     result is cached beside the recorded policy under the image's SHA-256 (`<config>/profiles/<sha>.json`);
     a cache entry is used only when it parses, names this image and its profile hashes to the hash it records,
     and is otherwise recompiled;
  2. answers `allow` with `updatedInput`, the whole tool input with `command` replaced by a command that runs the
     original under `prismpath/agent/sandbox_exec.py` (`updatedInput` replaces the
     whole object, so every other field is carried over unchanged);
  3. returns the profile's hash for the receipt.

The rewritten command invokes the runner by the absolute path of the interpreter that runs the hook, with `-I`
(no `PYTHONPATH`, no current directory, no user site, so the agent's environment cannot swap the program), and
by the absolute path of the runner file. Each argument, the original command above all, is passed through
`shlex.quote`, which wraps it in single quotes (a single quote inside becomes `'"'"'`), so whatever the agent
wrote, a quote, a semicolon, `$(...)`, a newline, is one argument to the runner and is read by a shell only
inside the sandbox.

On any platform but Linux `supported()` is false and the hook does not rewrite (see commands.hook): the call is
decided and not confined, and `prismpath agent status` and `doctor` say so. The time limit of a call is the Bash
`timeout` the model gave, else 120 s, at most 600 s (`call_timeout_s`).

It fails closed. A profile that does not compile or a missing bwrap raises `SandboxRefused`, which the hook
answers as a deny with cause 129 `agent:sandbox-unavailable`. A bwrap that is present and cannot start (user
namespaces off) is found when the command runs: the runner exits 126 and the command is not run.
"""
from __future__ import annotations

import json
import os
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

PROFILES_DIR = "profiles"
RUNNER = Path(__file__).resolve().parent / "sandbox_exec.py"
SANDBOX_CAUSE = "agent:sandbox-unavailable"


DEFAULT_TIMEOUT_S = 120        # Claude Code's own default for a Bash call
MAX_TIMEOUT_S = 600            # and its maximum


def supported() -> bool:
    """True where the sandbox applies: Linux. Elsewhere the hook decides a shell command and does not confine it."""
    return sys.platform.startswith("linux")


def call_timeout_s(tool_input: Mapping[str, Any]) -> int:
    """The time limit of one call: the Bash `timeout` (milliseconds, as Claude Code sends it) when it is a positive
    number, else 120 s, never past 600 s. The profile's `timeout_s` is the default of a caller that gives none
    (`run_sandboxed`), not what the hook applies, so the profile and its hash are the same for every call."""
    value = tool_input.get("timeout")
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not value > 0:
        return DEFAULT_TIMEOUT_S
    return max(1, min(MAX_TIMEOUT_S, int(-(-value // 1000))))


class SandboxRefused(Exception):
    """The call was allowed but cannot be run inside the sandbox; the hook denies it."""


@dataclass(frozen=True)
class Nested:
    """Where the per call sandbox runs: inside the outer agent sandbox of `prismpath agent run`. The host interpreter and the host checkout do not exist there, so the rewrite names the
    system interpreter (under the read only system prefix) and a runner that the launcher bound read only, and the
    runner reaches the launcher's decider over `socket` to record what the command showed. `available` is what the
    launcher measured at start by running this very runner nested once; when it is false every shell command is
    refused with cause 129, never run under the outer profile alone (the outer sandbox holds the model credential
    for the agent itself, which a shell child must not see)."""
    python: str
    runner: str
    socket: str
    available: bool = True
    reason: str = ""
    backend: str = "bwrap"      # the per call sandbox the launcher found to work here: bubblewrap, else Landlock


def _sha256_hex(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


def _binding(image_sha: str, compiler: int, profile_sha: str) -> str:
    """What ties a cached profile to the policy image it was compiled from and to the compiler that compiled it,
    so an entry made for another image, or by another compiler version, is never used."""
    return _sha256_hex(f"prismpath.profile-cache/1\0{image_sha}\0{compiler}\0{profile_sha}".encode("ascii"))


def profile_for(home: Path, image: bytes):
    """The profile of `image`, from the cache in `home` or compiled and cached. A cache entry is used only when it names
    this image's digest and the current compiler version and its binding hash over both agrees. Raises SandboxRefused."""
    from prismpath.agent import profile as profile_module
    image_sha = _sha256_hex(image)
    cache = Path(home) / PROFILES_DIR / f"{image_sha}.json"
    try:
        entry = json.loads(cache.read_text(encoding="utf-8"))
        loaded = profile_module.Profile(
            ro_mounts=tuple(entry["profile"]["ro_mounts"]), rw_path=entry["profile"]["rw_path"],
            host_write=bool(entry["profile"]["host_write"]), network=bool(entry["profile"]["network"]),
            max_processes=int(entry["profile"]["max_processes"]), timeout_s=int(entry["profile"]["timeout_s"]))
        if entry["image_sha256"] == image_sha and entry["profile_sha256"] == loaded.hash() \
                and entry["compiler"] == profile_module.COMPILER_VERSION \
                and entry["binding"] == _binding(image_sha, profile_module.COMPILER_VERSION, loaded.hash()) \
                and loaded.to_object() == entry["profile"]:
            return loaded
    except (OSError, ValueError, KeyError, TypeError):
        pass
    try:
        compiled = profile_module.compile_profile(image)
    except Exception as exc:    # noqa: BLE001 - any failure to compile is a refusal, never a guess
        raise SandboxRefused(f"the policy's sandbox profile did not compile: {' '.join(str(exc).split())[:160]}") from exc
    try:
        cache.parent.mkdir(parents=True, exist_ok=True)
        tmp = cache.with_name(cache.name + f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps({"image_sha256": image_sha, "profile_sha256": compiled.hash(),
                                   "compiler": profile_module.COMPILER_VERSION,
                                   "binding": _binding(image_sha, profile_module.COMPILER_VERSION, compiled.hash()),
                                   "profile": compiled.to_object()}, sort_keys=True), encoding="utf-8")
        os.replace(tmp, cache)
    except OSError:
        pass                    # a cache that cannot be written only costs the next call a compile
    return compiled


def rewrite_command(command: str, workspace: str, cwd: str, profile, python: Optional[str] = None,
                    timeout_s: Optional[int] = None, observe: Optional[Mapping[str, Any]] = None,
                    runner: Optional[str] = None, backend: Optional[str] = None,
                    control_paths: Sequence[str] = ()) -> str:
    """The shell command that runs `command` under the sandbox with `profile`."""
    python = python or sys.executable
    parts = [python, "-I", str(runner or RUNNER), "--workspace", workspace, "--cwd", cwd,
             "--profile", json.dumps(profile.to_object(), sort_keys=True, separators=(",", ":"))]
    if timeout_s is not None:
        parts += ["--timeout", str(int(timeout_s))]
    if backend:     # nested: the launcher measured which per call sandbox works inside, and the runner holds to it
        parts += ["--backend", backend]
    for path in control_paths:      # held read only beside the fixed control paths (the zone index, zones.py)
        parts += ["--control-path", str(path)]
    if observe:     # where the runner records what the command showed, bound to the call's receipt (observe.py)
        from prismpath.agent import observe as observe_module
        if "socket" in observe:     # nested: the run directory is outside, so the decider records it
            parts += observe_module.socket_argv(observe["socket"], observe["session"], observe["receipt"],
                                                observe["image_sha256"], observe["profile_sha256"])
        else:
            parts += observe_module.argv(observe["run_dir"], observe["session"], observe["receipt"],
                                         observe["image_sha256"], observe["profile_sha256"])
    parts += ["--", command]
    return " ".join(shlex.quote(part) for part in parts)


def sandbox_input(hook_input: Mapping[str, Any], workspace: str, profile, python: Optional[str] = None,
                  observe: Optional[Mapping[str, Any]] = None, runner: Optional[str] = None,
                  backend: Optional[str] = None, control_paths: Sequence[str] = ()) -> Dict[str, Any]:
    """`updatedInput` for an allowed Bash call: the original tool input, whole, with only `command` replaced."""
    tool_input = hook_input.get("tool_input")
    if not isinstance(tool_input, dict) or not isinstance(tool_input.get("command"), str):
        raise SandboxRefused("the Bash call has no command to sandbox")
    cwd = hook_input.get("cwd") if isinstance(hook_input.get("cwd"), str) and hook_input.get("cwd") else workspace
    out = dict(tool_input)
    out["command"] = rewrite_command(tool_input["command"], workspace, cwd, profile, python, call_timeout_s(tool_input), observe, runner, backend, control_paths)
    return out


def sandbox_profile_for_call(hook_input: Mapping[str, Any], home: Path, image: bytes, nested: Optional[Nested] = None,
                             floor: Optional[bytes] = None):
    """The profile an allowed Bash call runs under, after the checks that make it runnable. Raises SandboxRefused.
    Nested, it also refuses when the outer sandbox cannot host the per call one, and when the profile asks for a
    view of the host (`/` read only): inside, `/` is the outer sandbox's own root, which holds the model credential.
    `floor` is the `policy.core` of the action floor a home that follows a stream holds: the profile is then the one
    compiled from `image` and the floor together, so the sandbox never blocks what the floor allows (AF1). A floor that
    does not compile to a profile adds nothing."""
    from prismpath.agent import sandbox_exec
    tool_input = hook_input.get("tool_input")
    if not isinstance(tool_input, dict) or not isinstance(tool_input.get("command"), str):
        raise SandboxRefused("the Bash call has no command to sandbox")
    if nested is not None and not nested.available:
        raise SandboxRefused("a per call sandbox cannot be nested inside the agent sandbox on this host, so the command "
                             "was not run" + (f" ({nested.reason})" if nested.reason else ""))
    if not sandbox_exec.available():
        raise SandboxRefused(f"{sandbox_exec.BWRAP} is missing, so the command cannot be sandboxed")
    profile = profile_for(home, image)
    if floor is not None and floor != image:
        from prismpath.agent import profile as profile_module
        try:
            profile = profile_module.join(profile, profile_for(home, floor))
        except SandboxRefused:
            pass
    if nested is not None and "/" in profile.ro_mounts:
        raise SandboxRefused("the policy lets a shell command see the host, and inside the agent sandbox that view would "
                             "include the model credential, so the command was not run")
    return profile


def sandbox_allowed_bash(hook_input: Mapping[str, Any], workspace: str, home: Path, image: bytes
                         ) -> Tuple[Dict[str, Any], str]:
    """(updatedInput, profile hash) for an allowed Bash call. Raises SandboxRefused."""
    from prismpath.agent import sandbox_exec
    if not sandbox_exec.available():
        raise SandboxRefused(f"{sandbox_exec.BWRAP} is missing, so the command cannot be sandboxed")
    profile = profile_for(home, image)
    return sandbox_input(hook_input, workspace, profile), profile.hash()
