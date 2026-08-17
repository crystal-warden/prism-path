# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""prismpath.sandbox — the runtime enforcement half of code nodes.

`SandboxRunner` executes a code node's handler in a `bwrap` subprocess whose profile is derived from the
node's declared `@code` envelope (`prismpath.code_nodes.Envelope`): network off unless `net=true`, a
filesystem scope, a memory ceiling (RLIMIT_AS), and a wall-clock timeout. **Fail-closed:** if bwrap is
unavailable it REFUSES rather than running un-sandboxed — unless an explicit override is set, in which
case the outcome is stamped `_sandbox: "off"` so the degradation is never silent.

Handlers must be importable by dotted path (`module` + top-level name). A lambda/closure/`__main__`
function cannot cross into the subprocess — by design: the sandbox imports the declared function, it does
not ship code. Linux + bwrap MVP; macOS `sandbox-exec` / Windows job-objects are follow-ons.
"""
import json
import os
import shutil
import subprocess
import sys
from typing import Optional, Tuple

from prismpath.code_nodes import Envelope

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # parent of the prismpath/ pkg


class SandboxError(Exception):
    """A code node was blocked or failed inside the sandbox (timeout, memory, network, nonzero exit)."""


class SandboxUnavailable(SandboxError):
    """The sandbox could not be applied and no override was set — the code node is refused (fail-closed)."""


def find_bwrap() -> Optional[str]:
    return shutil.which("bwrap") if sys.platform.startswith("linux") else None


def _dotted(handler) -> Optional[Tuple[str, str]]:
    mod = getattr(handler, "__module__", None)
    qn = getattr(handler, "__qualname__", "") or ""
    if not mod or mod == "__main__" or "." in qn or "<" in qn:
        return None
    return mod, qn


class SandboxRunner:
    """A `code_nodes.Runner` that enforces the envelope via bwrap. See module docstring."""

    def __init__(self, allow_unsandboxed: Optional[bool] = None, scratch_dir: Optional[str] = None):
        if allow_unsandboxed is None:
            allow_unsandboxed = os.environ.get("PRISMPATH_SANDBOX_ALLOW_UNSAFE") == "1"
        self.allow_unsandboxed = allow_unsandboxed
        self.scratch_dir = scratch_dir
        self.bwrap = find_bwrap()

    def _profile(self, env: Envelope) -> list:
        cmd = [self.bwrap, "--die-with-parent", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
               "--new-session", "--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
        if not env.net:
            cmd += ["--unshare-net"]                       # network namespace with no interfaces
        if env.fs == "rw" and self.scratch_dir:
            cmd += ["--bind", self.scratch_dir, self.scratch_dir]
        # fs == none|ro: the root is bound read-only above; only /tmp (tmpfs) is writable.
        cmd += ["--", sys.executable, "-m", "prismpath._sandbox_child"]
        return cmd

    def __call__(self, handler, env: Envelope, node: str, instruction: str, state: dict):
        if self.bwrap is None:
            if self.allow_unsandboxed:
                out = handler(node, instruction, state)
                return {**out, "_sandbox": "off"} if isinstance(out, dict) else out
            raise SandboxUnavailable(
                f"code node {node!r}: bwrap unavailable (platform {sys.platform}) and no override — "
                f"refusing to run code un-sandboxed. Set PRISMPATH_SANDBOX_ALLOW_UNSAFE=1 to override.")
        dotted = _dotted(handler)
        if dotted is None:
            raise SandboxError(
                f"code node {node!r}: handler is not importable by dotted path "
                f"(lambdas/closures/__main__ cannot cross into the sandbox)")
        module, func = dotted
        job = json.dumps({"module": module, "func": func, "node": node, "instruction": instruction,
                          "state": state, "mem_mb": env.mem_mb})
        child_env = dict(os.environ)
        child_env["PYTHONPATH"] = _REPO_ROOT + os.pathsep + child_env.get("PYTHONPATH", "")
        try:
            p = subprocess.run(self._profile(env), input=job, capture_output=True, text=True,
                               timeout=env.timeout_s + 2, env=child_env)
        except subprocess.TimeoutExpired:
            raise SandboxError(f"code node {node!r}: exceeded timeout_s={env.timeout_s}")
        try:
            res = json.loads(p.stdout or "{}")
        except json.JSONDecodeError:
            raise SandboxError(f"code node {node!r}: sandbox produced no result "
                               f"(rc={p.returncode}): {(p.stderr or p.stdout or '')[:200]}")
        if not res.get("ok"):
            raise SandboxError(f"code node {node!r}: {res.get('error', 'sandbox error')}")
        return res["outcome"]
