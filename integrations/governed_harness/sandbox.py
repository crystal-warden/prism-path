# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Execution of an allowed call, inside bubblewrap.

The policy decides whether a call may run; the sandbox bounds what a call that runs can reach, so that a
classifier mistake, a race between classification and execution, or a program that does more than its
name says cannot touch the host. Every allowed call runs as `python3 -I exec_tool.py` under
/usr/bin/bwrap with:

  * every namespace unshared (`--unshare-all`): no network (only a loopback with nothing behind it), no
    view of the host's processes, its own IPC and hostname;
  * the system prefix /usr read only, and nothing else of the host: not the home directory, not any
    repository, not /etc, not the host's /tmp;
  * the throwaway workspace bound read write at /workspace, its `.toolchain` directory bound again read
    only on top, a private empty /tmp, and the executor itself read only;
  * an empty environment but a fixed PATH, HOME=/tmp and a git identity, a new session (no terminal), all
    capabilities dropped, and the sandbox killed with its parent; a call has 30 seconds.

A refused or escalated call never reaches this module.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List

from prismpath.agent import sandbox_exec

BWRAP = sandbox_exec.BWRAP
EXECUTOR = Path(__file__).resolve().parent / "exec_tool.py"
MOUNT = sandbox_exec.MOUNT
TIMEOUT_S = 30


def bwrap_argv(workspace: Path) -> List[str]:
    """The bubblewrap line itself now lives in `prismpath.agent.sandbox_exec`; this adds the executor."""
    return sandbox_exec.bwrap_argv(workspace, sandbox_exec.SandboxProfile(timeout_s=TIMEOUT_S),
                                   ["/usr/bin/python3", "-I", "/run/exec_tool.py"],
                                   [(str(EXECUTOR), "/run/exec_tool.py")])


def execute(call: Dict[str, Any], workspace: Path) -> Dict[str, Any]:
    """Run one allowed call in the sandbox; `{"ok": bool, "output": text}`."""
    try:
        done = subprocess.run(bwrap_argv(workspace), input=json.dumps(call).encode(), capture_output=True,
                              timeout=TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return {"ok": False, "output": f"the call ran past {TIMEOUT_S} seconds and was stopped"}
    try:
        return json.loads(done.stdout.decode("utf-8", "replace"))
    except ValueError:
        return {"ok": False, "output": f"sandbox exit {done.returncode}: {done.stderr.decode('utf-8', 'replace')[:2000]}"}
