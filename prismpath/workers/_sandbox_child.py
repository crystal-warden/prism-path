# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Child process for prismpath.sandbox — runs ONE code-node handler under a memory rlimit and reports
the outcome as JSON. Invoked as `python -m prismpath.workers._sandbox_child` INSIDE the bwrap sandbox; it reads
a single JSON job on stdin: {module, func, node, instruction, state, mem_mb}.

It imports the handler by dotted path (the sandbox never ships code, it imports a declared function),
applies RLIMIT_AS, runs, and writes {"ok": true, "outcome": …} or {"ok": false, "error": …}.
"""
import importlib
import json
import resource
import sys


def apply_memory_cap(mem_mb: int) -> bool:
    """Apply the job's RLIMIT_AS and report whether the kernel took it.

    Best effort by design (the wall clock and the namespaces still apply), but the caller has to be
    able to tell an enforced envelope from one that silently did not apply."""
    cap = mem_mb * 1024 * 1024
    try:
        resource.setrlimit(resource.RLIMIT_AS, (cap, cap))
        return True
    except (ValueError, OSError):
        return False


def main() -> int:
    try:
        job = json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError as error:
        sys.stdout.write(json.dumps({"ok": False, "error": f"bad job: {error}"}))
        return 1
    mem_mb = int(job.get("mem_mb", 256))
    mem_enforced = apply_memory_cap(mem_mb)
    try:
        mod = importlib.import_module(job["module"])
        func = getattr(mod, job["func"])
        outcome = func(job.get("node", ""), job.get("instruction", ""), job.get("state") or {})
        sys.stdout.write(json.dumps({"ok": True, "outcome": outcome, "mem_enforced": mem_enforced}))
        return 0
    except BaseException as error:  # MemoryError is a BaseException subclass; catch it too
        sys.stdout.write(json.dumps({"ok": False, "error": f"{type(error).__name__}: {str(error)[:200]}"}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
