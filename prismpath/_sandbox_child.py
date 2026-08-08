"""Child process for prismpath.sandbox — runs ONE code-node handler under a memory rlimit and reports
the outcome as JSON. Invoked as `python -m prismpath._sandbox_child` INSIDE the bwrap sandbox; it reads
a single JSON job on stdin: {module, func, node, instruction, state, mem_mb}.

It imports the handler by dotted path (the sandbox never ships code, it imports a declared function),
applies RLIMIT_AS, runs, and writes {"ok": true, "outcome": …} or {"ok": false, "error": …}.
"""
import importlib
import json
import resource
import sys


def main() -> int:
    try:
        job = json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError as e:
        sys.stdout.write(json.dumps({"ok": False, "error": f"bad job: {e}"}))
        return 1
    mem_mb = int(job.get("mem_mb", 256))
    try:
        cap = mem_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (cap, cap))
    except (ValueError, OSError):
        pass  # best-effort; the wall-clock + namespaces still apply
    try:
        mod = importlib.import_module(job["module"])
        func = getattr(mod, job["func"])
        outcome = func(job.get("node", ""), job.get("instruction", ""), job.get("state") or {})
        sys.stdout.write(json.dumps({"ok": True, "outcome": outcome}))
        return 0
    except BaseException as e:  # MemoryError is a BaseException subclass; catch it too
        sys.stdout.write(json.dumps({"ok": False, "error": f"{type(e).__name__}: {str(e)[:200]}"}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
