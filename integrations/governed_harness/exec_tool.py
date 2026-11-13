# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Runs ONE allowed tool call, inside the sandbox (sandbox.py starts it under bubblewrap). It reads the call
as JSON on standard input and writes the result as JSON on standard output. It is reached only after the
policy allowed the call; it re-checks nothing about policy, and it can touch only what the sandbox mounts:
the workspace at /workspace (its .toolchain read only), a private /tmp, and the read only system prefix.

Even so it does the least each tool means: a write never follows a final symbolic link (O_NOFOLLOW), a
delete removes one file, one link or one empty directory and never recurses, and a command runs without a
shell.
"""
import json
import os
import subprocess
import sys

LIMIT = 64 * 1024


def run(call):
    tool, args = call["tool"], call.get("args", {})
    if tool == "list_dir":
        path = args.get("path", ".")
        names = sorted(os.listdir(path))
        return "\n".join(name + ("/" if os.path.isdir(os.path.join(path, name)) else "") for name in names)
    if tool == "read_file":
        with open(args["path"], "rb") as handle:
            return handle.read(LIMIT).decode("utf-8", "replace")
    if tool == "write_file":
        fd = os.open(args["path"], os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(args["content"])
        return f"wrote {len(args['content'])} characters to {args['path']}"
    if tool == "delete_path":
        path = args["path"]
        if os.path.isdir(path) and not os.path.islink(path):
            os.rmdir(path)
        else:
            os.unlink(path)
        return f"deleted {path}"
    if tool == "run_command":
        argv = args["argv"]
    elif tool == "git":
        argv = ["git", args["subcommand"], *args.get("args", [])]
    else:
        raise ValueError(f"no such tool {tool}")
    done = subprocess.run(argv, capture_output=True, timeout=20, stdin=subprocess.DEVNULL)
    out = (done.stdout + done.stderr)[:LIMIT].decode("utf-8", "replace")
    return f"exit {done.returncode}\n{out}"


def main():
    call = json.loads(sys.stdin.read())
    try:
        result = {"ok": True, "output": run(call)}
    except Exception as error:   # noqa: BLE001 - the error is the tool's result
        result = {"ok": False, "output": f"{type(error).__name__}: {error}"}
    sys.stdout.write(json.dumps(result))


if __name__ == "__main__":
    main()
