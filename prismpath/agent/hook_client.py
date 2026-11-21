# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The hook client that runs INSIDE the agent sandbox.

Claude Code runs the hook command as a child of the sandboxed agent, so the hook cannot hold the keys, the
policy or the run directory. This file is the whole hook there: it reads the hook input on stdin, sends it to
the decider (`prismpath/agent/decider.py`, in the launcher, outside) over the unix socket named by its one
argument, and prints the answer. The launcher copies this file, unchanged, into the staged config directory and
binds it read only. It imports the standard library and nothing of PrismPath, and runs under /usr/bin/python3.

It fails closed. A missing socket, a timeout, a reply that is not JSON or does not decide, an input that is too
large: each prints a deny with the registered cause 126 `agent:hook-error` and exits 0. The settings run it as
`python3 -I hook_client.py SOCKET || exit 2`, so a crash before this code runs is a block as well.
"""
import json
import socket
import sys

MAX_INPUT = 1 << 20
MAX_REPLY = 1 << 20
TIMEOUT_S = 30.0
CAUSE = "126 agent:hook-error"


def deny(detail):
    detail = " ".join(str(detail).split()) or "error"
    if len(detail) > 240:
        detail = detail[:237] + "..."
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "deny",
        "permissionDecisionReason": f"PrismPath refused this call: cause {CAUSE} ({detail}). It was not run. "
                                    f"No receipt was written for it."}}


def _read_all(sock, limit):
    chunks, size = [], 0
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            return b"".join(chunks)
        size += len(chunk)
        if size > limit:
            raise ValueError("the reply is too large")
        chunks.append(chunk)


def _check(answer, event):
    """The reply must be an object, and for a tool call it must carry a decision."""
    if not isinstance(answer, dict):
        raise ValueError("the reply is not an object")
    if event == "PreToolUse":
        out = answer.get("hookSpecificOutput")
        if not isinstance(out, dict) or out.get("permissionDecision") not in ("allow", "deny", "ask"):
            raise ValueError("the reply holds no decision")
    return answer


def ask(path, raw):
    """The decider's answer to `raw`, or the deny that stands in for it."""
    event = None
    try:
        try:
            data = json.loads(raw.decode("utf-8"))
            event = data.get("hook_event_name") if isinstance(data, dict) else None
        except ValueError:
            pass
        if len(raw) > MAX_INPUT:
            raise ValueError("the hook input is too large")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(TIMEOUT_S)
            sock.connect(path)
            sock.sendall(raw)
            sock.shutdown(socket.SHUT_WR)
            reply = _read_all(sock, MAX_REPLY)
        finally:
            sock.close()
        return _check(json.loads(reply.decode("utf-8")), event)
    except BaseException as exc:    # noqa: BLE001 - nothing here may let a call through
        if event == "SessionEnd":
            return {"systemMessage": f"PrismPath could not seal this session's run: cause {CAUSE} "
                                     f"({type(exc).__name__}). `prismpath agent verify` seals it later."}
        return deny(f"the decider did not answer: {type(exc).__name__}")


def main(argv):
    try:
        if len(argv) != 2:
            raise ValueError("no decider socket named")
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        answer = ask(argv[1], raw)
    except BaseException as exc:    # noqa: BLE001
        answer = deny(f"the hook client failed: {type(exc).__name__}")
    try:
        sys.stdout.write(json.dumps(answer) + "\n")
        sys.stdout.flush()
    except BaseException:           # noqa: BLE001 - nothing left to tell
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
