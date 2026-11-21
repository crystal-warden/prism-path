# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""What the sandbox's own run of an allowed shell command shows about what the command tried and could not do.

An observation is evidence about the worker. It changes what the system knows and never what it is permitted
to do: nothing in this file, or in the code that reads an observation, edits a policy, a profile, a rule or
any decision, and `prismpath agent rules` does not count an observation as a rule hit. Only a signed policy
widens or narrows what runs.

How it is observed, and what that can and cannot show. bubblewrap reports no denied open and no refused
connect, and seccomp or Landlock audit needs privilege or a kernel facility this does not rely on. The runner
(prismpath/agent/sandbox_exec.py) therefore reads the command's own result: its exit status, whether it hit the
time limit, and the standard error it wrote, for the C library's error texts (`Permission denied`, `Network is
unreachable`, ...). That is indicative and is labelled `method: "stderr-pattern"` in every entry. It misses a
refusal the command swallowed or sent to `/dev/null`, and a `No such file or directory` is what the sandbox
gives for a path it did not mount and also what a missing file gives, so it is recorded as `path-absent` and
not as a refusal. The profile and the policy decide what is stopped. This file only notes what the command said.

Where it is kept, and why not in the signed root. `core-receipt/1` and the root statement are the oracle's
format and are not changed. Observations live in `observations.jsonl` beside the run's journal. Each line is one
canon/2 object (`prismpath.observation/1`) with the index and SHA-256 of the receipt of the allowed call it is
bound to, the image hash, the profile hash, a sequence number, the hash of the previous line and its own SHA-256
over the other fields. `Run.verify_observations` checks every line: its own hash, the chain, that the receipt
exists and hashes to the recorded value, and that the image and profile hashes are the receipt's and the
journal line's. The file is not under the signed Merkle root, so a whole line removed from the end cannot be
detected, and a rewritten file that is internally consistent cannot be told from the original except by the
receipts it names. A later format may seal its head into the root statement.

Outcomes are the same kind of record, kept the same way, in `outcomes.jsonl` (`Run.outcome_of_runner`, and
`Run.outcome_of_hook` for the PostToolUse hooks): the runner reporting that a command finished is an outcome of
its receipt whether or not the command showed anything.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence

FORMAT = "prismpath.observation/1"
FILE = "observations.jsonl"
METHOD = "stderr-pattern"
MAX_SIGNALS = 8
MAX_TEXT = 200

# (kind, pattern over one line of standard error). `path-absent` is deliberately not called a refusal.
_PATTERNS = (
    ("access-denied", re.compile(r"Permission denied|Operation not permitted")),
    ("write-refused", re.compile(r"Read-only file system")),
    ("path-absent", re.compile(r"No such file or directory")),
    ("network-unreachable", re.compile(
        r"Network is unreachable|Temporary failure in name resolution|Name or service not known|"
        r"Could not resolve host|Cannot assign requested address")),
    ("process-limit", re.compile(r"Cannot fork|fork: retry|Resource temporarily unavailable")),
)


def signals(stderr: bytes, timed_out: bool = False) -> List[Dict[str, str]]:
    """The error texts in `stderr` that look like the sandbox stopping an access, one per line, at most
    MAX_SIGNALS, each text cut to MAX_TEXT characters. A time-out is its own signal."""
    found: List[Dict[str, str]] = []
    for line in stderr.decode("utf-8", "replace").splitlines():
        for kind, pattern in _PATTERNS:
            if pattern.search(line):
                found.append({"kind": kind, "text": " ".join(line.split())[:MAX_TEXT]})
                break
        if len(found) >= MAX_SIGNALS:
            break
    if timed_out:
        found.append({"kind": "time-limit", "text": "stopped at the time limit"})
    return found


def observed(returncode: int, stderr: bytes, timed_out: bool = False, backend: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """The `observed` body for one finished sandboxed command, or None when its stderr shows nothing. `backend` is
    the per call sandbox that ran the command (`bwrap` or `landlock`)."""
    found = signals(stderr, timed_out)
    if not found:
        return None
    body = {"method": METHOD, "exit_status": int(returncode), "timed_out": bool(timed_out), "signals": found}
    if backend:
        body["backend"] = str(backend)[:16]
    return body


def record(run_dir: str, session: str, receipt: int, image_sha256: str, profile_sha256: str,
           returncode: int, stderr: bytes, timed_out: bool = False, backend: Optional[str] = None) -> Optional[int]:
    """Record the observation of one finished command on the run, bound to the receipt `receipt` of the allowed
    call, and the fact that the runner finished it as an outcome of that receipt (Run.outcome_of_runner, which is
    read only like an observation). Returns the observation's sequence number, or None when there was nothing to
    observe. Imported late so a command pays for the run store only when it runs."""
    from pathlib import Path
    from prismpath.agent.run import Run
    run = Run(Path(run_dir), session)
    body = observed(returncode, stderr, timed_out, backend)
    number = run.observe(receipt, image_sha256, profile_sha256, body) if body is not None else None
    run.outcome_of_runner(receipt, image_sha256, profile_sha256, returncode, timed_out)
    return number


def argv(run_dir: str, session: str, receipt: int, image_sha256: str, profile_sha256: str) -> Sequence[str]:
    """The runner flags the hook adds so the runner can bind an observation to the receipt."""
    return ["--observe-run", run_dir, "--observe-session", session, "--observe-receipt", str(receipt),
            "--observe-image", image_sha256, "--observe-profile", profile_sha256]


EVENT = "PrismPathObservation"
MAX_STDERR = 1 << 16
SOCKET_TIMEOUT_S = 10.0


def socket_argv(socket_path: str, session: str, receipt: int, image_sha256: str, profile_sha256: str) -> Sequence[str]:
    """The runner flags of a runner inside the outer agent sandbox: it has no run directory, so it asks the decider
    in the launcher to record the observation."""
    return ["--observe-socket", socket_path, "--observe-session", session, "--observe-receipt", str(receipt),
            "--observe-image", image_sha256, "--observe-profile", profile_sha256]


def send(socket_path: str, session: str, receipt: int, image_sha256: str, profile_sha256: str,
         returncode: int, stderr: bytes, timed_out: bool = False, backend: Optional[str] = None) -> None:
    """Ask the decider to record the observation of one finished command (standard library only). The decider
    reads the error texts itself, from the tail of `stderr`, and refuses a receipt or a hash that is not the
    call's. What a caller inside the sandbox sends is a claim, and it can only add knowledge, never widen anything."""
    import json
    import socket
    text = stderr[-MAX_STDERR:].decode("utf-8", "replace")
    body = json.dumps({"hook_event_name": EVENT, "session_id": session, "receipt": int(receipt),
                       "image_sha256": image_sha256, "profile_sha256": profile_sha256, "returncode": int(returncode),
                       "timed_out": bool(timed_out), "stderr": text, "backend": backend or ""}).encode("utf-8")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(SOCKET_TIMEOUT_S)
        sock.connect(socket_path)
        sock.sendall(body)
        sock.shutdown(socket.SHUT_WR)
        reply = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            reply += chunk
            if len(reply) > 65536:
                break
    finally:
        sock.close()
    answer = json.loads(reply.decode("utf-8"))
    if not isinstance(answer, dict) or answer.get("recorded") is not True:
        raise RuntimeError(str(answer.get("systemMessage", "not recorded")) if isinstance(answer, dict) else "bad reply")
