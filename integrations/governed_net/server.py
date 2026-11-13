# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The tool server: behind the XDP program, it re-derives every request and decides it again.

A lying client can put anything in a header, and XDP decides what the header says. So the server trusts
nothing it receives, not even the fact that it arrived:

  1. it reads the datagram strictly (`protocol.decode`); a malformed request that reached it is a FINDING,
     since XDP drops every malformed request;
  2. it refuses a request id it has seen (a replay) before anything else;
  3. it re-derives the decided fields from its own state: the handle's class comes from the server's own
     handle table, never from the header, and a handle it never issued is a finding; the other fields are
     the header's and the lengths are the bytes actually carried;
  4. it decides the re-derived reading with the Python kernel on the same signed image and writes that
     receipt (decider `server`) before anything runs;
  5. it executes only when its own decision is `allow` AND the header's class is the true class. Every
     request that arrives has passed XDP, so its own refusal of an arrived request, or a class the header
     lied about, is a disagreement between the two decisions: recorded as a finding, never executed;
  6. an allowed call runs confined: through `governed_harness.sandbox` (bubblewrap, every namespace
     unshared so no network, only the workspace writable, its `.toolchain` read only), the file named by
     the path the server itself resolved for the handle.

Handles. The workspace root is handle 1. LIST issues a handle for each entry of a directory it may list;
a symbolic link is never issued a handle (it is not listed), so no request can name one. An entry under
the workspace's `.toolchain` directory gets a toolchain class, every other entry a workspace class. CREATE
issues the new file's handle. Paths never cross the wire.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import stat
import sys
import threading
from pathlib import Path
from typing import Dict, Optional, Tuple

from integrations.governed_harness import evidence, sandbox

from . import protocol as p
from .policy import NetPolicy

DECIDER = "server"
TOOLCHAIN = ".toolchain"


class Handles:
    """The server's handle table: handle -> (class, path relative to the workspace)."""

    def __init__(self, workspace: Path):
        self.workspace = Path(os.path.realpath(workspace))
        self.table: Dict[int, Tuple[int, str]] = {p.ROOT_HANDLE: (p.H_WS_DIR, ".")}
        self.by_path: Dict[str, int] = {".": p.ROOT_HANDLE}
        self.next = p.ROOT_HANDLE + 1

    def _class_of(self, rel: str, is_dir: bool) -> int:
        top = rel.split("/", 1)[0]
        if top == TOOLCHAIN:
            return p.H_TC_DIR if is_dir else p.H_TC_FILE
        return p.H_WS_DIR if is_dir else p.H_WS_FILE

    def issue(self, rel: str, is_dir: bool) -> int:
        if rel in self.by_path:
            return self.by_path[rel]
        handle = self.next
        self.next += 1
        self.table[handle] = (self._class_of(rel, is_dir), rel)
        self.by_path[rel] = handle
        return handle

    def forget(self, handle: int) -> None:
        _cls, rel = self.table.pop(handle)
        self.by_path.pop(rel, None)

    def lookup(self, handle: int) -> Optional[Tuple[int, str]]:
        return self.table.get(handle)

    def listing(self, rel: str):
        """The entries of a directory with their handles; links and anything that is not a plain file or
        directory are left out, so they are never named."""
        entries = []
        base = self.workspace / rel
        for name in sorted(os.listdir(base)):
            if name == ".git":
                continue
            full = base / name
            mode = os.lstat(full).st_mode
            if stat.S_ISLNK(mode) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                continue
            child = name if rel == "." else f"{rel}/{name}"
            handle = self.issue(child, stat.S_ISDIR(mode))
            entries.append((self.table[handle][0], handle, name + ("/" if stat.S_ISDIR(mode) else "")))
        return entries


class ToolServer:
    def __init__(self, workspace: Path, policy: NetPolicy, run: Path, keys: Path, execute=sandbox.execute):
        self.workspace = Path(os.path.realpath(workspace))
        self.policy, self.handles, self.execute = policy, Handles(self.workspace), execute
        self.run = evidence.EpisodeRun(Path(run), "server", policy.image, keys, decider=DECIDER)
        self.seen = set()
        self.findings = []
        self.executed = []
        self.lock = threading.Lock()

    def _finding(self, request_id: int, kind: str, **detail) -> p.Reply:
        self.findings.append({"request_id": request_id, "finding": kind, **detail})
        return p.Reply(p.FINDING, request_id, body=kind.encode())

    def handle(self, raw: bytes) -> Optional[p.Reply]:
        with self.lock:
            try:
                req = p.decode(raw)
            except p.Malformed as bad:
                # XDP drops every malformed request, so one that arrived came around it
                self.findings.append({"request_id": None, "finding": "malformed-arrived", "reason": bad.reason})
                return None
            if req.request_id in self.seen:
                return self._finding(req.request_id, "replayed-request-id")
            self.seen.add(req.request_id)
            true_class, rel = 0, None
            if req.cmd in p.USES_HANDLE:
                found = self.handles.lookup(req.handle)
                if found is None:
                    return self._finding(req.request_id, "unissued-handle", handle=req.handle, claimed=req.hclass)
                true_class, rel = found
            reading = req.reading(hclass=true_class)
            decision = self.policy.decide(self.policy.reading_bytes(reading))
            idx = self.run.record(self.policy.reading_bytes(reading), decision.verdict)   # before anything runs
            if true_class != req.hclass:
                return self._finding(req.request_id, "class-mismatch", claimed=req.hclass, true=true_class,
                                     server_decision=[decision.kind, decision.cause], receipt=idx)
            if not decision.runs:
                return self._finding(req.request_id, "server-refuses-what-arrived",
                                     server_decision=[decision.kind, decision.cause], receipt=idx)
            ok, body = self._run(req, rel)
            self.executed.append({"request_id": req.request_id, "reading": reading, "receipt": idx, "ok": ok})
            return p.Reply(p.OK if ok else p.TOOL_ERROR, req.request_id, 0, idx, body)

    # ------------------------------------------------------------------ execution, confined
    def _call(self, call) -> Tuple[bool, str]:
        result = self.execute(call, self.workspace)
        return bool(result["ok"]), result["output"]

    def _run(self, req: p.Request, rel: Optional[str]) -> Tuple[bool, bytes]:
        mount = lambda path: sandbox.MOUNT + ("" if path == "." else "/" + path)   # noqa: E731
        if req.cmd == p.LIST:
            return True, p.encode_listing(self.handles.listing(rel))
        if req.cmd == p.READ:
            ok, out = self._call({"tool": "read_file", "args": {"path": mount(rel)}})
            return ok, (out[req.arg0:req.arg0 + req.arg1] if ok else out).encode()
        if req.cmd == p.WRITE:
            try:
                content = req.data.decode("utf-8")
            except UnicodeDecodeError:
                return False, b"the data is not UTF-8 text"
            ok, out = self._call({"tool": "write_file", "args": {"path": mount(rel), "content": content}})
            return ok, out.encode()
        if req.cmd == p.CREATE:
            child = req.name.decode("ascii") if rel == "." else f"{rel}/{req.name.decode('ascii')}"
            if os.path.lexists(self.workspace / child):
                return False, b"exists"
            try:
                content = req.data.decode("utf-8")
            except UnicodeDecodeError:
                return False, b"the data is not UTF-8 text"
            ok, out = self._call({"tool": "write_file", "args": {"path": mount(child), "content": content}})
            if not ok:
                return False, out.encode()
            handle = self.handles.issue(child, False)
            return True, p.encode_listing([(self.handles.lookup(handle)[0], handle, req.name.decode("ascii"))])
        if req.cmd == p.DELETE:
            ok, out = self._call({"tool": "delete_path", "args": {"path": mount(rel)}})
            if ok:
                self.handles.forget(req.handle)
            return ok, out.encode()
        if req.cmd == p.RUN:
            _name, argv = p.PROGRAMS[req.arg0]
            ok, out = self._call({"tool": "run_command", "args": {"argv": [*argv, mount(rel)]}})
            return ok, out.encode()
        if req.cmd == p.GIT_STATUS:
            ok, out = self._call({"tool": "git", "args": {"subcommand": "status", "args": ["--short"]}})
            return ok, out.encode()
        if req.cmd == p.GIT_LOG:
            ok, out = self._call({"tool": "git", "args": {"subcommand": "log", "args": [f"-{req.arg0}", "--oneline"]}})
            return ok, out.encode()
        if req.cmd == p.GIT_COMMIT:
            message = req.data.decode("utf-8", "replace")
            ok, out = self._call({"tool": "git", "args": {"subcommand": "add", "args": ["-A"]}})
            if ok:
                ok, out = self._call({"tool": "git", "args": {"subcommand": "commit", "args": ["-m", message]}})
            return ok, out.encode()
        return False, b"no such command"          # unreachable: the policy allows no other command

    def close(self) -> Dict:
        (self.run.run / "findings.json").write_text(json.dumps(self.findings, indent=1))
        (self.run.run / "executed.json").write_text(json.dumps(self.executed, indent=1))
        return self.run.close()


def serve(server: ToolServer, sock: socket.socket, stop: threading.Event) -> None:
    sock.settimeout(0.2)
    while not stop.is_set():
        try:
            raw, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError:
            return
        reply = server.handle(raw)
        if reply is not None:
            sock.sendto(p.encode_reply(reply), addr)


def main(argv=None) -> int:
    """Run until standard input ends, then seal the server's run. Prints the bound port first."""
    parser = argparse.ArgumentParser(description="the governed net tool server")
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--keys", required=True)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args(argv)
    server = ToolServer(Path(args.workspace), NetPolicy.load(), Path(args.run), Path(args.keys))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind, args.port))
    print(sock.getsockname()[1], flush=True)
    stop = threading.Event()
    thread = threading.Thread(target=serve, args=(server, sock, stop), daemon=True)
    thread.start()
    sys.stdin.read()
    stop.set()
    thread.join()
    sock.close()
    print(json.dumps(server.close()), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
