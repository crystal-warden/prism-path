# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The decider of `prismpath agent run` (agent-sandbox-plan, section 4 and WP5).

It runs in the launcher process, outside the sandbox, on a unix socket the launcher binds into the sandbox. The
thin hook client inside (`hook_client.py`) sends it one hook input per connection and reads one answer. The
decision is `commands.hook`, the code the stdin hook runs today (classifier, policy, receipt, observations), with
the keys, the policy and the runs directory that stay outside, and the disk facts read on the host against the
real workspace, which the sandbox mounts at the same path.

Shell commands. The per call sandbox rewrite names the host interpreter by absolute path, which does not exist
inside the outer sandbox, so the decider asks for `direct=True`: an allowed shell command runs as it is inside
the outer sandbox, the receipt carries no sandbox profile, and the answer says so. A per call sandbox nested in
the outer one is WP8.

Bounds. One request is read to EOF within `read_timeout_s` and at most `max_input` bytes, else it is answered
with a deny and nothing is decided. At most `max_connections` are served at once and decisions are taken one at
a time, since they append to one journal. Whatever a request does, the accept loop goes on.
"""
from __future__ import annotations

import json
import os
import socket
import threading
import time
from pathlib import Path
from typing import Callable, Mapping, Optional

from prismpath.agent import commands

MAX_INPUT = 1 << 20
READ_TIMEOUT_S = 10.0
MAX_CONNECTIONS = 8


class Decider:
    def __init__(self, path, env: Optional[Mapping[str, str]] = None, max_input: int = MAX_INPUT,
                 read_timeout_s: float = READ_TIMEOUT_S, max_connections: int = MAX_CONNECTIONS,
                 handler: Optional[Callable[[bytes], dict]] = None):
        self.path = Path(path)
        self.env = dict(os.environ if env is None else env)
        self.max_input = max_input
        self.read_timeout_s = read_timeout_s
        self._handler = handler or (lambda raw: commands.hook(raw, self.env, direct=True))
        self._slots = threading.BoundedSemaphore(max_connections)
        self._decide = threading.Lock()
        self._server: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._closed = False

    def start(self) -> "Decider":
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            if self.path.exists() or self.path.is_symlink():
                self.path.unlink()
            server.bind(str(self.path))
            os.chmod(self.path, 0o600)
            server.listen(16)
        except BaseException:
            server.close()
            raise
        self._server = server
        self._thread = threading.Thread(target=self._accept_loop, name="prismpath-decider", daemon=True)
        self._thread.start()
        return self

    def close(self) -> None:
        self._closed = True
        server, self._server = self._server, None
        if server is not None:
            try:
                server.close()
            except OSError:
                pass
        try:
            self.path.unlink()
        except OSError:
            pass
        if self._thread is not None:
            self._thread.join(timeout=5)

    def _accept_loop(self) -> None:
        server = self._server
        while not self._closed and server is not None:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            if not self._slots.acquire(blocking=False):
                self._finish(conn, commands.deny_answer("the decider is busy; try again"))
                continue
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        try:
            try:
                raw = self._read(conn)
            except Exception as exc:    # noqa: BLE001
                answer = commands.deny_answer(commands._detail(exc))
            else:
                try:
                    with self._decide:
                        answer = self._handler(raw)
                except BaseException as exc:    # noqa: BLE001 - one bad request never stops the decider
                    answer = commands.deny_answer(commands._detail(exc))
            self._finish(conn, answer)
        finally:
            self._slots.release()

    def _read(self, conn: socket.socket) -> bytes:
        deadline = time.monotonic() + self.read_timeout_s
        chunks, size = [], 0
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise commands.AgentError("the hook input did not arrive in time")
            conn.settimeout(left)
            try:
                chunk = conn.recv(65536)
            except socket.timeout:
                raise commands.AgentError("the hook input did not arrive in time") from None
            if not chunk:
                return b"".join(chunks)
            size += len(chunk)
            if size > self.max_input:
                raise commands.AgentError("the hook input is too large")
            chunks.append(chunk)

    def _finish(self, conn: socket.socket, answer: dict) -> None:
        try:
            conn.settimeout(self.read_timeout_s)
            conn.sendall(json.dumps(answer).encode("utf-8") + b"\n")
        except Exception:   # noqa: BLE001 - the client went away; its own timeout denies
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
