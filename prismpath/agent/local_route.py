# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A fixed route from the agent sandbox to one local model server (agent-sandbox spike, `--local-model`).

    prismpath agent run --local-model http://localhost:8888 -- PROGRAM

The egress proxy refuses loopback and private addresses by design, so a model served on this host cannot go
through it. This is a separate, explicit route and not an exception in that rule. The launcher binds a unix
socket in the staged directory. Each connection to it is forwarded, as bytes, to exactly one host and port
named when the route was built, and to nothing else: the sandbox cannot choose the destination. Inside, a
`socat` relay listens on 127.0.0.1:<that port> and connects to the socket, so a client uses
`http://127.0.0.1:<port>` as if the server were local. Every connection is appended to the egress log as one
JSON line with `route: "local-model"`, so the run's log shows what used it. Standard library only."""
import json
import os
import select
import socket
import threading
import time
from urllib.parse import urlsplit

SOCKET_IN = "/tmp/.pp-model.sock"
MAX_CONNECTIONS = 16
IDLE_TIMEOUT = 600.0
CONNECT_TIMEOUT = 10.0


class RouteError(ValueError):
    """The route's target is not a plain http host and port."""


def parse_target(text):
    """(host, port) of an `http://HOST:PORT` target. Anything else (another scheme, a path, userinfo, no port) is refused."""
    parts = urlsplit(text if "//" in text else "//" + text)
    if parts.scheme not in ("", "http") or parts.username or parts.password or parts.path not in ("", "/") \
            or parts.query or parts.fragment:
        raise RouteError(f"the local model target {text!r} must be http://HOST:PORT")
    try:
        port = parts.port
    except ValueError:
        port = None
    if not parts.hostname or not port or port < 1 or port > 65535:
        raise RouteError(f"the local model target {text!r} needs a host and a port")
    return parts.hostname, port


class LocalModelRoute:
    def __init__(self, socket_path, log_path, host, port, max_connections=MAX_CONNECTIONS, idle_timeout=IDLE_TIMEOUT):
        self.socket_path, self.log_path = str(socket_path), str(log_path)
        self.host, self.port = host, port
        self.idle_timeout = idle_timeout
        self._slots = threading.BoundedSemaphore(max_connections)
        self._log_lock = threading.Lock()
        self._listener = None
        self._thread = None
        self._closing = threading.Event()

    def start(self):
        if os.path.lexists(self.socket_path):
            os.unlink(self.socket_path)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o177)
        try:
            listener.bind(self.socket_path)
        finally:
            os.umask(old)
        listener.listen(32)
        listener.settimeout(0.2)
        self._listener = listener
        self._thread = threading.Thread(target=self._accept, name="local-model-accept", daemon=True)
        self._thread.start()
        return self

    def close(self):
        self._closing.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        try:
            os.unlink(self.socket_path)
        except FileNotFoundError:
            pass

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.close()

    def _accept(self):
        while not self._closing.is_set():
            try:
                client, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            if not self._slots.acquire(blocking=False):
                self._log("refuse", "too-many-connections")
                client.close()
                continue
            threading.Thread(target=self._serve, args=(client,), daemon=True).start()

    def _serve(self, client):
        upstream = None
        try:
            try:
                upstream = socket.create_connection((self.host, self.port), timeout=CONNECT_TIMEOUT)
            except OSError:
                self._log("error", "connect-failed")
                return
            self._log("allow", "local-model-route")
            pair = {client: upstream, upstream: client}
            while True:
                ready, _, _ = select.select(list(pair), [], [], self.idle_timeout)
                if not ready:
                    return
                for sock in ready:
                    data = sock.recv(65536)
                    if not data:
                        return
                    pair[sock].sendall(data)
        except OSError:
            pass
        finally:
            for sock in (upstream, client):
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
            self._slots.release()

    def _log(self, decision, reason):
        line = json.dumps({"time": round(time.time(), 3), "route": "local-model", "host": self.host[:253],
                           "port": self.port, "decision": decision, "reason": reason}, ensure_ascii=True)
        with self._log_lock:
            with open(self.log_path, "a", encoding="ascii") as handle:
                handle.write(line + "\n")
