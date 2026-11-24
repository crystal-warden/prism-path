# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""An HTTP reverse proxy in front of one service that has the core decide every request before the service sees it.

    prismpath gateway --upstream http://127.0.0.1:9000 --listen 127.0.0.1:8080

Each request is read into the finite reading of reading.py (method, path, body size, content type and query
classes, and the grant), the reading is decided by the core under the policy recorded and attested in the gateway's
home (the layout of `prismpath agent init`: keys, `policy.core.json`, `policy.attestation.json`, `runs/`), and the
decision is appended to the gateway's run as a receipt, durably, before anything else happens to the request.

A home that follows a stream (spec-policy-distribution.md, section 3, the `gateway` target) holds no policy file and
takes no route table from the command line: at every request the gateway reads the release its PEP committed, the
`policy.core`, the `gateway.routes` and the trust store its grants are verified under
(`prismpath.distribution.adapters.gateway.Following`). A revocation, an expiry or a new route table takes effect at
the next request, and a release that no longer stands refuses every request until one does. One run is decided by
one policy, so a release with another policy refuses until the gateway is started again under it.

  allow    the request goes to the upstream as the reading says it is: the target that was read, the
           body that was read, and a short list of headers (Accept, Accept-Language, Content-Type, User-Agent, and
           the names given with --forward-header), plus `X-PrismPath-Run` and `X-PrismPath-Receipt` so the service can
           tie a request to its receipt. Everything else the client sent, the grant header included, is dropped.
  refuse / escalate
           the client gets a 403 whose JSON names the registered cause and the receipt. An escalation has no person
           to ask at an HTTP boundary, so it is answered as a refusal that says it was held.

Fail closed. The proxy forwards nothing it cannot read and nothing whose receipt `append` did not return. A policy
that is missing, not attested, or not the policy of this reading's fields, a run that cannot be opened, a reading
or decision that fails and a receipt that is not durable all answer 403 (cause 131) with no receipt, and say which.
A request the HTTP parser itself refuses (a bad request line or header, an unsupported method) reads as all
`unknown` and is decided like any other. An upstream that fails or answers too much is a 502; the request was
decided and receipted, and the receipt says it was allowed.

Bounds. A request line or header over 64 KiB, more than 100 headers, a body over 1 MiB (never read: class
`oversize`), a client that is silent for `--timeout` seconds or a connection open for longer than `--deadline`
seconds, more than `--max-connections` at once, an upstream that does not answer within `--upstream-timeout`
seconds and an upstream answer over `--max-response` bytes are all cut off. A connection serves one request.

What it does not do. It does not terminate TLS (put it behind one), pass websockets or streaming bodies (the whole
body and the whole answer are held), follow redirects, or check the route table against the service's own routing:
a service that reads a path differently from reading.py's plain path grammar is protected only by the grammar's
refusal of every path it could read two ways.
"""
from __future__ import annotations

import http.client
import json
import socket
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from prismpath.agent.run import Extras
from . import reading as rd

CAUSE_NAME = "gateway:request-refused"
FORWARDED_REQUEST_HEADERS = ("accept", "accept-language", "content-type", "user-agent")
FORWARDED_RESPONSE_HEADERS = ("content-type", "cache-control", "etag", "last-modified", "content-language")
METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE")


def gateway_home(env=None) -> Path:
    from prismpath.agent import commands
    return commands.config_dir(env).with_name("gateway")


class Outcome:
    def __init__(self, kind: str, cause: Optional[str] = None, code: Optional[int] = None,
                 receipt: Optional[int] = None, failure: Optional[str] = None):
        self.kind, self.cause, self.code, self.receipt, self.failure = kind, cause, code, receipt, failure


class Gateway:
    """The decisions and the receipts of one gateway: one policy, one run."""

    def __init__(self, upstream: str, routes: Optional[rd.Routes], home: Path, session: Optional[str] = None,
                 forward_headers: Sequence[str] = (), timeout: float = 10.0, deadline: float = 30.0,
                 upstream_timeout: float = 10.0, max_response: int = 8 * 1024 * 1024, max_connections: int = 64):
        parts = urlsplit(upstream)
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.path not in ("", "/") \
                or parts.query or parts.fragment or parts.username:
            raise ValueError("the upstream is http://HOST[:PORT] or https://HOST[:PORT], with no path")
        self.scheme, self.host = parts.scheme, parts.hostname
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        self.routes, self.home = routes, Path(home)
        self.session = session or f"gateway-{time.strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:8]}"
        self.forward_headers = tuple(dict.fromkeys(FORWARDED_REQUEST_HEADERS + tuple(h.lower() for h in forward_headers)))
        self.timeout, self.deadline, self.upstream_timeout = timeout, deadline, upstream_timeout
        self.max_response, self.max_connections = max_response, max_connections
        self.lock = threading.Lock()
        self.policy = self.run = self.grants = self.follow = None
        self.failure: Optional[str] = None
        from prismpath.distribution.adapters import agent_home
        distributed = agent_home.is_distributed(self.home)
        if distributed and routes is not None:
            raise ValueError("this gateway home follows a stream, so its route table is the committed gateway.routes "
                             "and none is given here")
        if not distributed and routes is None:
            raise ValueError("a gateway home that does not follow a stream is given its route table")
        try:
            from prismpath.agent import commands
            from . import grants
            if distributed:
                from prismpath.distribution.adapters.gateway import Following
                from prismpath.agent.run import RunStore
                self.follow = Following(self.home)
                state = self.follow.current()
                policy, store = state.policy, RunStore(self.home / commands.RUNS_DIR)
                self.routes, self.grants = state.routes, state.grants
            else:
                policy, store = commands.load_checked(self.home)
                self.grants = grants.Verifier(commands._key_paths(self.home, "authority")[1].read_bytes(),
                                              commands._sha256_hex(policy.image), self.home / grants.REVOKED_FILE)
            if sorted(policy.fields) != sorted(rd.FIELDS):
                raise commands.AgentError(f"the recorded policy's fields {policy.fields} are not the gateway reading's "
                                          f"{sorted(rd.FIELDS)}")
            self.policy = policy
            self.run = store.open(self.session, policy.image)
        except Exception as exc:   # noqa: BLE001 - nothing can be decided, so everything is refused
            self.failure = f"the policy could not be loaded or the run opened ({type(exc).__name__}: {exc})"

    # ------------------------------------------------------------------ decide
    def current(self) -> Tuple[Optional[str], Optional[rd.Routes], Any]:
        """(failure, routes, grant verifier) the next request is read and decided under. A home that follows a
        stream reads its committed release again here, so the answer follows a commit, a revocation or an expiry."""
        if self.failure:
            return self.failure, None, None
        if self.follow is None:
            return None, self.routes, self.grants
        from prismpath.agent import commands
        try:
            state = self.follow.current()
        except commands.AgentError as exc:
            return f"the home's release no longer decides ({exc})", None, None
        if state.policy.image != self.policy.image:
            return ("the home committed another policy since this run began, and one run is decided by one policy",
                    None, None)
        return None, state.routes, state.grants

    def decide(self, reading: Dict[str, Any], grant: Optional[Dict[str, str]] = None,
               routes: Optional[rd.Routes] = None) -> Outcome:
        """The decision and receipt of `reading`, read under `routes` (by default the routes `current` answers)."""
        if self.failure:
            return Outcome("refuse", failure=self.failure)
        if routes is None:
            failure, routes, _grants = self.current()
            if failure:
                return Outcome("refuse", failure=failure)
        if self.follow is not None:
            from prismpath.distribution.adapters import agent_home
            agent_home.note(self.home, reading)                  # for the PEP's heartbeat (H5)
        try:
            raw = self.policy.reading_bytes(reading)
            decision = self.policy.decide(raw)
        except Exception as exc:   # noqa: BLE001
            return Outcome("refuse", failure=f"the request could not be decided ({type(exc).__name__}: {exc})")
        try:
            with self.lock:
                index = self.run.append(raw, decision.verdict, extras=Extras(grant=grant, routes_sha256=routes.digest()))
        except Exception as exc:   # noqa: BLE001 - never forward a request whose receipt is not durable
            return Outcome("refuse", failure=f"its receipt could not be written ({type(exc).__name__}: {exc})")
        return Outcome(decision.kind, decision.cause, decision.cause_code, index)

    def refusal(self, outcome: Outcome) -> Tuple[int, Dict[str, Any]]:
        from prismpath.kernel import causes
        if outcome.failure:
            return 403, {"refused": True, "decision": "refuse", "cause": CAUSE_NAME, "code": causes.code(CAUSE_NAME),
                         "receipt": None, "run": self.session,
                         "detail": f"PrismPath refused this request because {outcome.failure}. It was not sent to the "
                                   f"service. No receipt was written."}
        held = outcome.kind == "escalate"
        return 403, {"refused": True, "decision": outcome.kind, "cause": outcome.cause, "code": outcome.code,
                     "receipt": outcome.receipt, "run": self.session,
                     "detail": ("PrismPath holds this request for a person's approval, which an HTTP boundary cannot ask "
                                "for, so it was not sent to the service." if held else
                                "PrismPath refused this request. It was not sent to the service.")}

    # ----------------------------------------------------------------- forward
    def forward(self, method: str, target: str, headers: Dict[str, List[str]], body: bytes, receipt: int):
        """(status, reason, headers, body) of the upstream's answer. Raises on any failure or an answer too large."""
        out = {name: headers[name][0] for name in self.forward_headers if len(headers.get(name, ())) == 1}
        out["Host"] = f"{self.host}:{self.port}"
        out["Content-Length"] = str(len(body))
        out["Connection"] = "close"
        out["X-PrismPath-Run"], out["X-PrismPath-Receipt"] = self.session, str(receipt)
        cls = http.client.HTTPSConnection if self.scheme == "https" else http.client.HTTPConnection
        conn = cls(self.host, self.port, timeout=self.upstream_timeout)
        try:
            conn.request(method, target, body=body, headers=out)
            resp = conn.getresponse()
            data = resp.read(self.max_response + 1)
            if len(data) > self.max_response:
                raise ValueError(f"the upstream answered more than {self.max_response} bytes")
            kept = [(k, v) for k, v in resp.getheaders() if k.lower() in FORWARDED_RESPONSE_HEADERS]
            if method == "HEAD" and resp.getheader("Content-Length") is not None:
                kept.append(("Content-Length", resp.getheader("Content-Length")))
            return resp.status, resp.reason, kept, data
        finally:
            conn.close()

    def seal(self) -> None:
        if self.run is not None:
            try:
                self.run.seal(self.home)
            except Exception:   # noqa: BLE001 - the receipts are durable; verify seals them later
                pass


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64
    allow_reuse_address = True

    def __init__(self, address, handler, gateway: Gateway):
        super().__init__(address, handler)
        self.gateway = gateway
        self._slots = threading.BoundedSemaphore(gateway.max_connections)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            try:
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "PrismPathGateway"
    sys_version = ""

    def setup(self):
        self.timeout = self.server.gateway.timeout
        super().setup()
        self._answered = False
        self._in_request = False
        self.request_version, self.requestline, self.command = "HTTP/1.0", "", None   # until the request line is parsed
        self.close_connection = True
        self._timer = threading.Timer(self.server.gateway.deadline, self._cut)
        self._timer.daemon = True
        self._timer.start()

    def finish(self):
        self._timer.cancel()
        super().finish()

    def _cut(self) -> None:
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def log_message(self, *args) -> None:
        pass

    def parse_request(self) -> bool:
        """The stdlib parser also takes a request line cut short by the end of the stream and an HTTP/0.9 one
        (`GET /path`); neither is a whole request, so neither is read."""
        if not self.raw_requestline.endswith(b"\n"):
            self.send_error(400, "the request line was not finished")
            return False
        if not super().parse_request():
            return False
        if self.request_version not in ("HTTP/1.0", "HTTP/1.1"):
            self.send_error(400, "not an HTTP/1.x request")
            return False
        return True

    # --------------------------------------------------------------- answers
    def _send(self, status: int, headers: Sequence[Tuple[str, str]], body: bytes, head: bool = False) -> None:
        if self._answered:
            return
        self._answered = True
        if self.request_version == "HTTP/0.9":      # an answer to a refused simple request still has a status line
            self.request_version = "HTTP/1.0"
        try:
            self.send_response(status)
            for key, value in headers:
                self.send_header(key, value)
            if not any(k.lower() == "content-length" for k, _ in headers):
                self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if not head:
                self.wfile.write(body)
        except OSError:
            pass
        self.close_connection = True

    def _json(self, status: int, doc: Dict[str, Any], head: bool = False) -> None:
        body = json.dumps(doc, separators=(",", ":")).encode("utf-8")
        headers = [("Content-Type", "application/json"), ("X-PrismPath-Run", str(doc.get("run"))),
                   ("X-PrismPath-Cause", str(doc.get("code")))]
        if doc.get("receipt") is not None:
            headers.append(("X-PrismPath-Receipt", str(doc["receipt"])))
        self._send(status, headers, body, head)

    def send_error(self, code, message=None, explain=None):
        """The parser refused the request before a handler ran: it cannot be read, so it reads `unknown`."""
        if self._in_request or self._answered:
            return
        gateway = self.server.gateway
        status, doc = gateway.refusal(gateway.decide(dict(rd.UNREADABLE)))
        self._json(status, doc)

    # -------------------------------------------------------------- the request
    def _headers(self) -> Dict[str, List[str]]:
        out: Dict[str, List[str]] = {}
        for key, value in self.headers.items():
            out.setdefault(key.lower(), []).append(value)
        return out

    def _body(self, length: int) -> Optional[bytes]:
        deadline = time.monotonic() + self.server.gateway.timeout
        chunks, left = [], length
        try:
            while left:
                if time.monotonic() > deadline:
                    return None
                chunk = self.rfile.read(min(left, 65536))
                if not chunk:
                    return None
                chunks.append(chunk)
                left -= len(chunk)
        except OSError:
            return None
        return b"".join(chunks)

    def _serve(self) -> None:
        self._in_request = True
        gateway = self.server.gateway
        head = self.command == "HEAD"
        headers = self._headers()
        length = rd.declared_length(headers.get("content-length", ()), headers.get("transfer-encoding", ()))
        body = b""
        held = length
        if length is not None and 0 < length <= rd.MAX_BODY:
            taken = self._body(length)
            if taken is None:
                held = None
            else:
                body = taken
        failure, routes, verifier = gateway.current()
        if failure:
            status, doc = gateway.refusal(Outcome("refuse", failure=failure))
            self._json(status, doc, head)
            return
        try:
            reading, grant = rd.read(self.command, self.path, headers, routes, held, verifier)
        except Exception:   # noqa: BLE001 - a request that cannot be read is unknown, never forwarded
            reading, grant = dict(rd.UNREADABLE), None
        outcome = gateway.decide(reading, grant, routes)
        if outcome.kind == "allow" and (held is None or length is None or length > rd.MAX_BODY):
            outcome = Outcome("refuse", failure="its body could not be taken whole")     # belt and braces: the policy refused these
        if outcome.kind != "allow":
            status, doc = gateway.refusal(outcome)
            self._json(status, doc, head)
            return
        try:
            status, reason, kept, data = gateway.forward(self.command, self.path, headers, body, outcome.receipt)
        except Exception as exc:   # noqa: BLE001
            self._json(502, {"refused": False, "decision": "allow", "cause": None, "code": None,
                             "receipt": outcome.receipt, "run": gateway.session,
                             "detail": f"PrismPath allowed this request (receipt {outcome.receipt}) but the service did "
                                       f"not answer it ({type(exc).__name__})."}, head)
            return
        kept.append(("X-PrismPath-Receipt", str(outcome.receipt)))
        kept.append(("X-PrismPath-Run", gateway.session))
        self._send(status, kept, data, head)

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_TRACE = _serve


def make_server(gateway: Gateway, host: str, port: int) -> _Server:
    return _Server((host, port), _Handler, gateway)
