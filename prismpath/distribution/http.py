# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The HTTP binding of policy distribution, both sides (spec-policy-distribution.md, section 8.2).

A host PEP pulls (B3). It opens every connection itself, and the controller only listens:

    GET  /dist/v1/offers/<pep id>   the offers answer, JSON, with an ETag. `If-None-Match` with the last
                                    ETag answers 304 when nothing changed, and `?wait=<seconds>` holds the
                                    request open until something does or the wait ends (a long poll)
    GET  /dist/v1/blob/<sha256>     a sealed envelope by its envelope id, or a body by its SHA-256
    POST /dist/v1/state             one state record, answered 204
    GET  /dist/v1/fleet             the fleet view (F4), JSON

`PullClient` is the PEP's side and runs over a transport, `HttpTransport` here or the controller in process
for a test. It never reads more than it was promised (B9): an offers answer up to 64 kilobytes, a sealed
envelope up to 2,440 bytes, and a body up to the signed `body_size`, fetched only after the sealed envelope
verified through V8. A blob whose bytes are not the ones asked for is refused with `dist:body-mismatch` (B4).
The offers answer is a hint and is not signed (B5), so a wrong one costs a fetch and a refusal.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional, Tuple

from prismpath import canon
from prismpath.distribution import envelope as env
from prismpath.distribution import kinds, state_record
from prismpath.distribution.kinds import Refused
from prismpath.distribution.verify import verify_envelope

PREFIX = "/dist/v1"
MAX_OFFERS = 64 * 1024                             # B9
MAX_RECORD = 144 + 4 + state_record.MAX_BODY + state_record.MAX_EXTENSIONS + state_record.SIGNATURE_SIZE
MAX_WAIT = 30.0                                    # a long poll waits at most one interval
BODY_MISMATCH = "dist:body-mismatch"
RETRY = kinds.RETRYABLE


class FetchFailed(Exception):
    """A request that did not answer: a missing blob, a refused connection, a status other than the one
    expected. Nothing changes on the PEP (B5)."""


class TooLarge(Exception):
    """An answer longer than its bound. Nothing past the bound was read (B9)."""


def read_bounded(response, bound: int) -> bytes:
    """B9: the answer's body when its declared length is within `bound`, reading exactly that many bytes and
    no more. An answer with no declared length, or a longer one, is `TooLarge` with nothing read."""
    length = response.getheader("Content-Length")
    if length is None or not length.isdigit() or int(length) > bound:
        raise TooLarge(f"an answer of {length} bytes where {bound} were promised")
    data = response.read(int(length))
    if len(data) != int(length):
        raise FetchFailed("the answer ended early")
    return data


# ------------------------------------------------------------------ the PEP's side

class HttpTransport:
    """The PEP's connection to a controller at `base` (http://host:port). Each call opens its own connection."""

    def __init__(self, base: str, timeout: float = 10.0):
        parts = urllib.parse.urlsplit(base)
        if parts.scheme != "http" or not parts.hostname:
            raise ValueError(f"{base!r} is not an http://host:port address")
        self.host, self.port, self.timeout = parts.hostname, parts.port or 80, timeout
        self.etag: Optional[str] = None
        self.reads = 0                              # bytes read from answers, for the bound of B9
        self.blob_reads = 0                         # of which from blobs

    def _get(self, path: str, bound: int, headers: Optional[dict] = None, timeout: Optional[float] = None):
        connection = http.client.HTTPConnection(self.host, self.port, timeout=timeout or self.timeout)
        try:
            connection.request("GET", path, headers=headers or {})
            response = connection.getresponse()
            if response.status == 304:
                return response.status, None, response.getheader("ETag")
            if response.status != 200:
                raise FetchFailed(f"{path} answered {response.status}")
            data = read_bounded(response, bound)
            self.reads += len(data)
            return response.status, data, response.getheader("ETag")
        except OSError as error:
            raise FetchFailed(f"{path}: {error}") from None
        finally:
            connection.close()

    def offers(self, pep: str, wait: float = 0.0) -> Optional[dict]:
        """The offers answer, or None when it has not changed since the last one (304)."""
        headers = {"If-None-Match": self.etag} if self.etag else {}
        path = f"{PREFIX}/offers/{pep}" + (f"?wait={wait:g}" if wait else "")
        status, data, etag = self._get(path, MAX_OFFERS, headers, timeout=self.timeout + wait)
        if status == 304:
            return None
        try:
            answer = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise FetchFailed("the offers answer is not JSON") from None
        self.etag = etag
        return answer

    def blob(self, name: str, bound: int) -> bytes:
        data = self._get(f"{PREFIX}/blob/{name}", bound)[1]
        self.blob_reads += len(data)
        return data

    def post(self, record: bytes) -> None:
        connection = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            connection.request("POST", f"{PREFIX}/state", body=bytes(record),
                               headers={"Content-Type": "application/octet-stream"})
            response = connection.getresponse()
            response.read(0)
            if response.status != 204:
                raise FetchFailed(f"the state record was answered {response.status}")
        except OSError as error:
            raise FetchFailed(f"state: {error}") from None
        finally:
            connection.close()


class LocalTransport:
    """The controller in the same process, for tests and for a controller that is also its own PEP's host."""

    def __init__(self, controller):
        self.controller = controller

    def offers(self, pep: str, wait: float = 0.0) -> Optional[dict]:
        return self.controller.answer(pep)

    def blob(self, name: str, bound: int) -> bytes:
        data = self.controller.blob(name)
        if data is None:
            raise FetchFailed(f"no blob {name}")
        if len(data) > bound:
            raise TooLarge(f"a blob of {len(data)} bytes where {bound} were promised")
        return data

    def post(self, record: bytes) -> None:
        self.controller.receive(record)


class PullClient:
    """A host PEP's side of the binding: one `poll` reads the offers answer, stages what it is offered in the
    order given, commits and aborts as told, and sends every state record the PEP made (H4). The PEP id in
    the path is the hex of the first 16 bytes of SHA-256 of the instance public key (H1)."""

    def __init__(self, pep, transport):
        self.pep, self.transport = pep, transport
        self.id = state_record.pep_id(pep.instance_key.public_raw).hex()
        self.done: set = set()                       # envelope ids already staged or refused by this client
        self.failures: list = []

    def poll(self, wait: float = 0.0) -> Optional[dict]:
        """One round. Returns the answer it acted on, or None when the controller had nothing new."""
        try:
            answer = self.transport.offers(self.id, wait)
        except TooLarge as error:
            self.failures.append(("offers", str(error)))      # B9: dropped, and nothing read past the bound
            answer = None
        except FetchFailed as error:
            self.failures.append(("offers", str(error)))
            answer = None
        if isinstance(answer, dict):
            self._act(answer)
        self.pep.tick()
        if not self.pep.outbox:
            self.pep.record("beat")                   # H4: every poll reports, so the controller sees each answer
        self.send()
        return answer if isinstance(answer, dict) else None

    def beat(self) -> None:
        """H4: the heartbeat, at least every 30 seconds on a host."""
        self.pep.record("beat")
        self.send()

    def send(self) -> None:
        """Send every record the PEP made since the last send, oldest first. A record made before the PEP saw any
        epoch (H9) carries 0, which no controller accepts, so it is kept in the PEP's audit log and not sent."""
        for record in self.pep.drain():
            if struct_epoch(record) == 0:
                continue
            try:
                self.transport.post(record)
            except FetchFailed as error:
                self.failures.append(("state", str(error)))

    def _act(self, answer: dict) -> None:
        epoch = answer.get("epoch")
        if kinds.is_int(epoch, 0, 2 ** 64 - 1):
            self.pep.see_epoch(epoch)
        for offer in _list(answer.get("offers")):
            if isinstance(offer, dict) and kinds.is_hex64(offer.get("envelope_id")):
                self._stage(offer["envelope_id"])
        for entry in _list(answer.get("commit")):
            named = _names(entry)
            if named and self.pep.staged is not None and self.pep.staged.names(*named):
                delay = entry.get("delay", 0)
                self.pep.commit(*named, delay_ms=delay if kinds.is_int(delay, 0, 65535) else 0)
        for entry in _list(answer.get("abort")):
            named = _names(entry)
            if named and self.pep.staged is not None and self.pep.staged.names(*named):
                self.pep.abort(*named)

    def _stage(self, envelope_id: str) -> None:
        """Fetch and stage one offered envelope: the sealed envelope by its id, checked to hold that envelope
        (B4), then through V8 (B9), then its body, unless the PEP already holds it (X5)."""
        pep = self.pep
        held = (pep.staged.envelope_ids if pep.staged else frozenset()) | (
            pep.active.envelope_ids if pep.active else frozenset())
        if envelope_id in self.done or envelope_id in held:
            return
        try:
            sealed = self.transport.blob(envelope_id, env.MAX_SEALED)
        except (FetchFailed, TooLarge) as error:
            self.failures.append((envelope_id, str(error)))
            if isinstance(error, TooLarge):
                self.done.add(envelope_id)
                pep.refuse_fetched("dist:too-large", envelope_id)
            return
        self.done.add(envelope_id)
        try:
            contained = env.envelope_id(env.unseal(sealed)[0])
        except Refused:
            pep.stage(sealed, b"")                  # a container that does not read: the verifier's V2 cause
            return
        if contained != envelope_id:
            pep.refuse_fetched(BODY_MISMATCH, envelope_id)                # B4
            return
        verdict = verify_envelope(sealed, trust=pep.trust, pep=pep.view(), now=int(pep.clock()))
        if not verdict.ok or verdict.unchanged:
            self._staged(envelope_id, pep.stage(sealed, b""))   # the verifier refuses it, or answers unchanged, before V9
            return
        envelope = verdict.envelope
        body = pep.blob(envelope.body_sha256)
        if body is None:
            try:
                body = self.transport.blob(envelope.body_sha256, envelope.body_size)
            except TooLarge as error:
                self.failures.append((envelope.body_sha256, str(error)))
                pep.refuse_fetched("dist:too-large", envelope.body_sha256)
                return
            except FetchFailed as error:
                self.failures.append((envelope.body_sha256, str(error)))
                self.done.discard(envelope_id)
                return
            if canon.sha256_hex(body) != envelope.body_sha256:
                pep.refuse_fetched(BODY_MISMATCH, envelope.body_sha256)  # B4
                return
        self._staged(envelope_id, pep.stage(sealed, body))

    def _staged(self, envelope_id: str, signed: bytes) -> None:
        """An envelope refused for a reason that time or the trust chain may remove is tried again on a later
        poll. Every other envelope tried stays done."""
        cause = state_record.read(signed, self.pep.instance_key.public_raw).cause
        if cause in RETRY:
            self.done.discard(envelope_id)


def struct_epoch(record: bytes) -> int:
    """The epoch field of a signed state record (H1 bytes 40 to 47)."""
    return int.from_bytes(bytes(record)[40:48], "little")


def _list(value) -> list:
    return value if isinstance(value, list) else []


def _names(entry) -> Optional[Tuple[str, int, str]]:
    if not isinstance(entry, dict):
        return None
    stream, seq, policy = entry.get("stream"), entry.get("seq"), entry.get("policy")
    if kinds.is_stream(stream) and kinds.is_int(seq, 0, kinds.MAX_SEQ) and kinds.is_hex64(policy):
        return stream, seq, policy
    return None


# ------------------------------------------------------------------ the controller's side

class ControllerServer(ThreadingHTTPServer):
    """The controller's listener. It never opens a connection (B3). Each request holds the controller's lock,
    so a command run beside it (`prismpath dist offer`) is seen by the next request."""

    daemon_threads = True

    def __init__(self, address, controller):
        super().__init__(address, _Handler)
        self.controller = controller
        self.changed = threading.Condition()

    def notify(self) -> None:
        with self.changed:
            self.changed.notify_all()


class _Handler(BaseHTTPRequestHandler):
    server: ControllerServer
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args) -> None:
        return

    def _send(self, status: int, data: bytes = b"", content_type: str = "application/octet-stream",
              etag: Optional[str] = None) -> None:
        self.send_response(status)
        if status != 204 and status != 304:
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
        if etag:
            self.send_header("ETag", etag)
        self.send_header("Connection", "close")
        self.end_headers()
        if data and status not in (204, 304):
            self.wfile.write(data)

    def _answer(self, pep: str) -> Tuple[bytes, str]:
        with self.server.controller.locked() as controller:
            data = json.dumps(controller.answer(pep), sort_keys=True).encode("utf-8")
        return data, '"' + hashlib.sha256(data).hexdigest()[:32] + '"'

    def do_GET(self) -> None:
        parts = urllib.parse.urlsplit(self.path)
        path = parts.path
        if path.startswith(f"{PREFIX}/offers/"):
            pep = path[len(f"{PREFIX}/offers/"):]
            if len(pep) != 32 or any(char not in "0123456789abcdef" for char in pep):
                return self._send(404)
            query = urllib.parse.parse_qs(parts.query)
            try:
                wait = min(max(float(query.get("wait", ["0"])[0]), 0.0), MAX_WAIT)
            except ValueError:
                wait = 0.0
            data, etag = self._answer(pep)
            asked = self.headers.get("If-None-Match")
            if asked == etag and wait:
                with self.server.changed:
                    self.server.changed.wait(wait)
                data, etag = self._answer(pep)
            if asked == etag:
                return self._send(304, etag=etag)
            return self._send(200, data, "application/json", etag)
        if path.startswith(f"{PREFIX}/blob/"):
            with self.server.controller.locked() as controller:
                data = controller.blob(path[len(f"{PREFIX}/blob/"):])
            return self._send(404) if data is None else self._send(200, data)
        if path == f"{PREFIX}/fleet":
            with self.server.controller.locked() as controller:
                data = json.dumps(controller.fleet(), sort_keys=True).encode("utf-8")
            return self._send(200, data, "application/json")
        return self._send(404)

    def do_POST(self) -> None:
        if urllib.parse.urlsplit(self.path).path != f"{PREFIX}/state":
            return self._send(404)
        length = self.headers.get("Content-Length")
        if length is None or not length.isdigit() or int(length) > MAX_RECORD:
            return self._send(413)
        record = self.rfile.read(int(length))
        with self.server.controller.locked() as controller:
            controller.receive(record)
        self.server.notify()
        return self._send(204)


def serve(controller, address: Tuple[str, int]) -> ControllerServer:
    """A listener for `controller` on `address`, not yet serving. Call `serve_forever`, or run it on a thread."""
    return ControllerServer(address, controller)
