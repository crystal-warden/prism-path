# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The console's client of the collector's feed: one background thread, a bounded copy for the screens.

Nothing connects unless the launch names a collector (`MC_COLLECTOR`), and the read only posture never
does, since it writes the kept evidence. The endpoint is a Unix socket path (`/run/prismpath-collector/
feed.sock`, or `unix:PATH`) or `tcp:127.0.0.1:PORT` / `tcp:[::1]:PORT` for a collector started with
`--tcp`. A TCP endpoint must be a literal loopback address, and the peer the socket reaches is checked
again after connecting; the console never connects anywhere else, and it binds nothing. A remote
enforcer's feed is reached as the collector's README says, by forwarding its Unix socket over SSH.

The thread connects, sends the subscription line (after the first connection to a session, the resume that
asks the collector to prove its join seal from the last seal the console verified), and reads lines with a bound on each (the `hello`'s
`max_record`, never above `feed.HARD_MAX_RECORD`), checking each one through `feed.SessionCheck` and
keeping it through `feed.FeedStore`. The end of the stream, a read that waits too long, an oversized line
or a refused subscription closes the connection, and it reconnects with exponential backoff. A new
`session` in `hello` starts a new check and a new kept session. The kept store is held to its bounds
(`MC_COLLECTOR_KEEP_BYTES`, `MC_COLLECTOR_KEEP_DAYS`) by `feed.retain` whenever a segment closes and at most
once a minute besides, never touching the segment being written. Request handlers only ever take the
state lock for a copy (`snapshot`, `live`, `series`), so a slow or silent collector never holds a request.
"""
from __future__ import annotations

import collections
import ipaddress
import logging
import os
import socket
import threading
import time
from typing import Any, Deque, Dict, Optional, Tuple

from . import causes_view, feed
from .files import is_contained

LOG = logging.getLogger(__name__)
RECENT = 200                 # leaf records the live view holds
SERIES_RECORDS = 50_000      # leaf records the live cause series holds (arrival second, cause, action)
MAX_BUCKETS = 10_000
CONNECT_TIMEOUT_S = 5.0
BACKOFF_START_S = 0.5
BACKOFF_MAX_S = 30.0
READ_CHUNK = 65536
STORE_DIR_NAME = "collector-feed"
RETAIN_EVERY_S = 60.0         # the age bound is also applied this often while a segment stays open


class EndpointRefused(ValueError):
    pass


def parse_endpoint(text: str) -> Optional[Tuple[str, Any]]:
    """None for an empty setting (off), ("unix", path) or ("tcp", (host, port)) for loopback only.
    Raises EndpointRefused for anything else."""
    text = (text or "").strip()
    if not text:
        return None
    if text.startswith("unix:"):
        text = text[len("unix:"):]
    elif text.startswith("tcp:"):
        rest = text[len("tcp:"):]
        if rest.startswith("["):
            host, _, port = rest[1:].partition("]:")
        else:
            host, _, port = rest.rpartition(":")
        try:
            address = ipaddress.ip_address(host)
            number = int(port)
        except ValueError:
            raise EndpointRefused("a TCP collector endpoint is tcp:<loopback address>:<port>, "
                                  "an address literal, not a name") from None
        if not address.is_loopback:
            raise EndpointRefused("refused: the console connects to a collector on loopback only")
        if not 0 < number < 65536:
            raise EndpointRefused("a TCP port is from 1 to 65535")
        return ("tcp", (str(address), number))
    if not os.path.isabs(text):
        raise EndpointRefused("a collector socket is an absolute path, unix:PATH or tcp:127.0.0.1:PORT")
    return ("unix", text)


def describe(endpoint: Optional[Tuple[str, Any]]) -> str:
    if endpoint is None:
        return ""
    kind, where = endpoint
    if kind == "unix":
        return where
    host, port = where
    return f"tcp:[{host}]:{port}" if ":" in host else f"tcp:{host}:{port}"


def store_dir_for(settings) -> Tuple[Optional[str], str]:
    """(the directory sessions are kept in, or None, and why). It must lie under an evidence root."""
    roots = [os.path.realpath(root) for root in settings.evidence_roots]
    chosen = settings.collector_store or (os.path.join(roots[0], STORE_DIR_NAME) if roots else "")
    if not chosen:
        return None, "no evidence root is named (MC_EVIDENCE), so the feed is shown and not kept"
    chosen = os.path.abspath(os.path.expanduser(chosen))
    if not any(is_contained(chosen, root) for root in roots):
        return None, "the store (MC_COLLECTOR_STORE) is not under an evidence root, so the feed is not kept"
    return chosen, "kept under " + chosen


def _bucket_key(rendered: Dict[str, Any]) -> str:
    return str(rendered["code"]) if rendered["code"] is not None else rendered["label"]


class FeedClient:
    """The feed client and the console's live copy. `start` runs the thread; `stop` ends it."""

    def __init__(self, endpoint: Optional[Tuple[str, Any]], store_dir: Optional[str] = None, store_note: str = "",
                 rotate_bytes: int = 32 * 1024 * 1024, read_timeout_s: float = 30.0,
                 backoff_max_s: float = BACKOFF_MAX_S, keep_bytes: int = 1 << 30, keep_age_s: float = 30 * 86400.0):
        self.endpoint = endpoint
        self.store_dir = store_dir
        self.store_note = store_note
        self.rotate_bytes = rotate_bytes
        self.read_timeout_s = read_timeout_s
        self.backoff_max_s = backoff_max_s
        self.keep_bytes = keep_bytes
        self.keep_age_s = keep_age_s
        self.removed_total = 0
        self.removed_last: list = []                      # the latest removals, newest last, bounded
        self.retain_error: Optional[str] = None
        self._retained_at = 0.0
        self.lock = threading.Lock()
        self.changed = threading.Condition(self.lock)
        self.version = 0                                  # bumped on every change a screen shows
        self.connection = "off" if endpoint is None else "idle"
        self.last_error: Optional[str] = None
        self.connects = 0
        self.connected_since: Optional[float] = None
        self.check: Optional[feed.SessionCheck] = None
        self.previous: Optional[Dict[str, Any]] = None    # the last session's summary, when a new one began
        self.recent: Deque[Dict[str, Any]] = collections.deque(maxlen=RECENT)
        self.arrivals: Deque[Tuple[int, Optional[str], str]] = collections.deque(maxlen=SERIES_RECORDS)
        self.decoded: Dict[str, Dict[str, Any]] = {}
        self.kept: Optional[str] = None                   # the kept session's directory
        self.store_error: Optional[str] = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None
        self._store: Optional[feed.FeedStore] = None
        self._hello_line: Optional[bytes] = None

    # ------------------------------------------------------------ lifecycle
    @classmethod
    def from_settings(cls, settings, read_only: bool) -> Optional["FeedClient"]:
        """The client the launch configures, or None: no collector named, or the read only posture."""
        if read_only or not settings.collector:
            return None
        endpoint = parse_endpoint(settings.collector)
        store_dir, note = store_dir_for(settings)
        return cls(endpoint, store_dir, note, rotate_bytes=max(1 << 20, settings.max_evidence_bytes // 2),
                   keep_bytes=max(0, int(settings.collector_keep_bytes)),
                   keep_age_s=max(0.0, float(settings.collector_keep_days)) * 86400)

    def start(self) -> None:
        if self.endpoint is None or self._thread is not None:
            return
        self._retain()
        self._thread = threading.Thread(target=self._run, name="prismpath-feed", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        sock = self._sock
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout)
        self._close_store("console-stopped")

    def _bump(self) -> None:
        self.version += 1
        self.changed.notify_all()

    def _set(self, connection: str, error: Optional[str] = None) -> None:
        with self.lock:
            self.connection = connection
            if error is not None:
                self.last_error = error
            self._bump()

    # ------------------------------------------------------------ the thread
    def _run(self) -> None:
        backoff = BACKOFF_START_S
        while not self._stop.is_set():
            self._set("connecting")
            ended = None
            try:
                ended = self._session_once()
            except OSError as error:
                self._set("waiting", f"{type(error).__name__}: {error.strerror or error}")
            except Exception as error:                     # a bug must not end the thread quietly
                LOG.exception("the feed client failed")
                self._set("waiting", f"{type(error).__name__}")
            else:
                self._set("waiting")
            self._close_store(None)
            if ended in ("eof", "silent"):
                # A connection that ended as connections do starts the backoff over; one the console
                # closed for an oversized line or a refusal keeps backing off.
                backoff = BACKOFF_START_S
            if self._stop.wait(backoff):
                break
            backoff = min(backoff * 2, self.backoff_max_s)
        self._set("stopped")

    def _connect(self) -> socket.socket:
        kind, where = self.endpoint
        if kind == "unix":
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        else:
            family = socket.AF_INET6 if ":" in where[0] else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT_S)
        try:
            sock.connect(where)
            if kind == "tcp" and not ipaddress.ip_address(sock.getpeername()[0]).is_loopback:
                raise ConnectionRefusedError("the collector's peer is not a loopback address")
        except BaseException:
            sock.close()
            raise
        sock.settimeout(self.read_timeout_s)
        return sock

    def _session_once(self) -> Optional[str]:
        """One connection: subscribe, then read and check lines until it ends. Returns how it ended."""
        sock = self._connect()
        self._sock = sock
        try:
            with self.lock:
                resume = self.check.resume_point() if self.check is not None else None
            sock.sendall(feed.subscription_line(resume))
            with self.lock:
                self.connects += 1
                self.connection = "connected"
                self.connected_since = time.time()
                self._bump()
            buffer = bytearray()
            first = True
            bound = feed.DEFAULT_MAX_RECORD
            while not self._stop.is_set():
                newline = buffer.find(b"\n")
                if newline < 0:
                    if len(buffer) >= bound:
                        self._oversized(len(buffer))
                        return "oversized"
                    try:
                        chunk = sock.recv(min(READ_CHUNK, bound + 1 - len(buffer)))
                    except socket.timeout:
                        self._ended("silent", f"no record for {self.read_timeout_s:g} s")
                        return "silent"
                    if not chunk:
                        self._ended("eof", "the collector ended the stream")
                        return "eof"
                    buffer.extend(chunk)
                    continue
                raw = bytes(buffer[:newline])
                del buffer[:newline + 1]
                if newline + 1 > bound:
                    self._oversized(newline + 1)
                    return "oversized"
                if first:
                    first = False
                    record = feed.parse_line(raw)
                    if record is None or record.get("kind") != "hello":
                        reason = record.get("reason") if record and record.get("kind") == "refused" else None
                        self._ended("refused", f"the collector refused the subscription: {reason}" if reason
                                    else "the collector's first record is not a hello")
                        return "refused"
                    self._begin(raw, record)
                    bound = self.check.max_record
                    continue
                self._take(raw)
        finally:
            self._sock = None
            sock.close()
        self._ended("console-stopped", None)
        return "console-stopped"

    # ------------------------------------------------------------ lines
    def _begin(self, raw: bytes, hello: Dict[str, Any]) -> None:
        session = hello.get("session")
        with self.lock:
            new_session = self.check is None or self.check.session != session
        self._hello_line = raw
        self._open_store(session, new_session)
        with self.lock:
            if new_session:
                if self.check is not None:
                    self.previous = self.check.summary()
                self.check = feed.SessionCheck(session if isinstance(session, str) else None)
            # The check numbers its segments as the store names them, so the live verdict and the kept
            # session read back name the same segment for the same lines.
            self.check.begin_segment(self._store.number if self._store is not None else len(self.check.segments))
            self.check.line(raw)
            self._bump()
        self._keep(raw)

    def _open_store(self, session: Any, new_session: bool) -> None:
        if self.store_dir is None or not isinstance(session, str) or not feed.SESSION_RE.match(session):
            return
        try:
            if new_session or self._store is None or self._store.dir != os.path.join(self.store_dir, session):
                self._store = feed.FeedStore(self.store_dir, session, self.rotate_bytes)
            self._store.open_segment()
            with self.lock:
                self.kept = self._store.dir
                self.store_error = None
        except OSError as error:
            self._store = None
            with self.lock:
                self.store_error = f"the feed could not be kept: {error.strerror or error}"

    def _keep(self, raw: bytes) -> None:
        if self._store is None:
            return
        try:
            self._store.write(raw)
        except OSError as error:
            self._store = None
            with self.lock:
                self.store_error = f"the feed stopped being kept: {error.strerror or error}"

    def _take(self, raw: bytes) -> None:
        arrived = time.time()
        with self.lock:
            record = self.check.line(raw)
            if record is not None and record.get("kind") in feed.LEAF_KINDS:
                self.recent.append(feed.live_entry(record, int(arrived * 1_000_000)))
                if record.get("kind") == "malformed":
                    cause_key, action = None, "malformed"
                else:
                    rendered = causes_view.render(record.get("cause"))
                    cause_key = _bucket_key(rendered)
                    self.decoded.setdefault(cause_key, rendered)
                    action = record.get("outcome_name") if isinstance(record.get("outcome_name"), str) else record["kind"]
                self.arrivals.append((int(arrived), cause_key, action[:64]))
            self._bump()
        self._keep(raw)
        if record is not None and record.get("kind") == "seal" and self._store is not None:
            try:
                self._store.sync()
                if self._store.wants_rotation():
                    self._store.rotate(self._hello_line, raw)
                    with self.lock:
                        self.check.end_segment("rotated")
                        self.check.begin_segment(self._store.number)
                        self.check.line(self._hello_line)
                        self.check.line(raw)
                    self._retain()
                elif time.time() - self._retained_at >= RETAIN_EVERY_S:
                    self._retain()
            except OSError as error:
                self._store = None
                with self.lock:
                    self.store_error = f"the feed stopped being kept: {error.strerror or error}"

    def _oversized(self, length: int) -> None:
        with self.lock:
            if self.check is not None:
                self.check.oversized(length)
        self._ended("oversized", f"a line over the record bound ({length} bytes or more): the connection was closed")

    def _ended(self, reason: str, message: Optional[str]) -> None:
        # The kept segment is closed, with its end note, before the copy says the connection ended.
        self._close_store(reason)
        with self.lock:
            if self.check is not None:
                self.check.end_segment(reason)
            if message:
                self.last_error = message
            self._bump()

    def _close_store(self, reason: Optional[str]) -> None:
        store = self._store
        if store is None or store._fd is None:
            return
        try:
            store.close_segment(reason or "closed")
        except OSError as error:
            with self.lock:
                self.store_error = f"the feed's segment could not be closed: {error.strerror or error}"
        self._retain()

    def _retain(self) -> None:
        """Hold the store to its bounds (`feed.retain`), sparing the segment being written."""
        if self.store_dir is None or not (self.keep_bytes or self.keep_age_s):
            return
        self._retained_at = time.time()
        store = self._store
        in_use = os.path.join(store.dir, feed.segment_name(store.number)) if store is not None and store._fd is not None else None
        try:
            removed = feed.retain(self.store_dir, self.keep_bytes, self.keep_age_s, in_use=in_use)
        except OSError as error:
            with self.lock:
                self.retain_error = f"the store's bounds could not be applied: {error.strerror or error}"
            return
        if removed:
            for entry in removed:
                LOG.info("feed retention removed %s segment %d (%s)", entry["session"], entry["segment"], entry["removed"])
            with self.lock:
                self.removed_total += len(removed)
                self.removed_last = (self.removed_last + removed)[-20:]
                self.retain_error = None
                self._bump()

    # ------------------------------------------------------------ what the screens read
    def snapshot(self) -> Dict[str, Any]:
        with self.lock:
            return {"connection": self.connection, "endpoint": describe(self.endpoint), "version": self.version,
                    "connects": self.connects, "connected_since": self.connected_since, "last_error": self.last_error,
                    "kept": self.kept, "store": self.store_note, "store_error": self.store_error,
                    "retention": {"keep_bytes": self.keep_bytes, "keep_age_s": self.keep_age_s,
                                  "removed_total": self.removed_total, "last": list(self.removed_last),
                                  "error": self.retain_error},
                    "chain": self.check.summary() if self.check is not None else None,
                    "previous_session": self.previous}

    def live(self, limit: int = 50) -> Dict[str, Any]:
        """The connection, the chain's state, the newest leaf records (newest first) and the collector's
        last status: the enforcer's counters, whether a policy is loaded, and what the feed dropped."""
        view = self.snapshot()
        with self.lock:
            recent = list(self.recent)[-limit:][::-1] if limit > 0 else []
        chain = view["chain"] or {}
        status = chain.get("last_status") or {}
        view.update({"recent": recent, "enforcer": status.get("enforcer"), "feed": status.get("feed"),
                     "collector_count": status.get("count"), "verdict_of": feed.VERDICT_OF,
                     "statement": feed.STATEMENT})
        return view

    def series(self, bucket_s: int, last: Optional[int] = None) -> Dict[str, Any]:
        """The cause monitor's series over the live feed, bucketed by arrival time (the console's clock;
        `t_ns` is the enforcer host's monotonic clock, not wall time): the shape `evidence.cause_series`
        answers, so the monitor draws either."""
        if isinstance(bucket_s, bool) or not isinstance(bucket_s, int) or bucket_s <= 0:
            raise ValueError("bucket_s is a positive integer")
        with self.lock:
            arrivals = list(self.arrivals)
            decoded = dict(self.decoded)
        if last:
            arrivals = arrivals[-last:]
        starts = [second // bucket_s * bucket_s for second, _cause, _action in arrivals]
        if starts and (max(starts) - min(starts)) // bucket_s + 1 > MAX_BUCKETS:
            raise ValueError(f"the window spans more than {MAX_BUCKETS} buckets of {bucket_s} s")
        buckets: Dict[int, Dict[str, Any]] = {}
        seen: Dict[str, Dict[str, Any]] = {}
        for (_second, cause_key, action), start in zip(arrivals, starts):
            bucket = buckets.setdefault(start, {"start": start, "by_cause": {}, "by_action": {}})
            bucket["by_action"][action] = bucket["by_action"].get(action, 0) + 1
            if cause_key is not None:
                bucket["by_cause"][cause_key] = bucket["by_cause"].get(cause_key, 0) + 1
                seen[cause_key] = decoded.get(cause_key) or causes_view.render(None)
        view = self.snapshot()
        return {"source": "live", "path": view["endpoint"], "session": (view["chain"] or {}).get("session"),
                "connection": view["connection"], "bucket_s": bucket_s, "events": len(arrivals), "untimed": 0,
                "clock": "arrival", "buckets": [buckets[start] for start in sorted(buckets)], "causes": seen,
                "verdict_of": feed.VERDICT_OF}


def off_view(reason: str) -> Dict[str, Any]:
    """What the live routes answer when no client runs."""
    return {"connection": "off", "endpoint": "", "reason": reason, "chain": None, "recent": [], "enforcer": None,
            "feed": None, "verdict_of": feed.VERDICT_OF, "statement": feed.STATEMENT, "version": 0}
