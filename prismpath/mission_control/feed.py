# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The collector's feed as the console checks it and keeps it (WP9's feed, read by WP6 and WP4).

The collector (`prismpath-ebpf/collector/`, whose README is the feed's contract) serves newline delimited
canon/2 records: a `hello`, a `join` seal, then `decision`, `receipt` and `malformed` records that are each
a leaf of the session's RFC 6962 tree, `seal`s of that tree, `status`, `gap` and `error` records. This
module holds what the console does with those lines, apart from the socket (`feed_client`):

* `SessionCheck` checks one session's lines as they arrive. It starts an accumulator from the first seal
  of a connection (the `join` seal) with `MerkleAccumulator.from_peaks`, holds every leaf record's `index`
  to the count and its `leaf` to SHA-256 of its `frame`, adds the leaf, and holds every later seal's count,
  peaks and root to the tree it built. A `gap` is a hole: leaves the console's copy does not hold and the
  collector's seal does, so the tree cannot be carried over it; the console takes up the tree again from
  the next seal's peaks and says the leaves between were not checked. The live client and the stored
  evidence reader run the same code over the same bytes, so their verdicts are one verdict.
* `FeedStore` keeps every line as evidence under an evidence root, byte for byte as received.
* `feed_report` reads a kept session back under the evidence readers' rules (confined to the roots,
  bounded, never writing) and checks it again.

Every verdict here is the console's (`verdict_of: "console"`) over the collector's seals, which are the
collector's statement and are not signed (`statement: "collector seal, unsigned"`). A signed root
statement over a seal is the operator's step.

The layout of a kept session, `prismpath.console-feed/1`:

    <store>/<session>/feed-000000.jsonl      one connection's lines as received, each canon/2 and a line feed
    <store>/<session>/feed-000000.end.json   why that connection's copy ended (canon/2), written at its end
    <store>/<session>/feed-000001.jsonl      the next connection to the same session, or the same connection
                                             continued once the file passed the rotation bound
    ...

`<store>` is `MC_COLLECTOR_STORE`, or `collector-feed` in the first evidence root. `<session>` is the 32 hex
characters of the `hello` record's `session`. Every segment opens with the `hello` line and a seal line,
the `join` seal its connection was sent or, for a rotation, the seal the previous segment ended on, so a
segment is checkable alone from that seal's peaks, and read in order the segments are the session. A line
over the record bound is not kept (the end note names it); a line that is not canon/2 is kept as it came,
so a reader finds what the console found.
"""
from __future__ import annotations

import hashlib
import os
import re
import time
from typing import Any, Dict, List, Optional

from prismpath.kernel import canon2
from prismpath.ledgers.root_statement import MerkleAccumulator

from . import causes_view

PROTOCOL = "prismpath.collector/1"
SUBSCRIPTION = b'{"op":"subscribe","protocol":"prismpath.collector/1"}\n'
# The collector's bound on a line, its line feed included (README, "The feed"); `hello` states it as
# `max_record`. The console never takes a longer line whatever a hello says.
DEFAULT_MAX_RECORD = 8192
HARD_MAX_RECORD = 65536
FEED_FORMAT = "prismpath.console-feed/1"
VERDICT_OF = "console"
STATEMENT = "collector seal, unsigned"
LEAF_KINDS = ("decision", "receipt", "malformed")
SEGMENT_RE = re.compile(r"^feed-(\d{6})\.jsonl$")
SESSION_RE = re.compile(r"^[0-9a-f]{32}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_LISTED = 100              # findings, holes and unchecked spans a summary names at most
MAX_IGNORED_KINDS = 32        # distinct unknown kinds counted


def segment_name(number: int) -> str:
    return f"feed-{number:06d}.jsonl"


def end_name(number: int) -> str:
    return f"feed-{number:06d}.end.json"


def _int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def parse_line(raw: bytes) -> Optional[Dict[str, Any]]:
    """A line (no line feed) read by the strict canon/2 reader: the record, or None when it is not the
    canonical bytes of a JSON object with a string `kind`."""
    try:
        value = canon2.loads(raw)
    except (canon2.Canon2Error, TypeError, RecursionError):
        return None
    if not isinstance(value, dict) or not isinstance(value.get("kind"), str):
        return None
    return value


class SessionCheck:
    """One session's records checked as they arrive, across every connection to it. Feed it with
    `begin_segment`, `line` for each line received and `end_segment`; read the verdict with `summary`.

    Holds O(log n) of tree state and bounded lists, however long the session runs."""

    def __init__(self, session: Optional[str] = None):
        self.session = session
        self.hello: Optional[Dict[str, Any]] = None
        self.source: Optional[str] = None
        self.max_record = DEFAULT_MAX_RECORD
        self.acc: Optional[MerkleAccumulator] = None     # None: the tree cannot be carried (after a hole)
        self.expected: Optional[int] = None              # the index the stream's next leaf should carry
        self.joined_at: Optional[int] = None             # the count of the first seal the console was sent
        self.received = 0                                # leaf records received
        self.unframed = 0                                # leaf records without a frame, whose leaf is unchecked
        self.seals_checked = 0
        self.seals_adopted = 0                           # seals the tree was taken up from, after a hole
        self.last_seal: Optional[Dict[str, Any]] = None
        self.last_status: Optional[Dict[str, Any]] = None
        self.holes: List[Dict[str, Any]] = []
        self.holes_total = 0
        self.missing = 0
        self.unchecked: List[Dict[str, Any]] = []
        self.unchecked_total = 0
        self._unchecked_from: Optional[int] = None
        self.findings: List[Dict[str, Any]] = []
        self.findings_total = 0
        self.collector_errors: List[Dict[str, Any]] = []
        self.ignored: Dict[str, int] = {}
        self.segments: List[Dict[str, Any]] = []
        self._segment: Optional[Dict[str, Any]] = None

    # ------------------------------------------------------------ findings
    def _find(self, check: str, detail: str, **where: Any) -> None:
        self.findings_total += 1
        if len(self.findings) < MAX_LISTED:
            seg = self._segment
            entry = {"check": check, "detail": detail}
            if seg is not None:
                entry["segment"] = seg["segment"]
                entry["line"] = seg["lines"] - 1
            entry.update(where)
            self.findings.append(entry)

    def _hole(self, start: int, end: int, why: str) -> None:
        self.holes_total += 1
        self.missing += end - start
        if len(self.holes) < MAX_LISTED:
            self.holes.append({"from": start, "to": end, "leaves": end - start, "why": why,
                               "segment": self._segment["segment"] if self._segment else None})

    def _lose_tree(self) -> None:
        """The tree cannot be carried on: leaves from here to the next seal are held but not checked."""
        self.acc = None
        if self._unchecked_from is None and self.expected is not None:
            self._unchecked_from = self.expected

    def _close_unchecked(self, upto: int) -> None:
        if self._unchecked_from is not None and upto > self._unchecked_from:
            self.unchecked_total += 1
            if len(self.unchecked) < MAX_LISTED:
                self.unchecked.append({"from": self._unchecked_from, "to": upto, "leaves": upto - self._unchecked_from})
        self._unchecked_from = None

    # ------------------------------------------------------------ segments
    def begin_segment(self, number: int) -> None:
        self._segment = {"segment": number, "lines": 0, "starting_count": None, "ended": None}
        self.segments.append(self._segment)

    def end_segment(self, reason: str) -> None:
        if self._segment is not None:
            self._segment["ended"] = reason
            if self._segment["starting_count"] is None and reason not in ("refused",):
                self._find("no-starting-seal", "the connection ended before its hello and first seal")
        self._segment = None

    def oversized(self, length: int) -> None:
        """A line longer than the record bound arrived; the reader ends the connection without keeping it."""
        if self._segment is not None:
            self._segment["lines"] += 1
        self._find("oversized", f"a line of at least {length} bytes, over the {self.max_record} byte record bound")

    # ------------------------------------------------------------ one line
    def line(self, raw: bytes) -> Optional[Dict[str, Any]]:
        """Check one line (without its line feed). Returns the record when it read, else None."""
        seg = self._segment
        if seg is None:
            self.begin_segment(len(self.segments))
            seg = self._segment
        seg["lines"] += 1
        position = seg["lines"] - 1
        if len(raw) + 1 > self.max_record:
            self._find("oversized", f"a line of {len(raw) + 1} bytes, over the {self.max_record} byte record bound")
            return None
        record = parse_line(raw)
        if record is None:
            self._find("not-canon2", "the line is not the canonical canon/2 bytes of a record")
            return None
        kind = record["kind"]
        if position == 0:
            if kind == "refused":
                seg["refused"] = record.get("reason") if isinstance(record.get("reason"), str) else "?"
                return record
            if kind != "hello":
                self._find("no-hello", f"the connection's first record is {kind!r}, not hello")
                return record
            self._on_hello(record)
            return record
        if kind == "hello":
            self._find("hello-out-of-place", "a hello after the first record of a connection")
            return record
        if position == 1 or seg["starting_count"] is None:
            if kind != "seal":
                self._find("no-starting-seal", f"the record after hello is {kind!r}, not a seal")
                return record
            self._on_starting_seal(record)
            return record
        if kind in LEAF_KINDS:
            self._on_leaf(record)
        elif kind == "seal":
            self._on_seal(record)
        elif kind == "gap":
            self._on_gap(record)
        elif kind == "status":
            if record.get("session") not in (None, self.session):
                self._find("session", "a status record names another session")
            else:
                self.last_status = record
        elif kind == "error":
            if len(self.collector_errors) < MAX_LISTED:
                self.collector_errors.append({"reason": record.get("reason"), "segment": seg["segment"], "line": position})
        else:
            # A kind this console does not know is passed over, so the feed can add one (README); the
            # count names it, with the names and their number bounded.
            key = kind[:64]
            if key in self.ignored or len(self.ignored) < MAX_IGNORED_KINDS:
                self.ignored[key] = self.ignored.get(key, 0) + 1
        return record

    def _on_hello(self, record: Dict[str, Any]) -> None:
        session = record.get("session")
        if record.get("protocol") != PROTOCOL:
            self._find("protocol", f"the hello names protocol {record.get('protocol')!r}, not {PROTOCOL}")
        if not isinstance(session, str) or not SESSION_RE.match(session):
            self._find("session", "the hello's session is not 16 bytes of lowercase hex")
            return
        if self.session is None:
            self.session = session
        elif session != self.session:
            self._find("session", "a hello for another session inside this one")
            return
        self.hello = record
        if isinstance(record.get("source"), str):
            self.source = record["source"]
        bound = record.get("max_record")
        if _int(bound) and bound > 0:
            self.max_record = min(bound, HARD_MAX_RECORD)

    def _seal_state(self, record: Dict[str, Any]) -> Optional[MerkleAccumulator]:
        """The accumulator a seal states, or None (with a finding) when its count, peaks and root disagree."""
        if record.get("session") not in (None, self.session):
            self._find("session", "a seal names another session")
            return None
        count, peaks = record.get("count"), record.get("peaks")
        try:
            state = MerkleAccumulator.from_peaks(count, peaks if isinstance(peaks, list) else None)
        except (ValueError, TypeError):
            self._find("seal-peaks", "the seal's peaks are not one hash per set bit of its count", count=count)
            return None
        if state.root() != record.get("root", ""):
            self._find("seal-root", "the seal's root is not the root of its own peaks", count=count)
            return None
        return state

    def _on_starting_seal(self, record: Dict[str, Any]) -> None:
        seg = self._segment
        state = self._seal_state(record)
        if state is None:
            seg["starting_count"] = record.get("count") if _int(record.get("count")) else -1
            self._lose_tree()
            return
        count = state.count
        seg["starting_count"] = count
        seg["trigger"] = record.get("trigger")
        self.last_seal = {"count": count, "root": state.root(), "trigger": record.get("trigger")}
        if self.expected is None:                         # the console's first sight of this session
            self.joined_at = count
        elif count < self.expected:
            self._find("session-went-back", f"a seal of {count} leaves after the stream reached {self.expected}",
                       count=count)
        elif count == self.expected and self.acc is not None:
            if state.peaks() == self.acc.peaks():
                return                                    # the same tree, carried on
            self._find("seal-root", "the starting seal disagrees with the tree the console built", count=count)
        else:
            # The console's copy cannot be carried to this seal: the leaves it missed while it was not
            # connected are a hole, and the tree is taken up again from this seal's peaks.
            if count > self.expected:
                self._close_unchecked(self.expected)
                self._hole(self.expected, count, "disconnected")
            self.seals_adopted += 1
        self._close_unchecked(count)
        self.acc = state
        self.expected = count

    def _on_leaf(self, record: Dict[str, Any]) -> None:
        self.received += 1
        index, leaf, frame = record.get("index"), record.get("leaf"), record.get("frame")
        if not _int(index):
            self._find("index", "a leaf record without an integer index")
            self._lose_tree()
            self.expected = (self.expected or 0) + 1
            return
        if index != self.expected:
            self._find("index", f"the record's index is {index}, the stream's count is {self.expected}", index=index)
            self._lose_tree()
            self.expected = index
        if not isinstance(leaf, str) or not HEX64_RE.match(leaf):
            self._find("leaf", "the record's leaf is not a 32 byte hash in lowercase hex", index=index)
            leaf = None
        computed = None
        if frame is None:
            self.unframed += 1                            # a malformed record too long to carry its bytes
        elif isinstance(frame, str) and len(frame) % 2 == 0 and re.fullmatch(r"[0-9a-f]*", frame):
            computed = hashlib.sha256(bytes.fromhex(frame)).hexdigest()
            if leaf is not None and computed != leaf:
                self._find("leaf", "the record's leaf is not SHA-256 of its frame", index=index)
        else:
            self._find("leaf", "the record's frame is not lowercase hex", index=index)
        # What the console adds is the hash it computed when it could, so a seal is checked against the
        # frames themselves, not against a leaf member that could have been changed beside them.
        added = computed or leaf
        if self.acc is not None and added is not None:
            self.acc.add(added)
        elif self.acc is not None:
            self._lose_tree()
        self.expected = index + 1

    def _on_seal(self, record: Dict[str, Any]) -> None:
        state = self._seal_state(record)
        if state is None:
            self._lose_tree()
            return
        count = state.count
        self.last_seal = {"count": count, "root": state.root(), "trigger": record.get("trigger")}
        if count != self.expected:
            self._find("seal-count", f"a seal of {count} leaves where the stream holds {self.expected}", count=count)
        elif self.acc is not None:
            if state.peaks() == self.acc.peaks():
                self.seals_checked += 1
                return
            self._find("seal-root", "the seal's root is not the root of the leaves the console received", count=count)
        else:
            self.seals_adopted += 1                       # after a hole: the tree is taken up from this seal
        self._close_unchecked(count)
        self.acc = state
        self.expected = count

    def _on_gap(self, record: Dict[str, Any]) -> None:
        dropped = record.get("dropped")
        if not _int(dropped) or dropped == 0:
            self._find("gap", "a gap record without a positive count")
            self._lose_tree()
            return
        start = self.expected or 0
        self._close_unchecked(start)
        self._hole(start, start + dropped, "gap")
        self.acc = None
        self.expected = start + dropped
        self._unchecked_from = self.expected

    # ------------------------------------------------------------ the verdict
    def status(self) -> str:
        """`broken` when any check failed, `holes` when the console's copy misses leaves the collector
        sealed, `pending` when leaves since the last seal await one, `intact` when every leaf received is
        under a seal whose root the console recomputed, `empty` before a starting seal."""
        if self.findings_total:
            return "broken"
        if self.holes_total or self.unchecked_total or self._unchecked_from is not None:
            return "holes"
        if self.expected is None:
            return "empty"
        sealed = self.last_seal["count"] if self.last_seal else None
        return "intact" if sealed == self.expected else "pending"

    def summary(self) -> Dict[str, Any]:
        unchecked = list(self.unchecked)
        if self._unchecked_from is not None and self.expected is not None and self.expected > self._unchecked_from:
            unchecked.append({"from": self._unchecked_from, "to": self.expected,
                              "leaves": self.expected - self._unchecked_from, "open": True})
        return {
            "format": FEED_FORMAT, "session": self.session, "source": self.source, "status": self.status(),
            "verdict_of": VERDICT_OF, "statement": STATEMENT, "signed": False,
            "joined_at": self.joined_at, "count": self.expected, "received": self.received, "unframed": self.unframed,
            "seals": {"checked": self.seals_checked, "adopted": self.seals_adopted, "last": self.last_seal},
            "root": self.acc.root() if self.acc is not None else None,
            "holes": list(self.holes), "holes_total": self.holes_total, "missing": self.missing,
            "unchecked": unchecked, "unchecked_total": self.unchecked_total + (1 if len(unchecked) > len(self.unchecked) else 0),
            "findings": list(self.findings), "findings_total": self.findings_total,
            "collector_errors": list(self.collector_errors), "ignored": dict(self.ignored),
            "segments": [dict(segment) for segment in self.segments],
            "last_status": self.last_status,
            "note": "the seals are the collector's statement and are not signed; every check here is the "
                    "console's, and a signed root statement over a seal is the operator's step",
        }


def live_entry(record: Dict[str, Any], arrived_us: int) -> Dict[str, Any]:
    """The operating view of one leaf record: what the operator reads, every cause from the registry."""
    entry = {"kind": record.get("kind"), "index": record.get("index"), "arrived_us": arrived_us,
             "cause": causes_view.render(record.get("cause")) if "cause" in record else None}
    for name in ("outcome_name", "reason", "reading", "src_ip", "src_port", "request_id", "t_ns", "edge", "image_index",
                 "seq", "prev_node", "event", "next_node", "migration", "length"):
        if name in record:
            entry[name] = record[name]
    return entry


# ----------------------------------------------------------------- keeping the lines
class StoreError(OSError):
    pass


class FeedStore:
    """Keeps one session's lines under `<store>/<session>/` in the layout of the module docstring.

    Files are created by this process only (O_EXCL), never through a symlink, mode 0600, and a segment
    passing `rotate_bytes` is closed at the next seal and continued in a new one."""

    def __init__(self, store_dir: str, session: str, rotate_bytes: int):
        if not SESSION_RE.match(session or ""):
            raise StoreError("a session id is 32 lowercase hex characters")
        self.dir = os.path.join(store_dir, session)
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        if os.path.islink(self.dir) or not os.path.isdir(self.dir):
            raise StoreError("the session directory is not a directory")
        self.rotate_bytes = rotate_bytes
        self.number = self._next_number()
        self._fd: Optional[int] = None
        self._lines = 0
        self._size = 0

    def _next_number(self) -> int:
        numbers = [int(match.group(1)) for match in map(SEGMENT_RE.match, os.listdir(self.dir)) if match]
        return max(numbers) + 1 if numbers else 0

    def open_segment(self) -> int:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        self._fd = os.open(os.path.join(self.dir, segment_name(self.number)), flags, 0o600)
        self._lines = self._size = 0
        return self.number

    def write(self, raw: bytes) -> None:
        if self._fd is None:
            return
        data = raw + b"\n"
        os.write(self._fd, data)
        self._lines += 1
        self._size += len(data)

    def sync(self) -> None:
        if self._fd is not None:
            os.fsync(self._fd)

    def wants_rotation(self) -> bool:
        return self._fd is not None and self._size >= self.rotate_bytes

    def close_segment(self, reason: str) -> None:
        if self._fd is None:
            return
        os.fsync(self._fd)
        os.close(self._fd)
        self._fd = None
        note = {"format": FEED_FORMAT, "segment": self.number, "ended": reason, "lines": self._lines,
                "size": self._size, "time_us": int(time.time() * 1_000_000)}
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(os.path.join(self.dir, end_name(self.number)), flags, 0o600)
        try:
            os.write(fd, canon2.dumps(note) + b"\n")
        finally:
            os.close(fd)
        self.number += 1

    def rotate(self, hello_line: bytes, seal_line: bytes) -> int:
        """Close the segment on the seal just written and open the next with the hello and that seal."""
        self.close_segment("rotated")
        number = self.open_segment()
        self.write(hello_line)
        self.write(seal_line)
        return number


# ----------------------------------------------------------------- reading a kept session back
def _segments_of(listing: List[str]) -> List[int]:
    return sorted(int(match.group(1)) for match in map(SEGMENT_RE.match, listing) if match)


def is_feed_dir(filenames) -> bool:
    return any(SEGMENT_RE.match(name) for name in filenames)


def feed_report(path: Any, segment: Optional[int] = None, roots=None) -> Dict[str, Any]:
    """A kept session (`<store>/<session>`, under the evidence roots) checked again from its bytes: the
    same `SessionCheck` the live client ran, over every segment in order, or over one segment alone from
    its starting seal. Reads only, confined and bounded as every evidence reader is; the files of one
    report together are at most MC_MAX_EVIDENCE_BYTES (name one segment for a longer session)."""
    from . import evidence
    from .config import SETTINGS

    real, root = evidence._confine(path, roots)
    if not os.path.isdir(real):
        raise evidence.EvidenceRefused("not-found", "no kept feed session there")
    numbers = _segments_of(os.listdir(real))
    if not numbers:
        raise evidence.EvidenceRefused("not-found", "the directory holds no feed segment")
    if segment is not None:
        if isinstance(segment, bool) or not isinstance(segment, int) or segment not in numbers:
            raise evidence.EvidenceRefused("bad-request", f"the session's segments are {numbers[0]} to {numbers[-1]}")
        numbers = [segment]
    name = os.path.basename(real)
    check = SessionCheck(name if SESSION_RE.match(name) else None)
    total, files = 0, []
    for number in numbers:
        full, _root = evidence._confine(os.path.join(real, segment_name(number)), roots)
        try:
            data = evidence._read_bounded(full, SETTINGS.max_evidence_bytes - total, f"segment {number}")
        except evidence.EvidenceRefused as refused:
            if refused.reason == "too-large":
                raise evidence.EvidenceRefused("too-large", f"the session's segments together are over the "
                                               f"{SETTINGS.max_evidence_bytes} byte bound (MC_MAX_EVIDENCE_BYTES): "
                                               f"name one segment") from None
            raise
        total += len(data)
        ended = None
        note_path = os.path.join(real, end_name(number))
        if os.path.lexists(note_path):
            note_real, _root = evidence._confine(note_path, roots)
            try:
                note = canon2.loads(evidence._read_bounded(note_real, 4096, "an end note").rstrip(b"\n"))
            except (canon2.Canon2Error, RecursionError):
                note = None
            ended = note.get("ended") if isinstance(note, dict) and isinstance(note.get("ended"), str) else "unreadable"
        check.begin_segment(number)
        lines = data.split(b"\n")
        if lines and lines[-1] == b"":
            lines.pop()
        elif lines:
            check._find("truncated", "the segment's last line has no line feed")
            lines.pop()
        for raw in lines:
            check.line(raw)
        if ended == "oversized":
            check.oversized(check.max_record + 1)
        check.end_segment(ended or "open")
        files.append({"segment": number, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                      "lines": len(lines), "ended": ended})
    report = check.summary()
    report.update({"path": real, "evidence_root": root, "files": files, "whole": segment is None})
    return report
