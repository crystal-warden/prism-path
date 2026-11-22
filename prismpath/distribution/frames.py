# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The frame binding of policy distribution (spec-policy-distribution.md, section 8.3), for a broadcast
medium such as ESP-NOW or the cFS software bus, where one sender reaches every enforcement point at once.

`encode` and `decode` are the six frame types (offer, chunk, state, commit, abort and epoch). Anything a
reader would refuse is `dist:frame-invalid`, and `encode` refuses to write it. `frames_for` is the
sender's side: the offer and the chunks of one sealed envelope and its body, each frame within the link's
limit (250 bytes on ESP-NOW). `Assembler` is the receiver's side, the reassembly of B6, B7, B9 and B11
with an injected monotonic clock.

The assembler reads no more than it was promised (B9). The sealed part is held to the offered length,
which is at most 2,440 bytes, and its envelope id to the offered one. The body is read only once the
caller's `admit` has passed the sealed envelope through V8, and then only to the signed `body_size` and
against the signed `body_sha256`. A body chunk that arrives before that is not read, so a lost or early
frame costs a retry and never a partial stage. What the assembler hands back whole is then verified in
full by the enforcement point, as anything staged is (V1).
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Callable, Iterator, Optional, Tuple, Union

from prismpath.distribution import envelope as env
from prismpath.distribution.kinds import MAX_SEQ, TRUST_ARTIFACTS, TRUST_BOUND, Refused
from prismpath.distribution.state_record import prefix as hash_prefix
from prismpath.distribution.state_record import stream_prefix

FRAME_INVALID = "dist:frame-invalid"
TOO_LARGE = "dist:too-large"
VERSION = 1
ESPNOW_LIMIT = 250                                 # ESP_NOW_MAX_DATA_LEN
TIMEOUT = 5.0                                      # B7: seconds a transfer may stay incomplete
PREFIX = 16                                        # the bytes of a hash a frame carries
SEALED, BODY = 0, 1                                # chunk parts
OFFER, CHUNK, STATE, COMMIT, ABORT, EPOCH = 1, 2, 3, 4, 5, 6

_HEAD = struct.Struct("<BBH")                      # type, version, transfer
_OFFER = struct.Struct(f"<{PREFIX}sHI")            # envelope id prefix, sealed length, body length
_CHUNK = struct.Struct("<BIH")                     # part, offset, length
_ABORT = struct.Struct(f"<{PREFIX}sQ{PREFIX}s")    # stream hash prefix, seq, policy hash prefix
_COMMIT = struct.Struct(f"<{PREFIX}sQ{PREFIX}sH")  # the same, and the delay in milliseconds
_EPOCH = struct.Struct("<Q")
CHUNK_OVERHEAD = _HEAD.size + _CHUNK.size          # 11 bytes before a chunk's data


def _require(condition: bool, detail: str, cause: str = FRAME_INVALID) -> None:
    if not condition:
        raise Refused(cause, detail)


@dataclass(frozen=True)
class Offer:
    """A sealed envelope exists for this transfer: its envelope id's first 16 bytes and the two lengths."""
    transfer: int
    envelope_prefix: bytes
    sealed_length: int
    body_length: int


@dataclass(frozen=True)
class Chunk:
    """`data` at `offset` of `part`, the sealed envelope (0) or the body (1), of a transfer."""
    transfer: int
    part: int
    offset: int
    data: bytes


@dataclass(frozen=True)
class State:
    """One state record (H1), carried as its bytes and read by `state_record.read` with the PEP's key."""
    transfer: int
    record: bytes


@dataclass(frozen=True)
class Abort:
    """Drop the staged release named by its stream, `seq` and policy hash, each a 16 byte prefix but `seq`."""
    transfer: int
    stream_prefix: bytes
    seq: int
    policy_prefix: bytes

    def names(self, stream: str, seq: int, policy_sha256: str) -> bool:
        """Whether this frame names the release at `seq` of `policy_sha256` on `stream`."""
        return (self.stream_prefix, self.seq, self.policy_prefix) == (stream_prefix(stream), seq,
                                                                       hash_prefix(policy_sha256))


@dataclass(frozen=True)
class Commit(Abort):
    """Make the staged release active at the PEP's own monotonic time plus `delay_ms` (B8)."""
    delay_ms: int = 0


@dataclass(frozen=True)
class Epoch:
    """The controller's epoch id (H9)."""
    transfer: int
    epoch: int


Frame = Union[Offer, Chunk, State, Commit, Abort, Epoch]


def encode(frame: Frame, limit: int = ESPNOW_LIMIT) -> bytes:
    """The bytes of `frame`, at most `limit`. Refuses (`dist:frame-invalid`) what `decode` would refuse."""
    try:
        if isinstance(frame, Offer):
            kind, rest = OFFER, _OFFER.pack(frame.envelope_prefix, frame.sealed_length, frame.body_length)
        elif isinstance(frame, Chunk):
            kind, rest = CHUNK, _CHUNK.pack(frame.part, frame.offset, len(frame.data)) + bytes(frame.data)
        elif isinstance(frame, State):
            kind, rest = STATE, bytes(frame.record)
        elif isinstance(frame, Commit):
            kind, rest = COMMIT, _COMMIT.pack(frame.stream_prefix, frame.seq, frame.policy_prefix, frame.delay_ms)
        elif isinstance(frame, Abort):
            kind, rest = ABORT, _ABORT.pack(frame.stream_prefix, frame.seq, frame.policy_prefix)
        elif isinstance(frame, Epoch):
            kind, rest = EPOCH, _EPOCH.pack(frame.epoch)
        else:
            raise Refused(FRAME_INVALID, f"not a frame: {frame!r}")
        data = _HEAD.pack(kind, VERSION, frame.transfer) + rest
    except struct.error as error:
        raise Refused(FRAME_INVALID, f"a frame member out of range ({error})") from None
    if decode(data, limit) != frame:
        raise Refused(FRAME_INVALID, f"{frame!r} does not read back")
    return data


def decode(data: bytes, limit: int = ESPNOW_LIMIT) -> Frame:
    """The frame in `data`, or `Refused` with `dist:frame-invalid` for a frame of another length, type or
    version, a chunk part other than 0 and 1, a hash prefix that is not 16 bytes, or a `seq` past 2^53 - 1."""
    data = bytes(data)
    _require(_HEAD.size <= len(data) <= limit, f"a frame of {len(data)} bytes")
    kind, version, transfer = _HEAD.unpack_from(data)
    _require(version == VERSION, f"frame version {version}")
    rest = data[_HEAD.size:]

    def exactly(layout: struct.Struct) -> tuple:
        _require(len(rest) == layout.size, f"a frame of type {kind} of {len(data)} bytes")
        return layout.unpack(rest)

    if kind == OFFER:
        prefix, sealed_length, body_length = exactly(_OFFER)
        return Offer(transfer, prefix, sealed_length, body_length)
    if kind == CHUNK:
        _require(len(rest) >= _CHUNK.size, "a chunk shorter than its header")
        part, offset, length = _CHUNK.unpack_from(rest)
        _require(part in (SEALED, BODY), f"chunk part {part}")
        _require(len(rest) == _CHUNK.size + length, "a chunk whose length is not its data")
        return Chunk(transfer, part, offset, rest[_CHUNK.size:])
    if kind == STATE:
        return State(transfer, rest)
    if kind in (COMMIT, ABORT):
        values = exactly(_COMMIT if kind == COMMIT else _ABORT)
        _require(values[1] <= MAX_SEQ, "a seq past 2^53 - 1")
        return Commit(transfer, *values) if kind == COMMIT else Abort(transfer, *values)
    if kind == EPOCH:
        return Epoch(transfer, *exactly(_EPOCH))
    raise Refused(FRAME_INVALID, f"frame type {kind}")


def commit_for(transfer: int, stream: str, seq: int, policy_sha256: str, delay_ms: int = 0) -> Commit:
    return Commit(transfer, stream_prefix(stream), seq, hash_prefix(policy_sha256), delay_ms)


def abort_for(transfer: int, stream: str, seq: int, policy_sha256: str) -> Abort:
    return Abort(transfer, stream_prefix(stream), seq, hash_prefix(policy_sha256))


def frames_for(transfer: int, sealed: bytes, body: bytes, limit: int = ESPNOW_LIMIT) -> Iterator[bytes]:
    """The sender's frames for one sealed envelope and its body: the offer, then the chunks of the sealed
    envelope and of the body in offset order, each at most `limit` bytes, which is what an ordered link
    (B11) requires."""
    envelope_bytes, _entries = env.unseal(sealed)
    yield encode(Offer(transfer, hash_prefix(env.envelope_id(envelope_bytes)), len(sealed), len(body)), limit)
    step = limit - CHUNK_OVERHEAD
    _require(step > 0, f"a frame limit of {limit} bytes holds no chunk data")
    for part, data in ((SEALED, bytes(sealed)), (BODY, bytes(body))):
        for offset in range(0, len(data), step):
            yield encode(Chunk(transfer, part, offset, data[offset:offset + step]), limit)


@dataclass(frozen=True)
class Assembled:
    """A transfer whose sealed envelope and body are whole, for the enforcement point to verify and stage."""
    transfer: int
    sealed: bytes
    body: bytes


@dataclass(frozen=True)
class Dropped:
    """A transfer dropped with a cause: `dist:frame-invalid`, `dist:too-large` or the refusal of `admit`.
    `transfer` is None for a frame that did not read, which names no transfer."""
    transfer: Optional[int]
    cause: str


Event = Union[Assembled, Dropped, State, Commit, Abort, Epoch]
# admit(sealed) passes the sealed envelope through V8 and answers the signed (body_size, body_sha256), or
# raises Refused with the verifier's cause
Admit = Callable[[bytes], Tuple[int, str, str]]              # (body_size, body_sha256, artifact)


class _Part:
    """One part being assembled: its bytes so far and which of them have arrived."""

    def __init__(self, length: int):
        self.data = bytearray(length)
        self.have = bytearray(length)
        self.next = 0                              # the next offset an ordered link may send
        self.missing = length

    def put(self, offset: int, data: bytes, ordered: bool) -> None:
        _require(offset + len(data) <= len(self.data), "a chunk outside the offered length")       # B6
        _require(not ordered or offset == self.next, "a chunk out of order on an ordered link")    # B11
        self.data[offset:offset + len(data)] = data
        for index in range(offset, offset + len(data)):
            if not self.have[index]:
                self.have[index] = 1
                self.missing -= 1
        self.next = offset + len(data)

    @property
    def whole(self) -> bool:
        return self.missing == 0


class _Transfer:
    def __init__(self, offer: Offer, started: float):
        self.offer = offer
        self.started = started
        self.sealed = _Part(offer.sealed_length)
        self.body: Optional[_Part] = None          # opened only once admit passed the sealed envelope
        self.body_sha256 = ""
        self.sealed_bytes = b""


class Assembler:
    """The receiver of B6, B7, B9 and B11. `receive(frame)` takes one frame's bytes and answers an event
    or None. It holds one transfer at a time (B7): a new offer replaces a transfer that is not whole, and a
    transfer that is not whole `timeout` seconds after its offer is dropped silently. `clock` is the PEP's
    monotonic clock in seconds. `admit` is the enforcement point's check of the sealed envelope through V8
    (`admit_through_v8`). `artifact_bound` is the PEP's bound on the body of an artifact and `trust_bound` its
    bound on a trust body, never below 16,384 bytes (E6). An offer longer than both is dropped at once, and once
    the envelope is admitted its signed size is held to the bound of its artifact. `ordered` declares the link
    ordered (B11)."""

    def __init__(self, admit: Admit, *, clock: Callable[[], float], artifact_bound: int = env.MAX_BODY,
                 trust_bound: int = TRUST_BOUND, ordered: bool = False, limit: int = ESPNOW_LIMIT,
                 timeout: float = TIMEOUT):
        if trust_bound < TRUST_BOUND:
            raise ValueError(f"a trust bound is never below {TRUST_BOUND} bytes (E6)")
        self.admit, self.clock = admit, clock
        self.artifact_bound, self.trust_bound = artifact_bound, trust_bound
        self.ordered, self.limit, self.timeout = ordered, limit, timeout
        self.transfer: Optional[_Transfer] = None

    def _expire(self) -> None:
        if self.transfer is not None and self.clock() - self.transfer.started > self.timeout:
            self.transfer = None                   # B7: dropped silently

    def _drop(self, cause: str, transfer: int) -> Dropped:
        if self.transfer is not None and self.transfer.offer.transfer == transfer:
            self.transfer = None
        return Dropped(transfer, cause)

    def receive(self, data: bytes) -> Optional[Event]:
        try:
            frame = decode(data, self.limit)
        except Refused as refused:
            return Dropped(None, refused.cause)
        self._expire()
        if isinstance(frame, Offer):
            return self._offer(frame)
        if isinstance(frame, Chunk):
            try:
                return self._chunk(frame)
            except Refused as refused:
                return self._drop(refused.cause, frame.transfer)
        return frame

    def _offer(self, offer: Offer) -> Optional[Event]:
        current = self.transfer
        if current is not None and current.offer == offer:
            return None                            # a repeated offer
        if not 1 <= offer.sealed_length <= env.MAX_SEALED:                                         # B9
            return self._drop(FRAME_INVALID, offer.transfer)
        if offer.body_length > max(self.artifact_bound, self.trust_bound):                          # E6
            return self._drop(TOO_LARGE, offer.transfer)
        self.transfer = _Transfer(offer, self.clock())
        return None

    def _chunk(self, chunk: Chunk) -> Optional[Event]:
        current = self.transfer
        _require(current is not None and current.offer.transfer == chunk.transfer, "a chunk with no offer")
        if chunk.part == BODY:
            if current.body is None:
                return None                        # B9: no body is read before the envelope is admitted
            current.body.put(chunk.offset, chunk.data, self.ordered)
            return self._finish(current)
        if current.sealed.whole:
            return None                            # a repeat of a part already whole and admitted
        current.sealed.put(chunk.offset, chunk.data, self.ordered)
        if not current.sealed.whole:
            return None
        sealed = bytes(current.sealed.data)
        try:
            envelope_bytes, _entries = env.unseal(sealed)
        except Refused:
            raise Refused(FRAME_INVALID, "an assembled sealed part that is not the offered envelope") from None
        _require(hash_prefix(env.envelope_id(envelope_bytes)) == current.offer.envelope_prefix,
                 "an assembled sealed part whose envelope id is not the offered one")             # B6
        try:
            body_size, body_sha256, artifact = self.admit(sealed)
        except Refused as refused:
            return self._drop(refused.cause, chunk.transfer)
        _require(body_size == current.offer.body_length, "an offered body length that is not the signed one")
        if body_size > (self.trust_bound if artifact in TRUST_ARTIFACTS else self.artifact_bound):          # E6
            return self._drop(TOO_LARGE, chunk.transfer)
        current.sealed_bytes, current.body_sha256 = sealed, body_sha256
        current.body = _Part(body_size)
        return self._finish(current)

    def _finish(self, current: _Transfer) -> Optional[Event]:
        if current.body is None or not current.body.whole:
            return None
        body = bytes(current.body.data)
        _require(hashlib.sha256(body).hexdigest() == current.body_sha256,
                 "an assembled body whose hash is not the signed one")                              # B6
        self.transfer = None
        return Assembled(current.offer.transfer, current.sealed_bytes, body)


def admit_through_v8(through_v8: Callable[[bytes], object]) -> Admit:
    """An `admit` for `Assembler` from the enforcement point's `verify.verify_through_v8`, bound to its trust store,
    view and clock: `through_v8(sealed)` answers a `Verdict` of V2 to V8 with no body read (B9)."""

    def admit(sealed: bytes) -> Tuple[int, str, str]:
        verdict = through_v8(sealed)
        if verdict.cause is not None:
            raise Refused(verdict.cause)
        envelope = verdict.envelope
        return envelope.body_size, envelope.body_sha256, envelope.artifact
    return admit
