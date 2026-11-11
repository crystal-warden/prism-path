# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The concentrator profile (PROTOCOL.md section 2.9): many streams, one datagram.

A 2-3 byte decision inside a ~28 byte IP+UDP envelope is header-dominated; a bridge that uplinks
a fleet amortizes that envelope by concatenating records from many streams into one datagram.
The concentrated frame stays zero-header in the Facet sense: a record is
``[stream_id][reading]`` where the stream id is itself Zeckendorf-coded (ids from 1) and the
reading carries no length because the stream's codebook fixes its field count (I3 does the
framing). Records pack bit-contiguously; only the datagram is padded to the byte.

The demultiplexer is strict and fail-closed over the whole datagram: an unknown stream id, a
record truncated mid-reading, or a trailing partial that is not zero pad rejects the datagram
with a distinct cause (``concentrator-unknown-stream``, ``concentrator-truncated``)  -  never a
partial delivery, because a datagram that demuxes differently at two consumers is worse than a
lost one.

The registry mapping stream id to field count is derived from each stream's signed policy
(``len(build_partitions(policy))``) and agreed out of band exactly like the codebook itself.
"""
from __future__ import annotations

from typing import Dict, List, Tuple

from prismpath.kernel import causes
from prismpath.telemetry import packed
from prismpath.telemetry import zeckendorf as zeck

CONCENTRATOR_UNKNOWN_STREAM = "concentrator-unknown-stream"
CONCENTRATOR_TRUNCATED = "concentrator-truncated"
OK = "ok"

_NO_TERMINATOR = causes.NAMES["wire:no-terminator"]
_DANGLING_CODEWORD = causes.NAMES["wire:dangling-codeword"]


class Demuxed(tuple):
    """What `demux` returns: ``(records, status)`` as the plain pair it always was, and `cause`, the
    registry code (docs/design/spec-cause-codes.md) when the refusal is one the strict decode causes name
    exactly, else None. The status string stays the decoder's own; the cause sits beside it.

    `wire:no-terminator` (48) is a datagram with no complete codeword in it at all; `wire:dangling-codeword`
    (49) is a trailing partial codeword with data bits after at least one complete codeword. A record cut
    where only zero bits remain is padding, not a dangling codeword, and an unknown stream id has its own
    registered cause, so neither carries one here."""

    def __new__(cls, records, status, cause=None):
        self = super().__new__(cls, (records, status))
        self.cause = cause
        return self


def concentrate(records: List[Tuple[int, List[int]]]) -> bytes:
    """``[(stream_id, wire_ints)]`` -> one byte-aligned concentrated frame.

    ``wire_ints`` are the stream's already-encoded symbols-plus-one (the output layer of
    ``wire.encode_reading``); this layer composes existing encoders, it never re-encodes."""
    bits = []
    for stream_id, wire_ints in records:
        if stream_id < 1:
            raise ValueError(f"stream ids are positive (Zeckendorf-coded); got {stream_id}")
        if not wire_ints:
            raise ValueError(f"stream {stream_id}: empty reading")
        bits.append(zeck.encode(stream_id))
        bits.append(zeck.encode_stream(wire_ints))
    return packed.pack("".join(bits), 8)


def demux(frame: bytes, registry: Dict[int, int]) -> Demuxed:
    """One concentrated frame -> ``([(stream_id, wire_ints)], status)``.

    ``registry`` maps stream id -> field count (from the stream's signed policy). On any
    structural failure the WHOLE datagram is rejected: ``([], status)``. The result is a `Demuxed`,
    which also carries the registry `cause` where one of the strict decode causes names the refusal."""
    bits = packed.unpack(frame)
    bit_count = len(bits)
    out: List[Tuple[int, List[int]]] = []

    def take_one(pos: int) -> Tuple[int, int]:
        """Decode one Fibonacci code starting at ``pos``; returns (value, next_pos).
        Returns (-1, -1) if no complete code exists at/after ``pos``."""
        bit_index = pos
        while bit_index < bit_count - 1:
            if bits[bit_index] == "1" and bits[bit_index + 1] == "1":
                return zeck.decode(bits[pos:bit_index + 2]), bit_index + 2
            bit_index += 1
        return -1, -1

    pos = 0
    while pos < bit_count:
        if bits.find("1", pos) < 0:                 # find, not a slice: demux stays linear in the datagram
            break                                   # trailing zero pad: the only legal tail
        sid, nxt = take_one(pos)
        if sid < 0:
            # a 1-bit tail with no terminator: no codeword at all in the datagram, or one left dangling
            return Demuxed([], CONCENTRATOR_TRUNCATED, _NO_TERMINATOR if pos == 0 else _DANGLING_CODEWORD)
        if sid not in registry:
            return Demuxed([], CONCENTRATOR_UNKNOWN_STREAM)
        wire_ints: List[int] = []
        pos = nxt
        for _ in range(registry[sid]):
            value, nxt = take_one(pos)
            if value < 0:
                # record cut mid-reading: dangling when data bits remain, padding (no cause) when only zeros do
                return Demuxed([], CONCENTRATOR_TRUNCATED, _DANGLING_CODEWORD if bits.find("1", pos) >= 0 else None)
            wire_ints.append(value)
            pos = nxt
        out.append((sid, wire_ints))
    return Demuxed(out, OK)
