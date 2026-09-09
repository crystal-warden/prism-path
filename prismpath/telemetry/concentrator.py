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
with a distinct cause (``concentrator-unknown-stream``, ``concentrator-truncated``) — never a
partial delivery, because a datagram that demuxes differently at two consumers is worse than a
lost one.

The registry mapping stream id to field count is derived from each stream's signed policy
(``len(build_partitions(policy))``) and agreed out of band exactly like the codebook itself.
"""
from __future__ import annotations

from typing import Dict, List, Tuple

from prismpath.telemetry import packed
from prismpath.telemetry import zeckendorf as z

CONCENTRATOR_UNKNOWN_STREAM = "concentrator-unknown-stream"
CONCENTRATOR_TRUNCATED = "concentrator-truncated"
OK = "ok"


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
        bits.append(z.encode(stream_id))
        bits.append(z.encode_stream(wire_ints))
    return packed.pack("".join(bits), 8)


def demux(frame: bytes, registry: Dict[int, int]) -> Tuple[List[Tuple[int, List[int]]], str]:
    """One concentrated frame -> ``([(stream_id, wire_ints)], cause)``.

    ``registry`` maps stream id -> field count (from the stream's signed policy). On any
    structural failure the WHOLE datagram is rejected: ``([], cause)``."""
    bits = packed.unpack(frame)
    n = len(bits)
    out: List[Tuple[int, List[int]]] = []

    def take_one(pos: int) -> Tuple[int, int]:
        """Decode one Fibonacci code starting at ``pos``; returns (value, next_pos).
        Returns (-1, -1) if no complete code exists at/after ``pos``."""
        i = pos
        while i < n - 1:
            if bits[i] == "1" and bits[i + 1] == "1":
                return z.decode(bits[pos:i + 2]), i + 2
            i += 1
        return -1, -1

    pos = 0
    while pos < n:
        if "1" not in bits[pos:]:
            break                                   # trailing zero pad: the only legal tail
        sid, nxt = take_one(pos)
        if sid < 0:
            return [], CONCENTRATOR_TRUNCATED       # a 1-bit tail with no terminator
        if sid not in registry:
            return [], CONCENTRATOR_UNKNOWN_STREAM
        wire_ints: List[int] = []
        pos = nxt
        for _ in range(registry[sid]):
            v, nxt = take_one(pos)
            if v < 0:
                return [], CONCENTRATOR_TRUNCATED   # record cut mid-reading
            wire_ints.append(v)
            pos = nxt
        out.append((sid, wire_ints))
    return out, OK
