# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The controller statement (spec-policy-distribution.md, H9 and H16): the one thing the controller key signs.

A statement names the present on one stream with an epoch id, and with `fresh` 1 it also carries the end of the
controller's trust chain, the highest `seq` the controller holds on the stream and when the statement stops
counting for freshness. It is 102 bytes, or 126 with the freshness fields, and it is signed by the controller's
instance key over the DSSE pre-authentication encoding of the bytes before the signature, with its own payload
type. Integers are little endian.

`build` writes and signs one, `parse` reads one without checking its signature (`Refused` with `dist:bad-format`
when it does not read), and `verify` answers the statement only when it reads and its signature verifies under the
public key given. Whether a PEP takes what a statement says is the PEP's (`pep.Pep.take_statement`).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional, Tuple

from prismpath.distribution import kinds
from prismpath.distribution.kinds import Refused

MAGIC = b"PPEP"
VERSION = 1
PAYLOAD_TYPE = "application/vnd.prismpath.dist-epoch"
SIGNATURE_SIZE = 64
_HEAD = struct.Struct("<4sBQ16sQB")                # magic, version, key seq, stream prefix, epoch id, fresh
_FRESH = struct.Struct("<QQQ")                     # trust seq, stream seq, expires
SIZE, FRESH_SIZE = _HEAD.size + SIGNATURE_SIZE, _HEAD.size + _FRESH.size + SIGNATURE_SIZE
assert (SIZE, FRESH_SIZE) == (102, 126)
U64 = 2 ** 64 - 1


@dataclass(frozen=True)
class Statement:
    """One controller statement. `stream` is the 16 byte prefix of SHA-256 of the stream name. The three
    freshness fields are 0 when `fresh` is false."""
    key_seq: int
    stream: bytes
    epoch: int
    fresh: bool = False
    trust_seq: int = 0
    stream_seq: int = 0
    expires: int = 0

    def unsigned_bytes(self) -> bytes:
        if not all(kinds.is_int(value, 0, U64) for value in (self.key_seq, self.epoch, self.trust_seq,
                                                             self.stream_seq, self.expires)):
            raise ValueError("a controller statement's numbers are 0 to 2^64 - 1")
        if len(self.stream) != 16:
            raise ValueError("a controller statement names its stream by a 16 byte prefix")
        head = _HEAD.pack(MAGIC, VERSION, self.key_seq, bytes(self.stream), self.epoch, 1 if self.fresh else 0)
        return head + (_FRESH.pack(self.trust_seq, self.stream_seq, self.expires) if self.fresh else b"")


def signed_message(unsigned: bytes) -> bytes:
    """H9: the controller key signs the DSSE encoding of the statement's bytes with its own payload type."""
    from prismpath.ledgers.intoto import pae
    return pae(PAYLOAD_TYPE, unsigned)


def build(statement: Statement, controller_key) -> bytes:
    """The signed statement. `controller_key` is the controller's `root_statement.InstanceKey` (K6, F5)."""
    unsigned = statement.unsigned_bytes()
    return unsigned + controller_key.sign(signed_message(unsigned))


def parse(data: bytes) -> Tuple[Statement, bytes, bytes]:
    """(statement, the signed bytes, the signature), or `Refused` with `dist:bad-format`: another length, magic,
    version or `fresh` byte, or freshness fields on a statement whose `fresh` is 0."""
    data = bytes(data)
    if len(data) not in (SIZE, FRESH_SIZE) or len(data) < _HEAD.size:
        raise Refused(kinds.BAD_FORMAT, f"a controller statement of {len(data)} bytes")
    magic, version, key_seq, stream, epoch, fresh = _HEAD.unpack_from(data)
    if magic != MAGIC or version != VERSION or fresh not in (0, 1) or len(data) != (FRESH_SIZE if fresh else SIZE):
        raise Refused(kinds.BAD_FORMAT, "a controller statement's magic, version, fresh byte or length")
    trust_seq = stream_seq = expires = 0
    if fresh:
        trust_seq, stream_seq, expires = _FRESH.unpack_from(data, _HEAD.size)
    end = len(data) - SIGNATURE_SIZE
    return (Statement(key_seq, stream, epoch, bool(fresh), trust_seq, stream_seq, expires), data[:end], data[end:])


def verify(data: bytes, controller_public: Optional[bytes]) -> Optional[Statement]:
    """The statement in `data` when it reads and its signature verifies under `controller_public`, the 32 raw
    bytes of the controller key, else None. A statement with no key to check it against is None (K6)."""
    if controller_public is None:
        return None
    try:
        statement, unsigned, signature = parse(data)
    except Refused:
        return None
    from prismpath.onion import keys
    if not keys.verify(bytes(controller_public), signature, signed_message(unsigned)):
        return None
    return statement
