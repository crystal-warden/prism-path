# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The state record (spec-policy-distribution.md, section 15.1): the byte string an enforcement point signs
with its instance key after every transition and as its heartbeat (H1 to H4, H9, H10).

`build` writes and signs one, `read` checks one against the instance public key it should be signed by and
raises `Refused` with `fleet:state-invalid` when it does not read or does not verify. Both sides of H1
live here so the PEP and the controller never disagree on an offset.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Optional, Tuple

from prismpath.distribution.kinds import Refused
from prismpath.kernel import causes

MAGIC = b"PPSR"
VERSION = 1
PAYLOAD_TYPE = "application/vnd.prismpath.dist-state"
INVALID = "fleet:state-invalid"
EVENTS = ("beat", "staged", "refused", "committed", "aborted", "trust-applied", "lapsed", "rolled-back",
          "provisioned", "held")
STATES = ("no-policy", "active", "locked")
STAGED_BIT, DEV_BUILD_BIT, HELD_BIT = 0x80, 0x40, 0x20
MAX_BODY, MAX_EXTENSIONS = 1024, 512
SIGNATURE_SIZE = 64
_HEAD = struct.Struct("<4sBBBB16sQQQ16s16s16sQQ16sQQ")    # bytes 0 to 143
_ZERO16 = b"\x00" * 16
assert _HEAD.size == 144


def prefix(hex_or_bytes) -> bytes:
    """The first 16 bytes of a SHA-256 given in hex, or zeros for none."""
    if not hex_or_bytes:
        return _ZERO16
    raw = bytes.fromhex(hex_or_bytes) if isinstance(hex_or_bytes, str) else bytes(hex_or_bytes)
    return raw[:16]


def stream_prefix(stream: str) -> bytes:
    return hashlib.sha256(stream.encode("utf-8")).digest()[:16]


def pep_id(instance_public: bytes) -> bytes:
    """H1: the PEP id is the first 16 bytes of SHA-256 of the instance public key."""
    return hashlib.sha256(bytes(instance_public)).digest()[:16]


@dataclass(frozen=True)
class StateRecord:
    """One state record, as its fields. Hashes are the 16 byte prefixes H1 carries."""
    event: str
    state: str
    cause: Optional[str]
    pep_id: bytes
    counter: int
    time: int
    stream: bytes
    active_policy: bytes = _ZERO16
    active_release: bytes = _ZERO16
    active_seq: int = 0
    floor: int = 0
    staged_release: bytes = _ZERO16
    staged_seq: int = 0
    trust_seq: int = 0
    epoch: int = 0
    staged: bool = False
    dev_build: bool = False
    held: bool = False
    body: bytes = b""
    extensions: bytes = b""

    @property
    def status(self) -> int:
        return (STATES.index(self.state) | (STAGED_BIT if self.staged else 0) | (DEV_BUILD_BIT if self.dev_build else 0)
                | (HELD_BIT if self.held else 0))

    def unsigned_bytes(self) -> bytes:
        """Bytes 0 to 148+m+x, the part the signature covers."""
        if len(self.body) > MAX_BODY or len(self.extensions) > MAX_EXTENSIONS:
            raise ValueError("a state record body or extension area beyond its bound")
        code = causes.code(self.cause) if self.cause else 0
        if code is None:
            raise ValueError(f"{self.cause!r} is not a registered cause")
        head = _HEAD.pack(MAGIC, VERSION, EVENTS.index(self.event), self.status, code, self.pep_id, self.counter,
                          self.time, self.epoch, self.stream, self.active_policy, self.active_release,
                          self.active_seq, self.floor, self.staged_release, self.staged_seq, self.trust_seq)
        return (head + struct.pack("<H", len(self.body)) + bytes(self.body)
                + struct.pack("<H", len(self.extensions)) + bytes(self.extensions))


def signed_message(unsigned: bytes) -> bytes:
    """H1: the instance key signs the DSSE encoding of the record's bytes with its own payload type."""
    from prismpath.ledgers.intoto import pae
    return pae(PAYLOAD_TYPE, unsigned)


def build(record: StateRecord, instance_key) -> bytes:
    """The signed record. `instance_key` is the PEP's `root_statement.InstanceKey` and no other (H2)."""
    unsigned = record.unsigned_bytes()
    return unsigned + instance_key.sign(signed_message(unsigned))


def _parse(data: bytes) -> Tuple[StateRecord, bytes, bytes]:
    if len(data) < _HEAD.size + 4 + SIGNATURE_SIZE:
        raise Refused(INVALID, "shorter than a state record")
    (magic, version, event, status, code, pep, counter, time, epoch, stream, active_policy, active_release,
     active_seq, floor, staged_release, staged_seq, trust_seq) = _HEAD.unpack_from(data)
    if magic != MAGIC or version != VERSION or event >= len(EVENTS) or (status & 0x1F) >= len(STATES):
        raise Refused(INVALID, "magic, version, event or state")
    if status & 0x1C:
        raise Refused(INVALID, "a status bit this version does not define")
    cause = causes.name(code) if code else None
    if code and cause is None:
        raise Refused(INVALID, "an unregistered cause")
    (m,) = struct.unpack_from("<H", data, _HEAD.size)
    if m > MAX_BODY or len(data) < _HEAD.size + 2 + m + 2 + SIGNATURE_SIZE:
        raise Refused(INVALID, "a body length")
    body = data[_HEAD.size + 2:_HEAD.size + 2 + m]
    (x,) = struct.unpack_from("<H", data, _HEAD.size + 2 + m)
    end = _HEAD.size + 4 + m + x
    if x > MAX_EXTENSIONS or len(data) != end + SIGNATURE_SIZE:
        raise Refused(INVALID, "an extension length or a record length")
    record = StateRecord(event=EVENTS[event], state=STATES[status & 0x03], cause=cause, pep_id=pep, counter=counter,
                         time=time, stream=stream, active_policy=active_policy, active_release=active_release,
                         active_seq=active_seq, floor=floor, staged_release=staged_release, staged_seq=staged_seq,
                         trust_seq=trust_seq, epoch=epoch, staged=bool(status & STAGED_BIT),
                         dev_build=bool(status & DEV_BUILD_BIT), held=bool(status & HELD_BIT), body=body,
                         extensions=data[_HEAD.size + 4 + m:end])
    return record, data[:end], data[end:]


def read(data: bytes, instance_public: bytes) -> StateRecord:
    """H1, H2, H6 step 1: the record in `data`, signed by the instance key whose 32 raw public bytes are
    `instance_public` and naming that key's PEP id. Anything else is `fleet:state-invalid`."""
    from prismpath.hotswap import policy_pack
    _priv, Public, _ser, InvalidSignature = policy_pack._ed25519()
    record, unsigned, signature = _parse(bytes(data))
    if record.pep_id != pep_id(instance_public):
        raise Refused(INVALID, "the record names another PEP")
    try:
        Public.from_public_bytes(bytes(instance_public)).verify(signature, signed_message(unsigned))
    except (InvalidSignature, ValueError):
        raise Refused(INVALID, "the signature does not verify under the instance key") from None
    return record
