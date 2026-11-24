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
          "provisioned", "held", "fallback", "install-applied", "install-widened", "answered", "reconciling")
STATES = ("no-policy", "active", "locked", "reconciling")
RECONCILING_ENTRY = 4                              # H10, H14: the extension type of the reconciling entry
ENTRY_SIZE = 58
OWED = {"beat": 0, "committed": 3, "lapsed": 6, "rolled-back": 7, "fallback": 10, "install-applied": 11,
        "install-widened": 12}                     # H14: what a transition owes, 0 for none
STAGED_BIT, DEV_BUILD_BIT, HELD_BIT = 0x80, 0x40, 0x20
MAX_BODY, MAX_EXTENSIONS = 1024, 512
SIGNATURE_SIZE = 64
_HEAD = struct.Struct("<4sBBBB16sQQQ16s16s16sQQ16sQQ")    # bytes 0 to 143
_ZERO16 = b"\x00" * 16
assert _HEAD.size == 144


_ENTRY = struct.Struct("<BB16s16sQ16s")
assert _ENTRY.size == ENTRY_SIZE


@dataclass(frozen=True)
class ReconcilingEntry:
    """H14: the reconciling entry. `owed` is the event the transition owes (`beat` for none), `cause` the cause of
    the lapse owed or the one the running release fell for, then the running release's 16 byte prefixes and `seq`,
    and the set id prefix of the action floor the runtime holds, zeros for none."""
    owed: str = "beat"
    cause: Optional[str] = None
    running_policy: bytes = b"\x00" * 16
    running_release: bytes = b"\x00" * 16
    running_seq: int = 0
    floor: bytes = b"\x00" * 16

    def to_bytes(self) -> bytes:
        code = causes.code(self.cause) if self.cause else 0
        if code is None:
            raise ValueError(f"{self.cause!r} is not a registered cause")
        return _ENTRY.pack(OWED[self.owed], code, bytes(self.running_policy), bytes(self.running_release),
                           self.running_seq, bytes(self.floor))

    def extension(self) -> bytes:
        """The entry as one extension: its type, its length and its bytes (H10)."""
        return struct.pack("<BH", RECONCILING_ENTRY, ENTRY_SIZE) + self.to_bytes()

    @classmethod
    def from_bytes(cls, raw: bytes) -> "ReconcilingEntry":
        if len(raw) != ENTRY_SIZE:
            raise Refused(INVALID, f"a reconciling entry of {len(raw)} bytes")
        owed, code, policy, release, seq, floor = _ENTRY.unpack(bytes(raw))
        names = {value: name for name, value in OWED.items()}
        cause = causes.name(code) if code else None
        if owed not in names or (code and cause is None):
            raise Refused(INVALID, "a reconciling entry whose owed event or cause does not read")
        return cls(names[owed], cause, policy, release, seq, floor)


def extension_entries(run: bytes):
    """H10: the (type, bytes) of each entry of an extension area, or `Refused` with `fleet:state-invalid` when the
    run is cut short."""
    run, at, out = bytes(run), 0, []
    while at < len(run):
        if at + 3 > len(run):
            raise Refused(INVALID, "an extension entry cut short")
        kind, size = run[at], struct.unpack_from("<H", run, at + 1)[0]
        value = run[at + 3:at + 3 + size]
        if len(value) != size:
            raise Refused(INVALID, "an extension longer than the area")
        out.append((kind, value))
        at += 3 + size
    return out


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
    def reconciling(self) -> Optional[ReconcilingEntry]:
        """H14: the reconciling entry the record carries, or None."""
        for kind, value in extension_entries(self.extensions):
            if kind == RECONCILING_ENTRY:
                return ReconcilingEntry.from_bytes(value)
        return None

    @property
    def status(self) -> int:
        return (STATES.index(self.state) | (STAGED_BIT if self.staged else 0) | (DEV_BUILD_BIT if self.dev_build else 0)
                | (HELD_BIT if self.held else 0))

    def unsigned_bytes(self) -> bytes:
        """Bytes 0 to 148+m+x, the part the signature covers."""
        if self.event == "refused" and not self.cause:
            raise ValueError("a refused record carries the cause it was refused with")
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
    if magic != MAGIC or version != VERSION or event >= len(EVENTS) or (status & 0x03) >= len(STATES):
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
    state = status & 0x03
    record = StateRecord(event=EVENTS[event], state=STATES[state], cause=cause, pep_id=pep, counter=counter,
                         time=time, stream=stream, active_policy=active_policy, active_release=active_release,
                         active_seq=active_seq, floor=floor, staged_release=staged_release, staged_seq=staged_seq,
                         trust_seq=trust_seq, epoch=epoch, staged=bool(status & STAGED_BIT),
                         dev_build=bool(status & DEV_BUILD_BIT), held=bool(status & HELD_BIT), body=body,
                         extensions=data[_HEAD.size + 4 + m:end])
    return record, data[:end], data[end:]


def named_pep(data: bytes) -> bytes:
    """The PEP id a record names, read before its signature is checked, so a controller can find the enrolled
    key to check it with (H6 step 1). `Refused` with `fleet:state-invalid` when it does not read."""
    return _parse(bytes(data))[0].pep_id


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
    check_reconciling(record)
    return record


def check_reconciling(record: StateRecord) -> None:
    """H14: status 3 carries exactly one reconciling entry, status 0 and 1 carry none, no record carries two, and
    the entry reads. `Refused` with `fleet:state-invalid` otherwise (H6 step 1)."""
    entries = [value for kind, value in extension_entries(record.extensions) if kind == RECONCILING_ENTRY]
    if record.state == "reconciling" and len(entries) != 1:
        raise Refused(INVALID, "a reconciling record without exactly one reconciling entry")
    if record.state in ("no-policy", "active") and entries or len(entries) > 1:
        raise Refused(INVALID, "a reconciling entry under status no-policy or active, or more than one")
    for value in entries:
        ReconcilingEntry.from_bytes(value)
