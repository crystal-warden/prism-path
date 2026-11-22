# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The distribution envelope (spec-policy-distribution.md, section 4): the canon/2 document that names one
artifact body by hash, the bytes a signature covers, and the sealed envelope, one byte string on every
transport.

`build` writes an envelope and refuses one a reader would refuse. `read` is the reader of E1, E2, E5 and E8
and raises `Refused` with the registered cause. `seal` and `unseal` are the container of S2, and
`envelope_id` is E3. Nothing here decides whether an envelope is trusted. That is `verify.verify`.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, Iterable, List, Mapping, Optional, Sequence, Tuple

from prismpath import canon
from prismpath.distribution import kinds
from prismpath.distribution.kinds import BAD_FORMAT, MAX_SEQ, Refused, is_hex64, is_int, is_stream, load_canonical

FORMAT = "prismpath.dist/1"
DOMAIN = FORMAT.encode("ascii") + b"\x00"          # S1: the 17 bytes before the envelope bytes
MAGIC = b"PPDE"
CONTAINER_VERSION = 1
MAX_ENVELOPE = 2048                                # E6
MAX_ENTRIES = 4                                    # S2
MAX_BODY = 16777215                                # E1 body_size
TRUST_STREAM = "@trust"
ZERO_HASH = "0" * 64
KEY_ID_SIZE, SIGNATURE_SIZE = 32, 64
ENTRY_SIZE = KEY_ID_SIZE + SIGNATURE_SIZE
_HEADER = struct.Struct("<4sBH")                   # magic, container version, n

MEMBERS = frozenset({"artifact", "body_sha256", "body_size", "encoding", "expires", "format", "meta",
                     "not_before", "policy_sha256", "replaces", "seq", "stream", "targets", "widens"})


def _require(condition: bool, detail: str, cause: str = BAD_FORMAT) -> None:
    if not condition:
        raise Refused(cause, detail)


def key_id(public_raw: bytes) -> str:
    """K: the key id is the SHA-256 of the 32 raw public bytes, in lower case hex."""
    return canon.sha256_hex(bytes(public_raw))


def envelope_id(envelope_bytes: bytes) -> str:
    """E3: the SHA-256 of the envelope bytes. Signatures are not part of it."""
    return canon.sha256_hex(bytes(envelope_bytes))


@dataclass(frozen=True)
class Envelope:
    """A distribution envelope that `read` accepted, with the bytes it was read from."""
    artifact: str
    body_sha256: str
    body_size: int
    expires: int
    meta: Mapping[str, Any]
    not_before: int
    policy_sha256: str
    replaces: str
    seq: int
    stream: str
    targets: Tuple[str, ...]
    widens: bool
    raw: bytes

    @property
    def envelope_id(self) -> str:
        return envelope_id(self.raw)

    @property
    def is_trust(self) -> bool:
        return self.artifact in kinds.TRUST_ARTIFACTS


def _check_meta(artifact: str, meta: Any) -> None:
    """E1 meta: an object of the members section 3 lists for the artifact, strings and integers and one level
    of object."""
    _require(isinstance(meta, dict), "meta is not an object")
    required, optional = kinds.ARTIFACTS[artifact].meta_required, kinds.ARTIFACTS[artifact].meta_optional
    names = set(meta)
    _require(required <= names and names <= required | optional, f"meta members {sorted(names)} for {artifact}")

    def scalar(value: Any) -> bool:
        return isinstance(value, str) or is_int(value, -MAX_SEQ, MAX_SEQ)

    for value in meta.values():
        _require(scalar(value) or (isinstance(value, dict) and all(scalar(inner) for inner in value.values())),
                 "a meta value is not a string, an integer or one level of object")


def read(envelope_bytes: bytes) -> Envelope:
    """E1, E2, E5 and E8: the envelope in `envelope_bytes`, or `Refused` with `document:not-canonical` for
    canon/2 that is not its canonical spelling and `dist:bad-format` for anything else that is not the
    format."""
    raw = bytes(envelope_bytes)
    _require(0 < len(raw) <= MAX_ENVELOPE, f"an envelope of {len(raw)} bytes")
    doc = load_canonical(raw, "envelope")
    _require(isinstance(doc, dict), "the envelope is not an object")
    _require(set(doc) == MEMBERS, f"members {sorted(set(doc) ^ MEMBERS)} missing or extra")
    _require(doc["format"] == FORMAT and doc["encoding"] == canon.CANON2, "format or encoding")
    artifact = doc["artifact"]
    _require(artifact in kinds.ARTIFACTS, "an unknown artifact kind")                       # E8
    targets = doc["targets"]
    _require(isinstance(targets, list) and targets and all(target in kinds.TARGET_KINDS for target in targets),
             "targets empty or naming an unknown target kind")                             # E8
    _require(targets == sorted(set(targets)), "targets not sorted or repeated")
    _require(is_hex64(doc["body_sha256"]) and is_hex64(doc["policy_sha256"]), "a hash member")
    _require(doc["replaces"] == "" or is_hex64(doc["replaces"]), "replaces")
    _require(is_int(doc["body_size"], 0, MAX_BODY), "body_size")
    _require(is_int(doc["seq"], 1, MAX_SEQ), "seq")
    _require(is_int(doc["not_before"], 0, MAX_SEQ) and is_int(doc["expires"], 0, MAX_SEQ), "a time member")
    _require(isinstance(doc["widens"], bool), "widens")
    stream = doc["stream"]
    trust = artifact in kinds.TRUST_ARTIFACTS
    _require(is_stream(stream) or stream == TRUST_STREAM, "stream")
    _require(stream != TRUST_STREAM or doc["policy_sha256"] == ZERO_HASH, "a @trust envelope's policy_sha256 is 64 zeros")
    if trust:
        _require(doc["expires"] == 0, "a trust kind's expires is 0")                       # E5, X4
    else:
        _require(doc["expires"] > doc["not_before"], "expires is not above not_before")      # E5
    _check_meta(artifact, doc["meta"])
    return Envelope(artifact=artifact, body_sha256=doc["body_sha256"], body_size=doc["body_size"],
                    expires=doc["expires"], meta=doc["meta"], not_before=doc["not_before"],
                    policy_sha256=doc["policy_sha256"], replaces=doc["replaces"], seq=doc["seq"], stream=stream,
                    targets=tuple(targets), widens=doc["widens"], raw=raw)


def build(artifact: str, body: bytes, *, stream: str, seq: int, policy_sha256: str, targets: Sequence[str],
          not_before: int, expires: int, replaces: str = "", widens: bool = False,
          meta: Optional[Mapping[str, Any]] = None) -> bytes:
    """The canon/2 bytes of the envelope naming `body`. A writer refuses (`Refused`) every envelope `read`
    would refuse, so nothing it writes is unreadable."""
    body = bytes(body)
    doc = {"artifact": artifact, "body_sha256": canon.sha256_hex(body), "body_size": len(body),
           canon.ENCODING_KEY: canon.CANON2, "expires": expires, "format": FORMAT, "meta": dict(meta or {}),
           "not_before": not_before, "policy_sha256": policy_sha256, "replaces": replaces, "seq": seq,
           "stream": stream, "targets": sorted(targets), "widens": widens}
    try:
        raw = canon.canon2_bytes(doc)
    except canon.CanonicalError as error:
        raise Refused(BAD_FORMAT, f"the envelope has no canon/2 form ({error})") from None
    read(raw)
    return raw


def signed_message(envelope_bytes: bytes) -> bytes:
    """S1: what every signature covers, the domain and then the envelope bytes."""
    return DOMAIN + bytes(envelope_bytes)


def seal(envelope_bytes: bytes, signers: Iterable[Any]) -> bytes:
    """S2: the sealed envelope, `envelope_bytes` with one entry per signer (Ed25519 private keys), entries
    sorted by key id. Refuses no signer, more than four and a repeated key. A key is loaded with
    `policy_pack._load_private`, so no new private key format is read here."""
    from prismpath.hotswap import policy_pack
    _priv, _pub, ser, _invalid = policy_pack._ed25519()
    raw = bytes(envelope_bytes)
    _require(0 < len(raw) <= MAX_ENVELOPE, f"an envelope of {len(raw)} bytes")
    message = signed_message(raw)
    entries = []
    for private in signers:
        public_raw = private.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        entries.append((bytes.fromhex(key_id(public_raw)), private.sign(message)))
    entries.sort()
    _require(1 <= len(entries) <= MAX_ENTRIES, f"{len(entries)} signers")
    _require(len({entry[0] for entry in entries}) == len(entries), "a key signs twice")
    return seal_entries(raw, [(kid.hex(), signature) for kid, signature in entries])


def seal_entries(envelope_bytes: bytes, entries: Sequence[Tuple[str, bytes]]) -> bytes:
    """The S2 byte layout of `envelope_bytes` and `entries` as given, (key id hex, 64 byte signature), with no
    check. The writer's last step, and how a test writes a container `unseal` refuses."""
    out = [_HEADER.pack(MAGIC, CONTAINER_VERSION, len(envelope_bytes)), bytes(envelope_bytes), bytes([len(entries)])]
    out += [bytes.fromhex(kid) + bytes(signature) for kid, signature in entries]
    return b"".join(out)


def unseal(sealed: bytes) -> Tuple[bytes, List[Tuple[str, bytes]]]:
    """S2: (envelope bytes, [(key id hex, signature)]) of a sealed envelope. Any other length, magic or
    version, an unsorted or repeated key id, and zero or more than four entries are `dist:bad-format`."""
    _require(isinstance(sealed, (bytes, bytearray)), "a sealed envelope is bytes")
    data = bytes(sealed)
    _require(len(data) >= _HEADER.size + 1, "shorter than the header")
    magic, version, size = _HEADER.unpack_from(data)
    _require(magic == MAGIC and version == CONTAINER_VERSION, "magic or container version")
    _require(1 <= size <= MAX_ENVELOPE, f"an envelope length of {size}")
    _require(len(data) >= _HEADER.size + size + 1, "shorter than its envelope")
    count = data[_HEADER.size + size]
    _require(1 <= count <= MAX_ENTRIES, f"{count} entries")
    start = _HEADER.size + size + 1
    _require(len(data) == start + ENTRY_SIZE * count, "a length other than its entries")
    entries = []
    for index in range(count):
        entry = data[start + ENTRY_SIZE * index: start + ENTRY_SIZE * (index + 1)]
        entries.append((entry[:KEY_ID_SIZE].hex(), entry[KEY_ID_SIZE:]))
    ids = [kid for kid, _signature in entries]
    _require(ids == sorted(set(ids)), "entries unsorted or a key id repeated")
    return data[_HEADER.size:_HEADER.size + size], entries
