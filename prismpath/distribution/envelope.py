# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The distribution envelope (spec-policy-distribution.md, section 4): the canon/2 document that names one
artifact body by hash, the bytes a signature covers, and the sealed envelope, one byte string on every
transport.

`build` writes an envelope and refuses one a reader would refuse. `read` is the reader of E1, E2, E5 and E8
and raises `Refused` with the registered cause. `release_id` is E10 and `envelope_id` E3. `signed_message`
is the DSSE pre-authentication encoding a signature covers (S1). `seal` and `unseal` are the container of
S2, signatures first, and `to_dsse` and `from_dsse` its lossless map to a DSSE JSON envelope (S7). Nothing
here decides whether an envelope is trusted. That is `verify.verify`.
"""
from __future__ import annotations

import base64
import binascii
import struct
from dataclasses import dataclass
from typing import Any, Iterable, List, Mapping, Optional, Sequence, Tuple

from prismpath import canon
from prismpath.distribution import kinds
from prismpath.distribution.kinds import BAD_FORMAT, MAX_SEQ, Refused, is_hex64, is_int, is_stream, load_canonical

FORMAT = "prismpath.dist/1"
PAYLOAD_TYPE = "application/vnd.prismpath.dist+json"   # S1, S7
MAGIC = b"PPDE"
CONTAINER_VERSION = 1
MAX_ENVELOPE = 2048                                # E6
MAX_ENTRIES = 4                                    # S2
MAX_BODY = 16777215                                # E1 body_size
TRUST_STREAM = "@trust"
ZERO_HASH = "0" * 64
KEY_ID_SIZE, SIGNATURE_SIZE = 32, 64
ENTRY_SIZE = KEY_ID_SIZE + SIGNATURE_SIZE
_HEADER = struct.Struct("<4sBB")                   # magic, container version, k
_LENGTH = struct.Struct("<H")                      # n, after the k entries
MAX_SEALED = _HEADER.size + ENTRY_SIZE * MAX_ENTRIES + _LENGTH.size + MAX_ENVELOPE   # 2,440 bytes (B9)

MEMBERS = frozenset({"artifact", "body_sha256", "body_size", "encoding", "expires", "format", "meta",
                     "not_before", "policy_sha256", "release", "replaces", "seq", "stream", "targets", "widens"})


def _require(condition: bool, detail: str, cause: str = BAD_FORMAT) -> None:
    if not condition:
        raise Refused(cause, detail)


def key_id(public_raw: bytes) -> str:
    """K: the key id is the SHA-256 of the 32 raw public bytes, in lower case hex."""
    return canon.sha256_hex(bytes(public_raw))


def release_id(artifacts: Iterable[Tuple[str, str]]) -> str:
    """E10: the SHA-256 of the canon/2 bytes of the sorted `[artifact, body_sha256]` pairs of every artifact in
    the release. The signer computes it over the whole release. A trust kind is never one of them: a
    `trust.widening` envelope binds to its release by carrying the same `release` (E7)."""
    pairs = sorted([artifact, body_sha256] for artifact, body_sha256 in artifacts)
    _require(bool(pairs) and len({pair[0] for pair in pairs}) == len(pairs), "a release names each artifact once")
    _require(all(artifact in kinds.ARTIFACTS and artifact not in kinds.TRUST_ARTIFACTS for artifact, _ in pairs),
             "a release id names only artifact kinds that are not trust kinds")
    _require(all(is_hex64(body_sha256) for _, body_sha256 in pairs), "a body hash in a release id")
    return canon.sha256_hex(canon.canon2_bytes(pairs))


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
    release: str
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
    """E1, E11: an object of exactly the members section 3 lists for the artifact, each of the form the kind
    table gives it, so no check that reads a signed member has to guess its type."""
    _require(isinstance(meta, dict), "meta is not an object")
    required, optional = kinds.ARTIFACTS[artifact].meta_required, kinds.ARTIFACTS[artifact].meta_optional
    names = set(meta)
    _require(required <= names and names <= required | optional, f"meta members {sorted(names)} for {artifact}")
    for name, value in meta.items():
        _require(kinds.FORMS[name](value), f"meta {name} is not of its form")


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
    _require(all(is_hex64(doc[name]) for name in ("body_sha256", "policy_sha256", "release")), "a hash member")
    _require(doc["replaces"] == "" or is_hex64(doc["replaces"]), "replaces")
    _require(is_int(doc["body_size"], 0, MAX_BODY), "body_size")
    _require(is_int(doc["seq"], 1, MAX_SEQ), "seq")
    _require(is_int(doc["not_before"], 0, MAX_SEQ) and is_int(doc["expires"], 0, MAX_SEQ), "a time member")
    _require(isinstance(doc["widens"], bool), "widens")
    stream = doc["stream"]
    trust = artifact in kinds.TRUST_ARTIFACTS
    _require(is_stream(stream) or stream == TRUST_STREAM, "stream")
    _require(stream != TRUST_STREAM or doc["policy_sha256"] == doc["release"] == ZERO_HASH,
             "a @trust envelope's policy_sha256 and release are 64 zeros")
    if trust:
        _require(doc["expires"] == 0, "a trust kind's expires is 0")                       # E5, X4
    else:
        _require(doc["expires"] > doc["not_before"], "expires is not above not_before")      # E5
    _check_meta(artifact, doc["meta"])
    return Envelope(artifact=artifact, body_sha256=doc["body_sha256"], body_size=doc["body_size"],
                    expires=doc["expires"], meta=doc["meta"], not_before=doc["not_before"],
                    policy_sha256=doc["policy_sha256"], release=doc["release"], replaces=doc["replaces"], seq=doc["seq"], stream=stream,
                    targets=tuple(targets), widens=doc["widens"], raw=raw)


def build(artifact: str, body: bytes, *, stream: str, seq: int, policy_sha256: str, release: str,
          targets: Sequence[str], not_before: int, expires: int, replaces: str = "", widens: bool = False,
          meta: Optional[Mapping[str, Any]] = None) -> bytes:
    """The canon/2 bytes of the envelope naming `body`, in the release `release` (`release_id`, or 64 zeros on
    `@trust`). A writer refuses (`Refused`) every envelope `read` would refuse, so nothing it writes is
    unreadable."""
    body = bytes(body)
    doc = {"artifact": artifact, "body_sha256": canon.sha256_hex(body), "body_size": len(body),
           canon.ENCODING_KEY: canon.CANON2, "expires": expires, "format": FORMAT, "meta": dict(meta or {}),
           "not_before": not_before, "policy_sha256": policy_sha256, "release": release, "replaces": replaces, "seq": seq,
           "stream": stream, "targets": sorted(targets), "widens": widens}
    try:
        raw = canon.canon2_bytes(doc)
    except canon.CanonicalError as error:
        raise Refused(BAD_FORMAT, f"the envelope has no canon/2 form ({error})") from None
    read(raw)
    return raw


def signed_message(envelope_bytes: bytes) -> bytes:
    """S1: what every signature covers, the DSSE pre-authentication encoding of the envelope bytes with the
    payload type `application/vnd.prismpath.dist+json` (`intoto.pae`)."""
    from prismpath.ledgers.intoto import pae
    return pae(PAYLOAD_TYPE, bytes(envelope_bytes))


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
    """The S2 byte layout of `entries` as given, (key id hex, 64 byte signature), then `envelope_bytes`, with no
    check. The writer's last step, and how a test writes a container `unseal` refuses."""
    out = [_HEADER.pack(MAGIC, CONTAINER_VERSION, len(entries))]
    out += [bytes.fromhex(kid) + bytes(signature) for kid, signature in entries]
    out += [_LENGTH.pack(len(envelope_bytes)), bytes(envelope_bytes)]
    return b"".join(out)


def unseal(sealed: bytes) -> Tuple[bytes, List[Tuple[str, bytes]]]:
    """S2: (envelope bytes, [(key id hex, signature)]) of a sealed envelope. Any other length, magic or
    version, an unsorted or repeated key id, zero or more than four entries and an envelope length outside
    1 to 2048 are `dist:bad-format`. Nothing past 2,440 bytes is read (B9)."""
    _require(isinstance(sealed, (bytes, bytearray)), "a sealed envelope is bytes")
    data = bytes(sealed)
    _require(_HEADER.size <= len(data) <= MAX_SEALED, f"a sealed envelope of {len(data)} bytes")
    magic, version, count = _HEADER.unpack_from(data)
    _require(magic == MAGIC and version == CONTAINER_VERSION, "magic or container version")
    _require(1 <= count <= MAX_ENTRIES, f"{count} entries")
    start = _HEADER.size + ENTRY_SIZE * count
    _require(len(data) >= start + _LENGTH.size, "shorter than its entries")
    (size,) = _LENGTH.unpack_from(data, start)
    _require(1 <= size <= MAX_ENVELOPE, f"an envelope length of {size}")
    _require(len(data) == start + _LENGTH.size + size, "a length other than its envelope")
    entries = []
    for index in range(count):
        entry = data[_HEADER.size + ENTRY_SIZE * index: _HEADER.size + ENTRY_SIZE * (index + 1)]
        entries.append((entry[:KEY_ID_SIZE].hex(), entry[KEY_ID_SIZE:]))
    ids = [kid for kid, _signature in entries]
    _require(ids == sorted(set(ids)), "entries unsorted or a key id repeated")
    return data[start + _LENGTH.size:], entries


def to_dsse(sealed: bytes) -> dict:
    """S7: the DSSE JSON envelope of a sealed envelope. `payload` is the envelope bytes in base64,
    `payloadType` the one S1 signs, and each entry a `signatures` member with `keyid` in hex and `sig` in
    base64. Any DSSE verifier that holds the authority public key can check it."""
    envelope_bytes, entries = unseal(sealed)
    return {"payload": base64.b64encode(envelope_bytes).decode("ascii"), "payloadType": PAYLOAD_TYPE,
            "signatures": [{"keyid": kid, "sig": base64.b64encode(signature).decode("ascii")}
                           for kid, signature in entries]}


def _b64decode(text: Any) -> bytes:
    """DSSE base64, standard or URL safe (one alphabet per string), padded or not."""
    if not isinstance(text, str) or ("+" in text or "/" in text) and ("-" in text or "_" in text):
        raise ValueError("base64 that is not one alphabet")
    standard = text.replace("-", "+").replace("_", "/")
    return base64.b64decode(standard + "=" * (-len(standard) % 4), validate=True)


def from_dsse(doc: Mapping[str, Any]) -> bytes:
    """S7: the sealed envelope a DSSE JSON envelope maps back to. Its base64 may be standard or URL safe, as
    DSSE allows. The signature order of DSSE carries no meaning, so the entries are sorted by key id. Anything `unseal` would refuse is `dist:bad-format`."""
    _require(isinstance(doc, Mapping) and set(doc) == {"payload", "payloadType", "signatures"}, "DSSE members")
    _require(doc["payloadType"] == PAYLOAD_TYPE, "DSSE payloadType")
    signatures = doc["signatures"]
    _require(isinstance(signatures, list), "DSSE signatures")
    try:
        envelope_bytes = _b64decode(doc["payload"])
        entries = []
        for member in signatures:
            _require(isinstance(member, Mapping) and set(member) == {"keyid", "sig"} and is_hex64(member["keyid"]),
                     "a DSSE signature member")
            signature = _b64decode(member["sig"])
            _require(len(signature) == SIGNATURE_SIZE, "a DSSE signature length")
            entries.append((member["keyid"], signature))
    except (binascii.Error, TypeError, ValueError):
        raise Refused(BAD_FORMAT, "DSSE base64") from None
    _require(1 <= len(envelope_bytes) <= MAX_ENVELOPE and 1 <= len(entries) <= MAX_ENTRIES, "DSSE sizes")
    sealed = seal_entries(envelope_bytes, sorted(entries))
    unseal(sealed)
    return sealed
