# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The trust store of an enforcement point (spec-policy-distribution.md, section 5): the trusted keys with
their roles (K4), the retired key ids, what revocation has refused, the floors revocation raised, the
trust sequence, the threshold and the time floor (T1), and its durable file, a canon/2 document with format
`prismpath.dist-trust-store/1` (K1).

`counting` is S3 to S5, which entries of a sealed envelope count and the one cause when too few do. A store
that cannot be read refuses every envelope with `dist:unknown-key` (K1). The store changes only by provisioning,
a rotation and a revocation (K3). `apply_revocation` is the store after a verified revocation (R1 to R6),
`check_rotation` the rotation's own rules (O2 to O4) and `apply_rotation` the store after a verified rotation.
Nothing here verifies any other part of an envelope.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import Any, Dict, FrozenSet, Iterable, Mapping, Optional, Sequence, Tuple

from prismpath import canon
from prismpath.distribution import kinds
from prismpath.distribution.kinds import MAX_SEQ, Refused, Verdict, is_hex64, is_int, is_stream

FORMAT = "prismpath.dist-trust-store/1"
THRESHOLD = 1                                      # S6: the only threshold in this version
UNKNOWN_KEY, INVALID, REVOKED_KEY = "dist:unknown-key", "sig:invalid", "sig:revoked-key"
ROTATION_INVALID = "dist:rotation-invalid"
_ROLE = re.compile(r"[a-z][a-z0-9-]{0,31}")
_LISTS = ("revoked_envelopes", "revoked_keys", "revoked_policies")
MAX_KEYS, MAX_RETIRED = 8, 16                       # K5: the same bounds in every implementation
_MEMBERS = frozenset({"encoding", "floors", "format", "keys", "retired", "threshold", "time_floor", "trust_id",
                      "trust_seq", *_LISTS})


@dataclass(frozen=True)
class Key:
    """A key the store holds: its 32 raw public bytes and its role (K4). A key in a role this version does
    not know is kept and never counts."""
    public: bytes
    role: str = kinds.AUTHORITY


def _read_keys(keys, what: str) -> Dict[str, Key]:
    """The `keys` member of a trust store or an anchor: key id to `{public, role}`, each id its key's."""
    def require(condition: bool, detail: str) -> None:
        if not condition:
            raise Refused(kinds.BAD_FORMAT, f"{what} {detail}")

    require(isinstance(keys, dict), "keys")
    raw_keys: Dict[str, Key] = {}
    for kid, held in keys.items():
        require(isinstance(held, dict) and set(held) == {"public", "role"}, "a key entry")
        require(is_hex64(held["public"]), "a public key")
        require(isinstance(held["role"], str) and _ROLE.fullmatch(held["role"]) is not None, "a key role")
        public_raw = bytes.fromhex(held["public"])
        require(canon.sha256_hex(public_raw) == kid, "a key id that is not its key's")
        raw_keys[kid] = Key(public_raw, held["role"])
    return raw_keys


def _keys_document(keys: Mapping[str, "Key"]) -> dict:
    return {kid: {"public": key.public.hex(), "role": key.role} for kid, key in keys.items()}


@dataclass(frozen=True)
class TrustStore:
    """What an enforcement point holds about keys. `keys` maps a key id to its `Key`. The `revoked_*` sets are the
    latest revocation list, which holds every key id an earlier one held (R6), and `floors` the floor revocation
    raised for the PEP's stream. `retired` is the retired key ids, oldest first, at most 16, and `keys` holds at
    most 8 keys that are not retired (K5). A store whose file could not be read has `readable` False and counts
    nothing."""
    keys: Mapping[str, Key] = field(default_factory=dict)
    retired: Tuple[str, ...] = ()
    revoked_keys: FrozenSet[str] = frozenset()
    revoked_envelopes: FrozenSet[str] = frozenset()
    revoked_policies: FrozenSet[str] = frozenset()
    floors: Mapping[str, int] = field(default_factory=dict)
    trust_seq: int = 0
    trust_id: str = ""
    threshold: int = THRESHOLD
    time_floor: int = 0
    readable: bool = True
    path: Optional[str] = None

    def __post_init__(self):
        if not isinstance(self.retired, tuple):                       # a set given by a caller, in a stable order
            object.__setattr__(self, "retired", tuple(sorted(self.retired)))

    # ------------------------------------------------------------------ the durable file
    def document(self) -> dict:
        return {canon.ENCODING_KEY: canon.CANON2, "format": FORMAT, "floors": dict(self.floors),
                "keys": _keys_document(self.keys),
                "retired": list(self.retired), "revoked_envelopes": sorted(self.revoked_envelopes),
                "revoked_keys": sorted(self.revoked_keys), "revoked_policies": sorted(self.revoked_policies),
                "threshold": self.threshold, "time_floor": self.time_floor, "trust_id": self.trust_id,
                "trust_seq": self.trust_seq}

    def to_bytes(self) -> bytes:
        return canon.canon2_bytes(self.document())

    @classmethod
    def from_bytes(cls, raw: bytes, path: Optional[str] = None) -> "TrustStore":
        """The store in `raw`, or `Refused` (`dist:bad-format`, `document:not-canonical`) when it is not one."""
        doc = kinds.load_canonical(raw, "trust store")

        def require(condition: bool, detail: str) -> None:
            if not condition:
                raise Refused(kinds.BAD_FORMAT, f"trust store {detail}")

        require(isinstance(doc, dict) and set(doc) == _MEMBERS, "members")
        require(doc["format"] == FORMAT and doc["encoding"] == canon.CANON2, "format")
        require(doc["threshold"] == THRESHOLD, "threshold")
        require(all(is_int(doc[name], 0, MAX_SEQ) for name in ("time_floor", "trust_seq")), "an integer")
        require(doc["trust_id"] == "" or is_hex64(doc["trust_id"]), "trust_id")
        require(all(isinstance(doc[name], list) and all(is_hex64(item) for item in doc[name])
                    and doc[name] == sorted(set(doc[name])) for name in _LISTS), "a key or hash list")
        require(isinstance(doc["floors"], dict) and all(is_stream(stream) and is_int(seq, 1, MAX_SEQ)
                                                        for stream, seq in doc["floors"].items()), "floors")
        retired = doc["retired"]
        require(isinstance(retired, list) and all(is_hex64(item) for item in retired) and len(set(retired)) == len(retired)
                and len(retired) <= MAX_RETIRED and set(retired) <= set(doc["keys"]), "retired")
        require(len(set(doc["keys"]) - set(retired)) <= MAX_KEYS, "keys beyond the bound")
        return cls(keys=_read_keys(doc["keys"], "trust store"), retired=tuple(retired), revoked_keys=frozenset(doc["revoked_keys"]),
                   revoked_envelopes=frozenset(doc["revoked_envelopes"]),
                   revoked_policies=frozenset(doc["revoked_policies"]), floors=dict(doc["floors"]),
                   trust_seq=doc["trust_seq"], trust_id=doc["trust_id"], threshold=doc["threshold"],
                   time_floor=doc["time_floor"], path=path)

    @classmethod
    def load(cls, path: str) -> "TrustStore":
        """The store at `path`. A missing, unreadable or malformed file is a store that counts nothing (K1),
        never an empty store that a provisioning step could be skipped into."""
        try:
            with open(path, "rb") as handle:
                return cls.from_bytes(handle.read(), path=path)
        except (OSError, Refused):
            return cls(readable=False, path=path)

    def save(self, path: Optional[str] = None) -> "TrustStore":
        """Write the store durably (the old file or the new one, never a torn one) and return it with its
        path. An unreadable store is never written over a file."""
        target = path or self.path
        if not self.readable:
            raise ValueError("an unreadable trust store is not saved; provision the enforcement point again")
        if target is None:
            raise ValueError("a trust store needs a path to be saved")
        canon.atomic_write_bytes(target, self.to_bytes())
        return replace(self, path=target)

    @classmethod
    def with_keys(cls, public_keys: Sequence[bytes], role: str = kinds.AUTHORITY, **members) -> "TrustStore":
        """A store holding `public_keys` (32 raw bytes each) in `role`, for provisioning and tests."""
        return cls(keys={canon.sha256_hex(bytes(raw)): Key(bytes(raw), role) for raw in public_keys}, **members)

    # ------------------------------------------------------------------ R1 to R7: revocation
    def check_revocation(self, body: bytes) -> Optional[str]:
        """R6 for a revocation list that already reads (V11): it holds every key id the current list holds, since a
        key once revoked stays revoked. None, or `dist:trust-replay`."""
        listed = kinds.read_revocation(body)
        return None if self.revoked_keys <= frozenset(listed["keys"]) else "dist:trust-replay"

    def apply_revocation(self, envelope, body: bytes, stream: Optional[str] = None) -> "TrustStore":
        """The store after a verified `trust.revocation` (`envelope`, already through V2 to V11, so its `seq` is the
        trust sequence plus one, R1, and it drops no key, R6). The PEP holds this list and no other, so what it
        refuses is bounded by R7 (R2, R6). A floor it raises is kept for `stream`, the PEP's own, and only rises
        (R4). The caller makes the result durable before it reports it (R3)."""
        if envelope.artifact != "trust.revocation" or envelope.seq != self.trust_seq + 1:
            raise ValueError("only a verified revocation at the next trust sequence is applied (R1)")
        if self.check_revocation(body) is not None:
            raise ValueError("a revocation list that drops a revoked key is never applied (R6)")
        listed = kinds.read_revocation(body)
        floors = {name: seq for name, seq in self.floors.items() if stream is None or name == stream}
        for name, seq in listed["floors"].items():
            if stream is None or name == stream:
                floors[name] = max(floors.get(name, 0), seq)
        return replace(self, revoked_keys=frozenset(listed["keys"]), revoked_envelopes=frozenset(listed["envelopes"]),
                       revoked_policies=frozenset(listed["policies"]), floors=floors, trust_seq=envelope.seq,
                       trust_id=envelope.envelope_id)

    def holds_up(self, entries: Sequence[Tuple[str, bytes]], message: bytes, role: str = kinds.AUTHORITY) -> bool:
        """R5, O3: an entry by a key the store holds in `role`, not revoked, verifies. A retired key still holds up
        a release already active under it, where it no longer counts for a new envelope (S5)."""
        from prismpath.hotswap import policy_pack
        _priv, Public, _ser, InvalidSignature = policy_pack._ed25519()
        for kid, signature in entries:
            key = self.keys.get(kid)
            if key is None or key.role != role or kid in self.revoked_keys:
                continue
            try:
                Public.from_public_bytes(key.public).verify(signature, message)
                return True
            except InvalidSignature:
                continue
        return False

    # ------------------------------------------------------------------ O1 to O4: rotation
    def check_rotation(self, body: bytes, entries: Sequence[Tuple[str, bytes]], message: bytes,
                       instance_key_id: Optional[str] = None) -> Optional[str]:
        """O2 to O4 for a rotation whose envelope already counts under this store (V3) and reads (V11): the key in
        `add` signs it too, so it is signed under the store it leaves as well, `add` is neither the PEP's own
        instance key, a revoked key nor a key the store retired, since a retired key does not come back, and
        `retire` names a key the store holds. None, or `dist:rotation-invalid`."""
        from prismpath.hotswap import policy_pack
        _priv, Public, _ser, InvalidSignature = policy_pack._ed25519()
        doc = kinds.read_rotation(body)
        added = bytes.fromhex(doc["add"])
        added_id = canon.sha256_hex(added)
        if added_id == instance_key_id or added_id in self.revoked_keys or added_id in self.retired:
            return ROTATION_INVALID                                  # O4
        if doc["retire"] and doc["retire"] not in self.keys:
            return ROTATION_INVALID                                  # O3
        live = {kid for kid in self.keys if kid not in self.retired} | {added_id}
        if doc["retire"]:
            live.discard(doc["retire"])
        if len(live) > MAX_KEYS:
            return "dist:too-large"                                  # K5: a ninth key
        for kid, signature in entries:
            if kid == added_id:
                try:
                    Public.from_public_bytes(added).verify(signature, message)
                    return None                                      # O2
                except (InvalidSignature, ValueError):
                    break
        return ROTATION_INVALID

    def apply_rotation(self, envelope, body: bytes) -> "TrustStore":
        """The store after a verified `trust.rotation` at the next trust sequence (O1): the new key is held in the
        authority role and the retired one no longer counts (O3), though a release already active under it stays.
        A seventeenth retired id forgets the oldest, and its key with it (K5)."""
        if envelope.artifact != "trust.rotation" or envelope.seq != self.trust_seq + 1:
            raise ValueError("only a verified rotation at the next trust sequence is applied (O1)")
        doc = kinds.read_rotation(body)
        added = bytes.fromhex(doc["add"])
        keys = {**self.keys, canon.sha256_hex(added): Key(added, kinds.AUTHORITY)}
        retired = list(self.retired)
        if doc["retire"] and doc["retire"] not in retired:
            retired.append(doc["retire"])
        while len(retired) > MAX_RETIRED:                            # K5: the oldest retired id is forgotten, and
            keys.pop(retired.pop(0), None)                           # its signature then reads as an unknown key's
        return replace(self, keys=keys, retired=tuple(retired), trust_seq=envelope.seq,
                       trust_id=envelope.envelope_id)

    # ------------------------------------------------------------------ S3 to S5
    def counting(self, entries: Sequence[Tuple[str, bytes]], message: bytes, role: str = kinds.AUTHORITY) -> Verdict:
        """S3 to S5. An entry counts when its key id names a key the store holds in `role`, that key is neither
        revoked nor retired, and its signature over `message` verifies. Any other entry is skipped, as DSSE
        skips it, and a key id only finds the key. The envelope is signed when at least the threshold count.
        Otherwise the one cause is `sig:revoked-key` when an entry verifies under a revoked or retired key,
        `sig:invalid` when an entry names a held key and does not verify, and `dist:unknown-key` otherwise."""
        if not self.readable:
            return Verdict(UNKNOWN_KEY)
        from prismpath.hotswap import policy_pack
        _priv, Public, _ser, InvalidSignature = policy_pack._ed25519()
        counting, revoked_verifies, held_fails = 0, False, False
        for kid, signature in entries:
            key = self.keys.get(kid)
            if key is None:
                continue
            try:
                Public.from_public_bytes(key.public).verify(signature, message)
            except InvalidSignature:
                held_fails = True
                continue
            if kid in self.retired or kid in self.revoked_keys:
                revoked_verifies = True
            elif key.role == role:
                counting += 1
        if counting >= self.threshold:
            return Verdict(None)
        if revoked_verifies:
            return Verdict(REVOKED_KEY)
        return Verdict(INVALID if held_fails else UNKNOWN_KEY)


# ------------------------------------------------------------------ the trust anchor (P2, P3)

def check_drops(body: bytes, earlier: Sequence[bytes], held: Iterable[Any]) -> None:
    """R8, what the sealing tool and a controller check before they write or store the revocation list `body`,
    since a PEP cannot (R6). `earlier` is the bodies of the lists before it, oldest first, and `held` the
    envelopes the caller holds (`envelope.Envelope`). Against the latest earlier list, the new one keeps every
    key, and every envelope id or policy hash it drops is shown to be below a floor this list or an earlier one
    raised: each envelope of it the caller holds has a `seq` below its stream's floor, and the caller holds at
    least one. Raises `Refused` with `dist:trust-replay` and the entry it cannot place."""
    new = kinds.read_revocation(body)
    if not earlier:
        return
    lists = [kinds.read_revocation(raw) for raw in earlier]
    floors: Dict[str, int] = {}
    for listed in lists + [new]:
        for stream, seq in listed["floors"].items():
            floors[stream] = max(floors.get(stream, 0), seq)
    previous = lists[-1]
    dropped_keys = set(previous["keys"]) - set(new["keys"])
    if dropped_keys:
        raise Refused("dist:trust-replay", f"the list drops the revoked key {sorted(dropped_keys)[0]} (R6, R8)")
    held = list(held)

    def passed(envelopes) -> bool:
        return bool(envelopes) and all(one.seq < floors.get(one.stream, 0) for one in envelopes)

    for envelope_id in sorted(set(previous["envelopes"]) - set(new["envelopes"])):
        if not passed([one for one in held if one.envelope_id == envelope_id]):
            raise Refused("dist:trust-replay", f"the list drops the envelope {envelope_id}, which no floor has passed (R8)")
    for policy in sorted(set(previous["policies"]) - set(new["policies"])):
        if not passed([one for one in held if one.policy_sha256 == policy]):
            raise Refused("dist:trust-replay", f"the list drops the policy {policy}, which no floor has passed (R8)")


ANCHOR_FORMAT = "prismpath.dist-trust/1"
_ANCHOR_MEMBERS = frozenset({"encoding", "format", "keys", "stream", "target", "threshold"})


@dataclass(frozen=True)
class Anchor:
    """A trust anchor (P2 step 3): the keys with their roles, the threshold, the PEP's target kind and its
    stream. `fingerprint` is the SHA-256 of its bytes, which the operator compares (P2 step 4)."""
    keys: Mapping[str, Key]
    threshold: int
    target: str
    stream: str
    fingerprint: str

    def store(self) -> TrustStore:
        """P3: the trust store an anchor provisions, with the trust sequence and time floor at their start."""
        return TrustStore(keys=dict(self.keys), threshold=self.threshold)


def anchor_bytes(public_keys: Sequence[bytes], *, target: str, stream: str, role: str = kinds.AUTHORITY) -> bytes:
    """The canon/2 bytes of an anchor trusting `public_keys` (32 raw bytes each) in `role`. The owner's tool."""
    keys = {canon.sha256_hex(bytes(raw)): Key(bytes(raw), role) for raw in public_keys}
    raw = canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": ANCHOR_FORMAT, "keys": _keys_document(keys),
                              "stream": stream, "target": target, "threshold": THRESHOLD})
    read_anchor(raw)
    return raw


def read_anchor(raw: bytes) -> Anchor:
    """The anchor in `raw`, or `Refused` (`dist:bad-format`, `document:not-canonical`)."""
    doc = kinds.load_canonical(raw, "trust anchor")
    if not (isinstance(doc, dict) and set(doc) == _ANCHOR_MEMBERS and doc["format"] == ANCHOR_FORMAT
            and doc["encoding"] == canon.CANON2 and doc["threshold"] == THRESHOLD
            and doc["target"] in kinds.TARGET_KINDS and is_stream(doc["stream"])):
        raise Refused(kinds.BAD_FORMAT, "not a trust anchor")
    keys = _read_keys(doc["keys"], "trust anchor")
    if not keys:
        raise Refused(kinds.BAD_FORMAT, "a trust anchor with no key")
    return Anchor(keys=keys, threshold=doc["threshold"], target=doc["target"], stream=doc["stream"],
                  fingerprint=canon.sha256_hex(bytes(raw)))
