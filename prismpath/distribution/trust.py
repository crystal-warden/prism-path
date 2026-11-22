# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The trust store of an enforcement point (spec-policy-distribution.md, section 5): the trusted keys with
their roles (K4), the retired key ids, what revocation has refused, the floors revocation raised, the
trust sequence, the threshold and the time floor (T1), and its durable file, a canon/2 document with format
`prismpath.dist-trust-store/1` (K1).

`counting` is S3 to S5, which entries of a sealed envelope count and the one cause when too few do. A store
that cannot be read refuses every envelope with `dist:unknown-key` (K1). The store changes only by provisioning, a rotation and a revocation
(K3), applied by the code that owns them. Nothing here verifies any other part of an envelope.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import Dict, FrozenSet, Mapping, Optional, Sequence, Tuple

from prismpath import canon
from prismpath.distribution import kinds
from prismpath.distribution.kinds import MAX_SEQ, Refused, Verdict, is_hex64, is_int, is_stream

FORMAT = "prismpath.dist-trust-store/1"
THRESHOLD = 1                                      # S6: the only threshold in this version
UNKNOWN_KEY, INVALID, REVOKED_KEY = "dist:unknown-key", "sig:invalid", "sig:revoked-key"
_ROLE = re.compile(r"[a-z][a-z0-9-]{0,31}")
_LISTS = ("retired", "revoked_envelopes", "revoked_keys", "revoked_policies")
_MEMBERS = frozenset({"encoding", "floors", "format", "keys", "threshold", "time_floor", "trust_id",
                      "trust_seq", *_LISTS})


@dataclass(frozen=True)
class Key:
    """A key the store holds: its 32 raw public bytes and its role (K4). A key in a role this version does
    not know is kept and never counts."""
    public: bytes
    role: str = kinds.AUTHORITY


@dataclass(frozen=True)
class TrustStore:
    """What an enforcement point holds about keys. `keys` maps a key id to its `Key`. The `revoked_*` sets and `floors` are cumulative (R6): a later list never removes one. A store
    whose file could not be read has `readable` False and counts nothing."""
    keys: Mapping[str, Key] = field(default_factory=dict)
    retired: FrozenSet[str] = frozenset()
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

    # ------------------------------------------------------------------ the durable file
    def document(self) -> dict:
        return {canon.ENCODING_KEY: canon.CANON2, "format": FORMAT, "floors": dict(self.floors),
                "keys": {kid: {"public": key.public.hex(), "role": key.role} for kid, key in self.keys.items()},
                "retired": sorted(self.retired), "revoked_envelopes": sorted(self.revoked_envelopes),
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
        keys = doc["keys"]
        require(isinstance(keys, dict), "keys")
        raw_keys: Dict[str, Key] = {}
        for kid, held in keys.items():
            require(isinstance(held, dict) and set(held) == {"public", "role"}, "a key entry")
            require(is_hex64(held["public"]), "a public key")
            require(isinstance(held["role"], str) and _ROLE.fullmatch(held["role"]) is not None, "a key role")
            public_raw = bytes.fromhex(held["public"])
            require(canon.sha256_hex(public_raw) == kid, "a key id that is not its key's")
            raw_keys[kid] = Key(public_raw, held["role"])
        return cls(keys=raw_keys, retired=frozenset(doc["retired"]), revoked_keys=frozenset(doc["revoked_keys"]),
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
