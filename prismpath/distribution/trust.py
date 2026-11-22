# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The trust store of an enforcement point (spec-policy-distribution.md, section 5): the trusted authority
keys, the retired key ids, what revocation has refused, the floors revocation raised, the trust sequence,
the threshold and the time floor (T1), and the durable file that holds them.

`counting` is S3 to S6, which entries of a sealed envelope count. A store that cannot be read refuses every
envelope with `dist:unknown-key` (K1). The store changes only by provisioning, a rotation and a revocation
(K3), applied by the code that owns them. Nothing here verifies any other part of an envelope.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Dict, FrozenSet, Mapping, Optional, Sequence, Tuple

from prismpath import canon
from prismpath.distribution import kinds
from prismpath.distribution.kinds import MAX_SEQ, Refused, Verdict, is_hex64, is_int, is_stream

FORMAT = "prismpath.dist-trust-store/1"
THRESHOLD = 1                                      # S6: the only threshold in this version
UNKNOWN_KEY, INVALID, REVOKED_KEY = "dist:unknown-key", "sig:invalid", "sig:revoked-key"
_LISTS = ("retired", "revoked_envelopes", "revoked_keys", "revoked_policies")
_MEMBERS = frozenset({"encoding", "floors", "format", "keys", "threshold", "time_floor", "trust_id",
                      "trust_seq", *_LISTS})


@dataclass(frozen=True)
class TrustStore:
    """What an enforcement point holds about authority keys. `keys` maps a key id to its 32 raw public
    bytes. The `revoked_*` sets and `floors` are cumulative (R6): a later list never removes one. A store
    whose file could not be read has `readable` False and counts nothing."""
    keys: Mapping[str, bytes] = field(default_factory=dict)
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
                "keys": {kid: raw.hex() for kid, raw in self.keys.items()},
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
        raw_keys: Dict[str, bytes] = {}
        for kid, public_hex in keys.items():
            require(isinstance(public_hex, str) and len(public_hex) == 64 and is_hex64(public_hex), "a public key")
            public_raw = bytes.fromhex(public_hex)
            require(canon.sha256_hex(public_raw) == kid, "a key id that is not its key's")
            raw_keys[kid] = public_raw
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
    def with_keys(cls, public_keys: Sequence[bytes], **members) -> "TrustStore":
        """A store trusting `public_keys` (32 raw bytes each), for provisioning and tests."""
        return cls(keys={canon.sha256_hex(bytes(raw)): bytes(raw) for raw in public_keys}, **members)

    # ------------------------------------------------------------------ S3 to S6
    def counting(self, entries: Sequence[Tuple[str, bytes]], message: bytes) -> Verdict:
        """Which entries count (S3 to S6). An entry by a key the store does not hold is ignored. One that
        names a held key and does not verify refuses the envelope with `sig:invalid`. A verifying entry by a
        retired or revoked key does not count. Fewer counting entries than the threshold is
        `sig:revoked-key` when verifying entries by held keys exist and none counts, `dist:unknown-key`
        otherwise."""
        if not self.readable:
            return Verdict(UNKNOWN_KEY)
        from prismpath.hotswap import policy_pack
        _priv, Public, _ser, InvalidSignature = policy_pack._ed25519()
        known = [(kid, signature) for kid, signature in entries if kid in self.keys]
        if not known:
            return Verdict(UNKNOWN_KEY)
        counting = 0
        for kid, signature in known:
            try:
                Public.from_public_bytes(self.keys[kid]).verify(signature, message)
            except InvalidSignature:
                return Verdict(INVALID)
            if kid not in self.retired and kid not in self.revoked_keys:
                counting += 1
        if counting >= self.threshold:
            return Verdict(None)
        return Verdict(REVOKED_KEY if counting == 0 else UNKNOWN_KEY)
