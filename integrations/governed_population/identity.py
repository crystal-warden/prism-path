# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Who may sign what, and the signed documents of the population.

There are three kinds of key, made by the repository's own generators, and each signs only its own kinds
of document, each over its own domain prefix so that no signature can be presented as another kind:

  * the operator's AUTHORITY key (`policy_pack.keygen`): policy images (the core's image attestation), the
    founding certificate of the root member, stop orders, and the standing order under which the
    controller stops a lineage the admission policy escalates. It never leaves the `Operator` object;
    nothing a member holds can sign a policy, so no member can sign its own guardrails;
  * the controller's INSTANCE key (`root_statement.keygen`): the root statements of its decision runs,
    the admission run and every evaluation run;
  * each member's own INSTANCE key: the root statements of its harness run, and its requests to the
    controller. A child's key is made fresh by the controller at admission; a parent never sees it.

A signed document is a canon/2 object with `key_id` and `sig` members; `sig` is Ed25519 over the domain
prefix and the canon/2 bytes of every other member.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, Optional

from prismpath.hotswap import policy_pack
from prismpath.kernel import canon2
from prismpath.ledgers import core_evidence, root_statement

FOUNDING = b"prismpath.population-founding/1\x00"
STOP = b"prismpath.population-stop/1\x00"
STANDING = b"prismpath.population-standing-order/1\x00"
REQUEST = b"prismpath.population-request/1\x00"
DOMAINS = {"prismpath.population-founding/1": FOUNDING, "prismpath.population-stop/1": STOP,
           "prismpath.population-standing-order/1": STANDING, "prismpath.population-request/1": REQUEST}


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(doc: Dict[str, Any]) -> str:
    return sha256_hex(canon2.dumps(doc))


def signed_bytes(doc: Dict[str, Any]) -> bytes:
    return DOMAINS[doc["format"]] + canon2.dumps({key: value for key, value in doc.items() if key != "sig"})


def verify_signed(doc: Any, public_raw: bytes, fmt: str) -> bool:
    """True when `doc` is a `fmt` document signed with the key whose raw public bytes are given."""
    _Priv, Pub, _ser, Invalid = root_statement._ed25519()
    if not isinstance(doc, dict) or doc.get("format") != fmt or doc.get("key_id") != sha256_hex(public_raw):
        return False
    sig = doc.get("sig")
    if not isinstance(sig, str):
        return False
    try:
        Pub.from_public_bytes(public_raw).verify(bytes.fromhex(sig), signed_bytes(doc))
    except (Invalid, ValueError):
        return False
    return True


class InstanceIdentity:
    """A member's or the controller's instance key, in its own directory beside the operator's PUBLIC key
    only: `instance.key`, `instance.pub`, `authority.pub`."""

    def __init__(self, keys: Path):
        self.keys = Path(keys)
        self.key = root_statement.InstanceKey.load(str(self.keys / "instance.key"))
        self.key_id = self.key.key_id
        self.public_raw = self.key.public_raw

    @classmethod
    def create(cls, keys: Path, authority_pub: bytes) -> "InstanceIdentity":
        keys = Path(keys)
        keys.mkdir(parents=True, exist_ok=False)
        root_statement.keygen(str(keys), "instance")
        (keys / "authority.pub").write_bytes(authority_pub)
        identity = cls(keys)
        root_statement.check_separation(identity.key, [sha256_hex(authority_pub)])
        return identity

    def sign(self, body: Dict[str, Any]) -> Dict[str, Any]:
        doc = {**body, "key_id": self.key_id}
        doc["sig"] = self.key.sign(signed_bytes(doc)).hex()
        return doc


class Operator:
    """The operator: the only holder of the authority key."""

    def __init__(self, keys: Path):
        self.keys = Path(keys)
        if not (self.keys / "authority.key").exists():
            policy_pack.keygen(str(self.keys), "authority")
        self._signer = policy_pack._load_private(str(self.keys / "authority.key"))
        self.public_raw = (self.keys / "authority.pub").read_bytes()
        self.key_id = sha256_hex(self.public_raw)
        self._stops = 0

    def attest(self, image: bytes) -> str:
        """The image attestation's signature, the core's own (`core_evidence.IMAGE_DOMAIN`): a run signed by
        an instance key carries it, so no instance key ever needs the authority key to seal a run."""
        return self._signer.sign(core_evidence.IMAGE_DOMAIN + image).hex()

    def _sign(self, body: Dict[str, Any]) -> Dict[str, Any]:
        doc = {**body, "key_id": self.key_id}
        doc["sig"] = self._signer.sign(signed_bytes(doc)).hex()
        return doc

    def found(self, root_spec: Dict[str, Any]) -> Dict[str, Any]:
        """The founding certificate: the operator names the root member's spec by its digest."""
        return self._sign({"format": "prismpath.population-founding/1", "root_spec_sha256": digest(root_spec)})

    def stop(self, target: str, reason: str = "operator") -> Dict[str, Any]:
        """A stop order for a member and every descendant of it."""
        self._stops += 1
        return self._sign({"format": "prismpath.population-stop/1", "target": target, "scope": "subtree",
                           "reason": reason, "nonce": self._stops})

    def standing_order(self, admission_image_sha256: str) -> Dict[str, Any]:
        """The controller may stop, as a group, any lineage the admission image escalates with cause 122."""
        return self._sign({"format": "prismpath.population-standing-order/1", "action": "stop-escalated-lineage",
                           "image_sha256": admission_image_sha256, "cause_code": 122})


def request(identity: InstanceIdentity, issuer: str, nonce: int, kind: str, **params: Any) -> Dict[str, Any]:
    """A member's signed request to the controller."""
    return identity.sign({"format": "prismpath.population-request/1", "issuer": issuer, "nonce": nonce, "kind": kind,
                          "params": params})


def forged_request(key_path: Path, issuer: str, nonce: int, kind: str, **params: Any) -> Dict[str, Any]:
    """A request signed with any instance key file (the scenario of a key that is not the member's)."""
    key = root_statement.InstanceKey.load(str(key_path))
    doc = {"format": "prismpath.population-request/1", "issuer": issuer, "nonce": nonce, "kind": kind,
           "params": params, "key_id": key.key_id}
    doc["sig"] = key.sign(signed_bytes(doc)).hex()
    return doc


def public_of(doc: Dict[str, Any]) -> Optional[str]:
    return doc.get("key_id") if isinstance(doc, dict) else None
