"""Crypto-agility runtime governor (`spec-crypto-agility.md` §4) — the swap side of the control plane.

Governs *which* crypto-suite-selection policy is authorized to be live and delegates every actual
cryptographic operation to a vetted provider. It never implements a primitive. A swap is accepted
only when it is **Authorized** (signed pack), **Envelope-bounded** (declared suites ⊆ approved, and
the pack's `registry_hash` matches the live registry — so a swap cannot re-point a suite id at a
weaker primitive), monotonic (anti-rollback version floor), and every declared suite's provider is
available on this host. Provider absence is **loud**: the swap is *refused*, never silently
downgraded to a weaker suite. Every attempt — accepted or rejected — is one Merkle-logged audit
event, so an attempted downgrade is attack-visible, not just absent.

Composes `policy_pack` (signature, canonical manifest, image validation), `crypto_registry` (the
signed symbol→primitive binding), and `audit_log` (the attested trail). Mirrors `PolicyHost`'s
persisted version floor and atomic flip.
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from . import crypto_registry as cr
from . import policy_pack as pp
from .audit_log import AuditLog

_PQ_KEM_TOKENS = ("ml-kem", "kyber")


class CryptoSwapRejected(Exception):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ------------------------------------------------------------------ pack building (crypto binding)

def build_crypto_pack(ppt_path: str, fields: dict, version: int, envelope_id: str,
                      suites: List[str], registry_hash: str,
                      priv_path: str, pub_path: str) -> dict:
    """Sign a `.ppt` into a crypto pack: the generic manifest plus the crypto binding (`suites`,
    `registry_hash`), both covered by the same Ed25519 signature over the canonical manifest."""
    with open(ppt_path, "rb") as f:
        image = f.read()
    ok, reasons = pp.validate_image(image)
    if not ok:
        raise ValueError("refusing to sign an invalid image: " + ",".join(reasons))
    _pub, key_id = pp.load_public(pub_path)
    manifest = pp.build_manifest(image, fields, version, envelope_id, key_id)
    manifest["suites"] = sorted(suites)
    manifest["registry_hash"] = registry_hash
    priv = pp._load_private(priv_path)
    sig = priv.sign(pp.canonical_bytes(manifest))
    with open(ppt_path + ".manifest.json", "w") as f:
        json.dump(manifest, f, indent=1, sort_keys=True)
        f.write("\n")
    with open(ppt_path + ".manifest.sig", "wb") as f:
        f.write(sig)
    return manifest


# ------------------------------------------------------------------ provider binding (loud absence)

def _has_mlkem() -> bool:
    """Does the vetted provider expose an ML-KEM implementation on this host? Probed, never assumed —
    so post-quantum suites bind the moment a real provider ships them and stay loudly-absent until."""
    try:
        from cryptography.hazmat.primitives.asymmetric import mlkem  # noqa: F401
        return True
    except Exception:
        return False


def resolve_provider(suite_spec: dict) -> Tuple[bool, Optional[str]]:
    """Can the vetted provider perform this suite's KEM + AEAD on THIS host? Returns (ok, reason).
    Never substitutes; a miss is a loud refusal the caller turns into a rejected swap."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import (  # noqa: F401
            AESGCM, ChaCha20Poly1305)
    except Exception:
        return False, "provider:cryptography-absent"

    aead = suite_spec.get("aead", "").lower()
    if not ("chacha20" in aead or aead in ("aes-256-gcm", "aes-128-gcm")):
        return False, f"provider:unknown-aead:{aead}"

    kem = suite_spec.get("kem", "").lower()
    for token in kem.split("+"):
        token = token.strip()
        if any(pq in token for pq in _PQ_KEM_TOKENS):
            if not _has_mlkem():
                return False, f"provider:pqc-kem-unavailable:{token}"
        elif not (token.startswith("x25519") or token.startswith("x448")
                  or token.startswith("ecdh") or token.startswith("p-")):
            return False, f"provider:unknown-kem:{token}"
    return True, None


def measure_suite_cost(suite_spec: dict, payload_len: int = 1024, iters: int = 500) -> dict:
    """Measured cost of a suite's classical parts on THIS host (X25519 ECDHE + the AEAD). Honest and
    host-specific — the PQC KEM cost is not modelled, only what a vetted provider actually runs here."""
    import time
    ok, reason = resolve_provider(suite_spec)
    base = {"measured": False, "reason": reason, "payload_len": payload_len}
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    except Exception:
        return base
    hs_iters = max(50, iters // 10)
    t0 = time.perf_counter()
    for _ in range(hs_iters):
        a, b = X25519PrivateKey.generate(), X25519PrivateKey.generate()
        a.exchange(b.public_key()); b.exchange(a.public_key())
    handshake_us = (time.perf_counter() - t0) / hs_iters * 1e6
    aead_obj = (ChaCha20Poly1305(ChaCha20Poly1305.generate_key())
                if "chacha20" in suite_spec.get("aead", "").lower()
                else AESGCM(AESGCM.generate_key(256)))
    nonce, msg = bytes(12), bytes(payload_len)
    t0 = time.perf_counter()
    for _ in range(iters):
        aead_obj.encrypt(nonce, msg, None)
    enc_us = (time.perf_counter() - t0) / iters * 1e6
    return {"measured": True, "classical_only": bool(reason),
            "handshake_us": round(handshake_us, 1), "encrypt_us_per_pkt": round(enc_us, 3),
            "payload_len": payload_len}


# ------------------------------------------------------------------ the swap governor

class CryptoHost:
    def __init__(self, state_dir: str, pubkey_paths: List[str], envelope: dict, registry: dict,
                 audit_path: Optional[str] = None, revoked: frozenset = frozenset()):
        self.state_dir = state_dir
        self.pubkey_paths = list(pubkey_paths)
        self.envelope = envelope
        self.registry = registry
        self.registry_hash = cr.registry_hash(registry)
        self.revoked = revoked
        os.makedirs(state_dir, exist_ok=True)
        self.audit = AuditLog(audit_path or os.path.join(state_dir, "crypto_swaps.log"))
        self._lock = threading.Lock()
        self._active: Optional[dict] = None
        self._prev: Optional[dict] = None
        self._version_path = os.path.join(state_dir, "active_crypto_version")

    def _stored_version(self) -> int:
        try:
            with open(self._version_path) as f:
                return int(f.read().strip() or "0")
        except (FileNotFoundError, ValueError):
            return 0

    def _persist_version(self, version: int) -> None:
        tmp = self._version_path + ".tmp"
        with open(tmp, "w") as f:
            f.write(str(version)); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, self._version_path)

    def _reject(self, to_hash, version, reasons: List[str], strict: bool) -> dict:
        self.audit.append("crypto_host", "swap_rejected", {
            "from_hash": self._active["sha256"] if self._active else None,
            "to_hash": to_hash, "version": version, "reasons": reasons, "result": "rejected"})
        if strict:
            raise CryptoSwapRejected(reasons)
        return {"ok": False, "reasons": reasons}

    def _check_crypto_envelope(self, manifest: dict) -> Tuple[bool, List[str]]:
        reasons: List[str] = []
        if manifest.get("registry_hash") != self.registry_hash:
            reasons.append("crypto:registry-hash-mismatch")
        approved = set(self.envelope.get("approved_suites", []))
        for s in sorted(set(manifest.get("suites", [])) - approved):
            reasons.append(f"crypto:unapproved-suite:{s}")
        return (not reasons), reasons

    def _resolve_all(self, suites: List[str]) -> Tuple[bool, List[str]]:
        reasons: List[str] = []
        for sid in sorted(set(suites)):
            spec = self.registry.get("suites", {}).get(sid)
            if spec is None:
                reasons.append(f"crypto:suite-not-in-registry:{sid}")
                continue
            ok, reason = resolve_provider(spec)
            if not ok:
                reasons.append(f"{reason}::{sid}")
        return (not reasons), reasons

    def swap(self, ppt_path: str, *, strict: bool = False) -> dict:
        """Authorized -> generic envelope -> crypto binding -> version floor -> provider resolution
        -> atomic flip. Any miss is a rejected, audited attempt; the active policy only changes on
        full success, and provider absence refuses rather than downgrades."""
        with self._lock:
            try:
                with open(ppt_path, "rb") as f:
                    image = f.read()
            except OSError as e:
                return self._reject(None, None, [f"image:unreadable:{e.errno}"], strict)
            to_hash = pp.sha256_hex(image)

            ok, reasons, manifest = pp.verify_pack(ppt_path, self.pubkey_paths, self.revoked)
            if not ok:
                return self._reject(to_hash, None, reasons, strict)
            ok, reasons = pp.check_envelope(manifest, image, self.envelope)
            if not ok:
                return self._reject(to_hash, manifest.get("version"), reasons, strict)
            ok, reasons = self._check_crypto_envelope(manifest)
            if not ok:
                return self._reject(to_hash, manifest.get("version"), reasons, strict)
            version = manifest["version"]
            if version <= self._stored_version():
                return self._reject(to_hash, version,
                                    [f"version:not-monotonic:{version}<={self._stored_version()}"],
                                    strict)
            ok, reasons = self._resolve_all(manifest.get("suites", []))
            if not ok:
                return self._reject(to_hash, version, reasons, strict)   # loud absence: refuse

            new_active = {"sha256": to_hash, "version": version, "key_id": manifest.get("key_id"),
                          "envelope_id": manifest.get("envelope_id"),
                          "suites": manifest.get("suites", []),
                          "registry_hash": manifest.get("registry_hash"),
                          "image": image, "since": _now(), "ppt_path": os.path.abspath(ppt_path)}
            self._prev, self._active = self._active, new_active
            self._persist_version(version)
            self.audit.append("crypto_host", "swap", {
                "from_hash": self._prev["sha256"] if self._prev else None, "to_hash": to_hash,
                "version": version, "key_id": manifest.get("key_id"),
                "envelope_id": manifest.get("envelope_id"), "suites": manifest.get("suites", []),
                "registry_hash": manifest.get("registry_hash"), "result": "accepted"})
            return {"ok": True, **self.attest()}

    def attest(self) -> dict:
        """The Attested property: what suite-selection policy is live, provably."""
        a = self._active
        if a is None:
            return {"active": None}
        return {"active": a["sha256"], "version": a["version"], "since": a["since"],
                "envelope_id": a["envelope_id"], "registry_hash": a["registry_hash"],
                "suites": a["suites"], "audit_root": self.audit.current_root()}
