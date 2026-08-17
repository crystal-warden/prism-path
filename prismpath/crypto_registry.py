# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Crypto-suite registry — the signed symbol->primitive binding (`spec-crypto-agility.md` §7).

The control plane governs SELECTION over symbolic suite ids; this registry pins each id to a
concrete, vetted implementation plus a declared strength rank. It is canonicalized and Ed25519-signed
exactly like a policy pack (reusing `policy_pack`'s primitives — no new crypto is written here), so a
policy swap cannot silently re-point a suite id at a weaker primitive: the registry's hash is bound
into both the pack manifest and the envelope, and any edit flips the hash.

PrismPath never implements a primitive. `provider` names the vetted library that performs the
operation; resolution is loud-absence (see `crypto_host`), never a silent downgrade. `strength_rank`
is an honestly-declared policy input, not a theorem about relative cryptographic strength — the
proofs in `crypto_agility` are sound *with respect to* this declared order.
"""
from __future__ import annotations

import os
from typing import Dict, List, Optional, Tuple

from . import policy_pack as pp

REGISTRY_FORMAT = "ppt-suite-registry/1"

# Declared post-quantum KEM tokens: a suite is "quantum-resistant" iff its `kem` names one of these.
# A documented naming convention, deliberately conservative — classical-only is the safe default so a
# mislabelled suite is treated as weaker, never stronger. Used only by the P4 monotone-migration proof.
_PQ_KEM_TOKENS = ("ml-kem", "kyber")

_REQUIRED_SUITE_KEYS = ("kem", "sig", "aead", "provider", "strength_rank")


def build_registry(suites: Dict[str, dict], key_id: str) -> dict:
    """Canonical registry dict. Each suite spec must carry kem/sig/aead/provider/strength_rank."""
    norm: Dict[str, dict] = {}
    for sid, spec in suites.items():
        missing = [k for k in _REQUIRED_SUITE_KEYS if k not in spec]
        if missing:
            raise ValueError(f"suite {sid!r} missing keys: {','.join(missing)}")
        norm[sid] = {
            "kem": str(spec["kem"]),
            "sig": str(spec["sig"]),
            "aead": str(spec["aead"]),
            "provider": str(spec["provider"]),
            "strength_rank": int(spec["strength_rank"]),
        }
    return {"format": REGISTRY_FORMAT, "suites": norm, "key_id": str(key_id)}


def registry_hash(registry: dict) -> str:
    """The identity bound into pack manifests and envelopes; any edit flips it."""
    return pp.sha256_hex(pp.canonical_bytes(registry))


# ------------------------------------------------------------------ signing (composes policy_pack)

def sign_registry(registry: dict, priv_path: str, out_path: str) -> str:
    """Write the canonical registry JSON + a detached Ed25519 signature (`<out>.sig`). Returns hash."""
    priv = pp._load_private(priv_path)
    payload = pp.canonical_bytes(registry)
    with open(out_path, "wb") as f:
        f.write(payload)
    sig = priv.sign(payload)
    with open(out_path + ".sig", "wb") as f:
        f.write(sig)
    return registry_hash(registry)


def verify_registry(path: str, pubkey_paths: List[str],
                    revoked: frozenset = frozenset()) -> Tuple[bool, List[str], Optional[dict]]:
    """Verify a registry file's detached signature by a known, non-revoked authority key.
    Returns (ok, stable-reasons, registry-or-None). Loud absence if signing lib is unavailable."""
    import json
    _Priv, _Pub, _ser, InvalidSignature = pp._ed25519()
    sig_path = path + ".sig"
    if not os.path.exists(path) or not os.path.exists(sig_path):
        return False, ["registry:missing"], None
    with open(path, "rb") as f:
        raw = f.read()
    with open(sig_path, "rb") as f:
        sig = f.read()
    try:
        registry = json.loads(raw)
    except Exception:
        return False, ["registry:bad-json"], None
    if registry.get("format") != REGISTRY_FORMAT:
        return False, ["registry:bad-format"], registry
    signer_id = None
    for pk in pubkey_paths:
        pub, key_id = pp.load_public(pk)
        try:
            pub.verify(sig, raw)
            signer_id = key_id
            break
        except InvalidSignature:
            continue
    if signer_id is None:
        return False, ["registry:sig-invalid"], registry
    if signer_id in revoked:
        return False, ["registry:revoked-key"], registry
    if registry.get("key_id") != signer_id:
        return False, ["registry:key-id-mismatch"], registry
    # signature is over the raw bytes; confirm they canonicalize identically (no sneaked whitespace)
    if pp.canonical_bytes(registry) != raw:
        return False, ["registry:non-canonical"], registry
    return True, [], registry


# ------------------------------------------------------------------ strength / migration queries

def suite_ids(registry: dict) -> set:
    return set(registry.get("suites", {}).keys())


def strength_rank(registry: dict, suite_id: str) -> Optional[int]:
    s = registry.get("suites", {}).get(suite_id)
    return None if s is None else int(s["strength_rank"])


def suites_below(registry: dict, floor_id: str) -> set:
    """Suite ids ranked strictly below `floor_id` — the below-floor set the class-floor proof forbids."""
    floor = strength_rank(registry, floor_id)
    if floor is None:
        raise KeyError(f"unknown floor suite: {floor_id}")
    return {sid for sid in suite_ids(registry) if (strength_rank(registry, sid) or 0) < floor}


def is_quantum_resistant(registry: dict, suite_id: str) -> bool:
    s = registry.get("suites", {}).get(suite_id)
    if s is None:
        return False
    kem = s["kem"].lower()
    return any(tok in kem for tok in _PQ_KEM_TOKENS)


def classical_only_ids(registry: dict) -> set:
    """Suite ids with no post-quantum KEM component — the set the monotone-migration proof forbids
    once a node is past its migration phase."""
    return {sid for sid in suite_ids(registry) if not is_quantum_resistant(registry, sid)}
