#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Real signed, anchored, replayable receipts for AI-safety determinations, so the AST-3 facts are
MEASURED rather than declared.

Reuses the engine's own Ed25519 primitives (prismpath.policy_pack) and its content-addressed
provenance manifest (prismpath.ledger_airgap), the same core the rest of PrismPath signs and anchors
with. Nothing here reads the clock: signed_at is passed in, so a receipt is reproducible.

A receipt binds the sha256 of the canonical determination (the determination_root) under an Ed25519
signature. Verification re-hashes the determination and checks the signature, so a tampered
determination or a tampered receipt fails. anchor_receipt commits the root into a content-addressed
manifest that verify_manifest re-derives offline.
"""
from prismpath import canon as _canon
from prismpath.hotswap import policy_pack as _pp
from prismpath.ledgers import ledger_airgap as _lg

_SIGNED_KEYS = ("kind", "determination_root", "signed_at", "key_id")


def _determination_root(determination, encoding):
    """sha256 of the determination: its canon/2 content bytes for a canon/2 receipt (a float as its
    decimal string), its canon/1 compact bytes for a receipt signed before the migration."""
    if encoding == _canon.CANON2:
        return _pp.sha256_hex(_canon.content_bytes(determination))
    return _pp.sha256_hex(_canon.canonical_compact(determination))


def _payload(determination, signed_at, key_id):
    return {"kind": "ai-safety-receipt",
            "determination_root": _determination_root(determination, _canon.CANON2),
            "signed_at": signed_at, "key_id": key_id, _canon.ENCODING_KEY: _canon.CANON2}


def sign_receipt(determination, key, signed_at):
    """Ed25519-sign a determination. `key` is a keygen() result dict (private, public, key_id).
    signed_at is an ISO-8601 string. Returns a receipt with a signature over the canonical payload."""
    priv = _pp._load_private(key["private"])
    payload = _payload(determination, signed_at, key["key_id"])
    payload["signature"] = priv.sign(_pp.signed_bytes(payload)).hex()
    return payload


def verify_receipt(receipt, determination, pub_path):
    """Verify the Ed25519 signature AND that the determination still hashes to the receipt's
    determination_root. A tampered determination or receipt fails. Offline, no clock."""
    _Priv, _Pub, _ser, InvalidSignature = _pp._ed25519()
    pub, key_id = _pp.load_public(pub_path)
    if receipt.get("key_id") != key_id:
        return False
    try:
        encoding = _canon.encoding_of(receipt)
        if _determination_root(determination, encoding) != receipt.get("determination_root"):
            return False
        payload = {field: receipt.get(field) for field in _SIGNED_KEYS}
        if encoding == _canon.CANON2:
            payload[_canon.ENCODING_KEY] = _canon.CANON2
        pub.verify(bytes.fromhex(receipt.get("signature", "")), _pp.signed_bytes(payload))
        return True
    except (InvalidSignature, ValueError):
        return False


def anchor_receipt(receipt):
    """Bind the receipt's root into a content-addressed provenance manifest (offline-verifiable)."""
    return _lg.provenance_manifest(receipt["determination_root"], "ai-safety-receipt",
                                   ingestion_hashes=[receipt.get("signature", "")[:32]])


def verify_anchor(manifest):
    """Re-derive the content address and confirm the manifest was not edited after anchoring."""
    return _lg.verify_manifest(manifest)
