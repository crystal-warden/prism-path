# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""crypto_registry — the signed suite registry (spec-crypto-agility.md §7).

Pure-hash/strength tests run everywhere; signing tests importorskip `cryptography` (the optional
signing extra), matching the policy_pack convention."""
import pytest

from prismpath import crypto_registry as cr

SUITES = {
    "cnsa2-hybrid-1":           {"kem": "x25519+ml-kem-1024", "sig": "ml-dsa-87", "aead": "aes-256-gcm",     "provider": "cryptography>=44", "strength_rank": 3},
    "tls13-hybrid-x25519mlkem": {"kem": "x25519+ml-kem-768",  "sig": "ed25519",   "aead": "chacha20poly1305", "provider": "cryptography",     "strength_rank": 2},
    "tls13-aesgcm":             {"kem": "x25519",             "sig": "ed25519",   "aead": "aes-256-gcm",      "provider": "cryptography",     "strength_rank": 1},
}


def test_build_is_canonical_and_hash_is_stable():
    a = cr.build_registry(SUITES, key_id="k")
    b = cr.build_registry(dict(reversed(list(SUITES.items()))), key_id="k")  # insertion order differs
    assert cr.registry_hash(a) == cr.registry_hash(b)   # canonical JSON -> order-independent


def test_any_edit_flips_the_hash():
    a = cr.build_registry(SUITES, key_id="k")
    weakened = dict(SUITES)
    weakened["tls13-aesgcm"] = {**SUITES["tls13-aesgcm"], "aead": "aes-128-gcm"}
    b = cr.build_registry(weakened, key_id="k")
    assert cr.registry_hash(a) != cr.registry_hash(b)


def test_missing_key_is_rejected():
    with pytest.raises(ValueError):
        cr.build_registry({"bad": {"kem": "x25519"}}, key_id="k")


def test_strength_and_below():
    reg = cr.build_registry(SUITES, key_id="k")
    assert cr.strength_rank(reg, "cnsa2-hybrid-1") == 3
    assert cr.suites_below(reg, "cnsa2-hybrid-1") == {"tls13-hybrid-x25519mlkem", "tls13-aesgcm"}
    assert cr.suites_below(reg, "tls13-aesgcm") == set()          # nothing below the floor


def test_classical_only_detection():
    reg = cr.build_registry(SUITES, key_id="k")
    assert cr.is_quantum_resistant(reg, "cnsa2-hybrid-1") is True
    assert cr.is_quantum_resistant(reg, "tls13-aesgcm") is False
    assert cr.classical_only_ids(reg) == {"tls13-aesgcm"}


def test_sign_verify_roundtrip_and_tamper(tmp_path):
    from prismpath import policy_pack as pp
    pytest.importorskip("cryptography")
    keys = pp.keygen(str(tmp_path))
    _pub, key_id = pp.load_public(keys["public"])
    reg = cr.build_registry(SUITES, key_id=key_id)
    reg_path = str(tmp_path / "registry.json")
    h = cr.sign_registry(reg, keys["private"], reg_path)
    assert h == cr.registry_hash(reg)

    ok, reasons, loaded = cr.verify_registry(reg_path, [keys["public"]])
    assert ok, reasons
    assert cr.registry_hash(loaded) == h

    # tamper: rewrite the file with a weakened suite, signature no longer matches
    weakened = cr.build_registry({**SUITES, "tls13-aesgcm": {**SUITES["tls13-aesgcm"], "aead": "aes-128-gcm"}}, key_id=key_id)
    with open(reg_path, "wb") as f:
        f.write(pp.canonical_bytes(weakened))
    ok2, reasons2, _ = cr.verify_registry(reg_path, [keys["public"]])
    assert ok2 is False and "registry:sig-invalid" in reasons2
