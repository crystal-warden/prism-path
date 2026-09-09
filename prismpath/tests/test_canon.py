# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""prismpath.canon reproduces every recipe it replaced byte for byte: the compact and spaced canonical
forms, the bare and prefixed digests, the manifest address, the atomic write, and the sanitizer."""
import hashlib
import json
import os

from prismpath import canon

OBJ = {"b": [1, 2, {"z": "ü", "a": None}], "a": "x y", "c": 1.5, "d": True}


def test_compact_matches_the_signature_recipe():
    assert canon.canonical_compact(OBJ) == json.dumps(OBJ, sort_keys=True, separators=(",", ":")).encode()


def test_spaced_matches_the_manifest_recipe():
    assert canon.canonical_spaced(OBJ) == json.dumps(OBJ, sort_keys=True).encode()
    o = {"t": (1, 2)}
    assert canon.canonical_spaced(o, default=str) == json.dumps(o, sort_keys=True, default=str).encode()


def test_digests():
    data = b"prism"
    assert canon.sha256_hex(data) == hashlib.sha256(data).hexdigest()
    assert canon.sha256_prefixed(data) == "sha256:" + hashlib.sha256(data).hexdigest()


def test_file_digest_and_manifest_hash(tmp_path):
    p = tmp_path / "f.md"; p.write_bytes(b"## a\n")
    assert canon.file_sha256_prefixed(p) == "sha256:" + hashlib.sha256(b"## a\n").hexdigest()
    m = {"manifest_hash": "stale", "policy_hash": "sha256:1", "gate_id": "g", "ingestion_hashes": ["sha256:aa"]}
    body = json.dumps({k: m[k] for k in m if k != "manifest_hash"}, sort_keys=True).encode()
    assert canon.manifest_hash(m) == hashlib.sha256(body).hexdigest()


def test_atomic_write_creates_parent_and_replaces(tmp_path):
    p = tmp_path / "deep" / "dir" / "x.json"
    canon.atomic_write(p, "one")
    canon.atomic_write(p, "two")
    assert p.read_text() == "two" and not os.path.exists(str(p) + ".tmp")


def test_safe_name():
    assert canon.safe_name("a/b c") == "a_b_c" and canon.safe_name("") == "flow"


def test_old_names_still_resolve():
    from prismpath import checkpoint, ledger, policy_pack, context_ledger
    assert checkpoint._atomic_write is canon.atomic_write
    assert ledger._safe is canon.safe_name
    assert policy_pack.sha256_hex is canon.sha256_hex
    assert context_ledger._sha256_hex is canon.sha256_hex
    assert policy_pack.canonical_bytes({"a": 1}) == canon.canonical_compact({"a": 1})
