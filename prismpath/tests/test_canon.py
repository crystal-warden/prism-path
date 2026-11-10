# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""prismpath.canon: the canon/2 byte rule (the tag decides, canon/1 is refused), the bare and prefixed
digests, the manifest address, the atomic write, the sanitizer, and plain JSON that is never hashed."""
import hashlib
import os

import pytest

from prismpath import canon

OBJ = {"b": [1, 2, {"z": "ü", "a": None}], "a": "x y", "c": "1.5", "d": True}


def test_the_bytes_a_document_is_hashed_and_signed_over_are_canon2():
    doc = canon.tagged(OBJ)
    assert canon.document_bytes(doc) == canon.canon2_bytes(doc)
    assert canon.signed_message(doc) == canon.CANON2_DOMAIN + canon.canon2_bytes(doc)
    assert canon.document_hash(doc) == hashlib.sha256(canon.canon2_bytes(doc)).hexdigest()


def test_a_document_that_does_not_name_canon2_is_refused_everywhere():
    for doc in (OBJ, {"encoding": "canon/1"}, {"encoding": "canon/3"}, {"encoding": None}, [1], "x", 7):
        for use in (canon.encoding_of, canon.document_bytes, canon.signed_message, canon.document_hash):
            with pytest.raises(canon.EncodingError):
                use(doc)
    with pytest.raises(canon.EncodingError):
        canon.manifest_hash(OBJ)


def test_a_retired_function_is_gone():
    for name in ("canonical_compact", "canonical_spaced", "CANON1", "dumps_strict", "loads", "load"):
        assert not hasattr(canon, name), name


def test_digests():
    data = b"prism"
    assert canon.sha256_hex(data) == hashlib.sha256(data).hexdigest()
    assert canon.sha256_prefixed(data) == "sha256:" + hashlib.sha256(data).hexdigest()


def test_file_digest_and_manifest_hash(tmp_path):
    path = tmp_path / "f.md"; path.write_bytes(b"## a\n")
    assert canon.file_sha256_prefixed(path) == "sha256:" + hashlib.sha256(b"## a\n").hexdigest()
    manifest = {"manifest_hash": "stale", "policy_hash": "sha256:1", "gate_id": "g", "ingestion_hashes": ["sha256:aa"],
                "encoding": "canon/2"}
    body = {key: manifest[key] for key in manifest if key != "manifest_hash"}
    assert canon.manifest_hash(manifest) == hashlib.sha256(canon.canon2_bytes(body)).hexdigest()


def test_atomic_write_creates_parent_and_replaces(tmp_path):
    path = tmp_path / "deep" / "dir" / "x.json"
    canon.atomic_write(path, "one")
    canon.atomic_write(path, "two")
    assert path.read_text() == "two" and not os.path.exists(str(path) + ".tmp")


def test_safe_name():
    assert canon.safe_name("a/b c") == "a_b_c" and canon.safe_name("") == "flow"


def test_old_names_still_resolve():
    import warnings
    with warnings.catch_warnings():                       # the aliases warn on purpose; this test is about identity
        warnings.simplefilter("ignore", DeprecationWarning)
        from prismpath import checkpoint, ledger, policy_pack, context_ledger
    assert checkpoint._atomic_write is canon.atomic_write
    assert ledger._safe is canon.safe_name
    assert policy_pack.sha256_hex is canon.sha256_hex
    assert context_ledger._sha256_hex is canon.sha256_hex
    assert policy_pack.canonical_bytes(canon.tagged({"a": 1})) == canon.document_bytes(canon.tagged({"a": 1}))
