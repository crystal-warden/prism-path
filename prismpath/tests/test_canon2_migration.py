# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The canon/2 migration of everything PrismPath hashes or signs (docs/design/spec-verified-core.md,
section 3.1): a document's own tag decides its reader, canon/1 is verify only, and nothing writes it.

  1. THE TAG DECIDES. `"encoding": "canon/2"` is hashed and signed under canon/2 and read by the strict
     canon/2 reader; no tag is a canon/1 document from before the migration; any other tag is refused.
  2. NOTHING WRITES CANON/1. The canon/1 encoders are called only by the readers that verify what was
     already signed, hashed or anchored, and by the generators of frozen canon/1 twins. A new call
     site fails this test until it is either moved to canon/2 or named here with its reason.
"""
import re

import pytest

from prismpath import canon
from prismpath.kernel import canon2
from prismpath.tests._repo import repo_file


def test_the_tag_decides_the_bytes():
    legacy = {"b": 1.5, "a": "é"}
    tagged = canon.tagged({"b": 2, "a": "é"})
    assert canon.encoding_of(legacy) == "canon/1" and canon.encoding_of(tagged) == "canon/2"
    assert canon.document_bytes(legacy) == canon.canonical_compact(legacy)
    assert canon.document_bytes(tagged) == '{"a":"é","b":2,"encoding":"canon/2"}'.encode()
    assert canon.signed_message(tagged) == canon.CANON2_DOMAIN + canon.document_bytes(tagged)
    assert canon.signed_message(legacy) == canon.canonical_compact(legacy)
    with pytest.raises(canon.EncodingError):
        canon.encoding_of({"encoding": "canon/3"})
    with pytest.raises(canon.EncodingError):
        canon.document_bytes({"encoding": None})
    with pytest.raises(canon.EncodingError):
        canon.document_bytes(canon.tagged({"x": 0.5}))      # canon/2 has no float: refused, never converted


def test_a_document_that_names_canon2_is_read_by_the_strict_reader():
    assert canon.loads_document('{"encoding":"canon/2","n":1}') == {"encoding": "canon/2", "n": 1}
    assert canon.loads_document('{"n": 1.5}') == {"n": 1.5}                    # canon/1, verify only
    for text in ('{"encoding":"canon/2","n":1.5}', '{"encoding":"canon/2","n":1,"n":2}',
                 '{"encoding":"canon/2","n":9007199254740992}', '{"encoding":"canon/3"}'):
        with pytest.raises(canon.CanonicalReadError):
            canon.loads_document(text)


def test_content_is_canon2_with_a_float_as_its_decimal_string():
    assert canon.content_bytes({"r": 0.1, "n": [1, 2.0]}) == b'{"n":[1,"2.0"],"r":"0.1"}'
    assert canon2.loads(canon.content_bytes({"k": "v"})) == {"k": "v"}
    with pytest.raises(canon.CanonicalError):
        canon.content_bytes({"x": float("nan")})


# Every call of a canon/1 encoder outside prismpath/canon.py, with the reason it is not a writer.
_PYTHON_CANON1 = re.compile(r"\b(canonical_compact|canonical_spaced)\(")
_ALLOWED_PYTHON = {
    "prismpath/ledgers/root_statement.py": "verifies a prismpath-root-statement/1 signature",
    "adapters/compliance/ai_safety_receipts.py": "verifies the root of a receipt signed before the migration",
    "prismpath/portable/gen_canonical_fixtures.py": "the frozen canon/1 encoding corpus (canonical.json)",
    "prismpath/portable/gen_receipt_fixtures.py": "legacy events and statements, the cases that cross the migration",
}
_RUST_CANON1 = re.compile(r"\b(try_)?py_canonical_string\(")
_ALLOWED_RUST = {
    "prismpath-rs/src/durable.rs": "the canon/1 encoder itself, and the untagged branch of document_bytes, "
                                   "signed_message and manifest_hash_of (verify only)",
    "prismpath-hotswap-rs/src/root_statement.rs": "verifies a prismpath-root-statement/1 signature",
    "prismpath-hotswap-rs/src/pyval.rs": "Python's str() of a value in a message, nothing hashed",
    "prismpath-rs/src/connector.rs": "the sink's JSONL record, Python's json.dumps line, nothing hashed",
}
_JS_CANON1 = re.compile(r"\bpyCanonicalString\(")
_ALLOWED_JS = {
    "prismpath/portable/prismpath.mjs": "the canon/1 encoder itself and the untagged branch of documentString (verify only)",
}


def _sources(top, suffix):
    root = repo_file(top)
    for path in sorted(root.rglob(f"*{suffix}")):
        rel = path.relative_to(repo_file(".")).as_posix()
        if "/tests/" in rel or "/target/" in rel or rel.startswith("prismpath/comparisons/") or "/.lake/" in rel:
            continue
        yield rel, path.read_text(encoding="utf-8", errors="replace")


def test_nothing_writes_canon1():
    found = set()
    for top in ("prismpath", "adapters"):
        for rel, text in _sources(top, ".py"):
            if rel == "prismpath/canon.py":
                continue
            if _PYTHON_CANON1.search(text):
                found.add(rel)
    for top in ("prismpath-rs", "prismpath-hotswap-rs", "prismpath-telemetry-rs", "prismpath-preflight"):
        for rel, text in _sources(top, ".rs"):
            code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("//"))
            if _RUST_CANON1.search(code):
                found.add(rel)
    for top in ("prismpath/portable", "prismpath-go", "prismpath-ebpf"):
        for rel, text in _sources(top, ".mjs"):
            if _JS_CANON1.search(text):
                found.add(rel)
    unexplained = found - set(_ALLOWED_PYTHON) - set(_ALLOWED_RUST) - set(_ALLOWED_JS)
    assert not unexplained, f"canon/1 encoders called outside the verify only readers: {sorted(unexplained)}"
    stale = (set(_ALLOWED_PYTHON) | set(_ALLOWED_RUST) | set(_ALLOWED_JS)) - found
    assert not stale, f"allowed sites that no longer call a canon/1 encoder (remove them): {sorted(stale)}"
