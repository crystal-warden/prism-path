# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""canon/2 is the only encoding of everything PrismPath hashes or signs, and canon/1 is gone
(docs/design/spec-verified-core.md, section 3.1; SPEC.md section 8):

  1. THE TAG IS REQUIRED. `"encoding": "canon/2"` is hashed and signed under canon/2 and read by the strict
     canon/2 reader. A document with no tag, another tag, or no object at all is refused, never read under
     another encoding. (Each reader of each artifact has its own refusal test beside it; this file holds the
     rule and the sweep.)
  2. A FLOAT IS REFUSED. In content PrismPath hashes but did not write, a float raises, it is never spelled.
  3. NO CANON/1 AT ALL. No encoder and no decoder of it remains in Python, Rust, JavaScript, Go or the eBPF
     and hardware code, and no frozen canon/1 corpus is left. A name that was part of it reappearing in
     product code fails the sweep below.
"""
import re

import pytest

from prismpath import canon
from prismpath.kernel import canon2
from prismpath.tests._repo import REPO_ROOT, repo_file


def test_the_tag_is_required_and_decides_the_bytes():
    tagged = canon.tagged({"b": 2, "a": "é"})
    assert canon.encoding_of(tagged) == "canon/2"
    assert canon.document_bytes(tagged) == '{"a":"é","b":2,"encoding":"canon/2"}'.encode()
    assert canon.signed_message(tagged) == canon.CANON2_DOMAIN + canon.document_bytes(tagged)
    for refused in ({"b": 1.5, "a": "é"}, {"encoding": "canon/1"}, {"encoding": "canon/3"}, {"encoding": None}, [1], "x"):
        for use in (canon.encoding_of, canon.document_bytes, canon.signed_message, canon.document_hash):
            with pytest.raises(canon.EncodingError):
                use(refused)
    with pytest.raises(canon.EncodingError):
        canon.document_bytes(canon.tagged({"x": 0.5}))      # canon/2 has no float: refused, never converted


def test_a_document_that_names_canon2_is_read_by_the_strict_reader():
    assert canon.loads_document('{"encoding":"canon/2","n":1}') == {"encoding": "canon/2", "n": 1}
    for text in ('{"n": 1.5}', '{"n": 1}', '[1]', "7", '{"encoding":"canon/2","n":1.5}', '{"encoding":"canon/2","n":1,"n":2}',
                 '{"encoding":"canon/2","n":9007199254740992}', '{"encoding":"canon/3"}', '{"encoding":"canon/1"}'):
        with pytest.raises(canon.CanonicalReadError):
            canon.loads_document(text)


def test_a_float_in_content_is_refused_not_converted():
    assert canon.content_bytes({"r": "0.1", "n": [1, 2]}) == b'{"n":[1,2],"r":"0.1"}'
    assert canon2.loads(canon.content_bytes({"k": "v"})) == {"k": "v"}
    for content in ({"r": 0.1}, {"n": [1, 2.0]}, {"x": float("nan")}, {"x": {"y": [float("inf")]}}, {1.5: "k"},
                    0.5, {"x": {1, 2}}):
        with pytest.raises((canon.FloatRefused, TypeError)):
            canon.content_bytes(content)
    with pytest.raises(canon.FloatRefused, match="integer of a stated unit .* or a decimal string"):
        canon.content_bytes([0.5])
    with pytest.raises(canon.FloatRefused):
        canon.content_bytes({"d": object()}, default=lambda item: 0.5)       # a stringifier's float too
    assert issubclass(canon.FloatRefused, canon.CanonicalError)


# ------------------------------------------------------------------ the sweep: no canon/1 anywhere

# Names that were canon/1: its encoders and decoders, the legacy statement format, the canon/1 corpora.
_PYTHON = re.compile(r"\b(canonical_compact|canonical_spaced|CANON1|LEGACY_FORMAT|LEGACY_SIGNING_DOMAIN|LEGACY_BODY_FIELDS"
                     r"|dumps_strict|manifest_hash_of_legacy)\b|\bcanon\.(loads|load)\(|\bsha256\w*\(\s*(canon\.)?json\.dumps\(")
_RUST = re.compile(r"\b(try_)?py_canonical_string\b|\bCANON1\b|\bLEGACY_FORMAT\b|\bLEGACY_SIGNING_DOMAIN\b|\bLEGACY_BODY_FIELDS\b"
                   r"|\bparse_strict\b|\bis_legacy\b")
_JS = re.compile(r"\b(pyCanonicalString|canonicalCompact|canonicalSpaced|LEGACY_FORMAT|LEGACY_SIGNING_DOMAIN)\b")
_GO = re.compile(r"\b(pyCanonicalString|PyCanonical|CanonicalCompact|CanonicalSpaced|LegacyFormat)\b|crypto/sha256|crypto/ed25519")
_C = re.compile(r"canon/1|canonical_compact|canonical_spaced")
_RETIRED_FILES = (
    "prismpath/portable/conformance/canonical.json",
    "prismpath/portable/conformance/receipts_canon1.json",
    "prismpath/portable/conformance/hotswap_canon1.json",
    "prismpath/portable/gen_canonical_fixtures.py",
)


def _sources(top, suffixes, skip=()):
    root = REPO_ROOT / top
    if not root.is_dir():       # the product carries Python and Rust only; a tree it does not carry has nothing to sweep
        return
    for path in sorted(root.rglob("*")):
        if path.suffix not in suffixes or not path.is_file():
            continue
        rel = path.relative_to(repo_file(".")).as_posix()
        parts = rel.split("/")
        if ("tests" in parts or "target" in parts or ".lake" in parts or "node_modules" in parts
                or rel.startswith("prismpath/comparisons/") or rel in skip or rel.endswith("_test.go")
                or rel.endswith(".test.mjs") or rel.endswith("/test_canon2_migration.py")):
            continue
        yield rel, path.read_text(encoding="utf-8", errors="replace")


def _comment_free(text, comment):
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith(comment))


def _hits(pattern, tops, suffixes, comment):
    found = []
    for top in tops:
        for rel, text in _sources(top, suffixes):
            if pattern.search(_comment_free(text, comment)):
                found.append(rel)
    return found


# Two generators spell a canon/1 document by hand (Python's compact `json.dumps`) because the cases they
# write are the refusals of what canon/1 wrote: the product must be shown to refuse it. They are research
# tooling, nothing imports them, and no product code may use the spelling.
_REFUSAL_INPUTS = {"prismpath/portable/gen_receipt_fixtures.py", "prismpath/portable/gen_hotswap_fixtures.py"}


def test_no_canon1_encoder_or_decoder_in_python():
    found = _hits(_PYTHON, ("prismpath", "adapters", "integrations", "tools", "prismpath-hw", "prismpath-ebpf"), {".py"}, "#")
    assert sorted(set(found) - _REFUSAL_INPUTS) == []
    for rel in _REFUSAL_INPUTS:
        module = rel[:-3].replace("/", ".")
        for other, text in _sources("prismpath", {".py"}):
            assert f"import {module.rsplit('.', 1)[-1]}" not in text or other.startswith("prismpath/portable/gen_") or "tests" in other, other


def test_no_canon1_encoder_or_decoder_in_rust():
    assert _hits(_RUST, ("prismpath-rs", "prismpath-hotswap-rs", "prismpath-telemetry-rs", "prismpath-preflight",
                         "prismpath-reflect-bindings", "prismpath-ebpf/collector"), {".rs"}, "//") == []


def test_no_canon1_encoder_or_decoder_in_javascript():
    assert _hits(_JS, ("prismpath/portable", "prismpath/editor"), {".mjs", ".js"}, "//") == []


def test_go_and_ebpf_hash_and_sign_nothing_and_name_no_canon1():
    assert _hits(_GO, ("prismpath-go",), {".go"}, "//") == []
    assert _hits(_C, ("prismpath-ebpf", "prismpath-hw"), {".c", ".h", ".v", ".sv", ".cpp"}, "//") == []


def test_no_frozen_canon1_corpus_or_generator_is_left():
    for name in _RETIRED_FILES:
        assert not (REPO_ROOT / name).exists(), f"{name} was removed with canon/1"
    for rel in ("tools/run_corpora.py", "prismpath/portable/conformance/README.md"):
        if not (REPO_ROOT / rel).exists():
            continue
        text = repo_file(*rel.split("/")).read_text(encoding="utf-8")
        for name in ("receipts_canon1", "hotswap_canon1", "canonical.json"):
            assert name not in text, f"{rel} still names {name}"
    import json
    doc = json.loads(repo_file("prismpath", "portable", "conformance", "receipts.json").read_text(encoding="utf-8"))
    assert "canon" not in {case["kind"] for case in doc["cases"]}
    assert "canonical" not in json.loads(repo_file("prismpath", "portable", "conformance", "durable.json").read_text(encoding="utf-8"))


def test_the_retired_python_names_are_gone_from_the_module():
    for name in ("canonical_compact", "canonical_spaced", "CANON1", "dumps_strict", "loads", "load"):
        assert not hasattr(canon, name), name
