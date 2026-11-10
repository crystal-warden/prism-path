# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Canonical JSON refuses what it has no form for: NaN, Infinity, -Infinity, a number beyond the double
range (`1e400`), and a lone surrogate. It refuses them where bytes are written and where a document
that will be hashed, signed or verified is read, and it never converts them to infinity or zero.
`prismpath-rs/tests/test_canonical.rs` pins the same refusals in Rust from the same corpus."""
import json
import math

import pytest

from prismpath import canon
from prismpath.ledgers.audit_log import AuditLog, AuditWriteError

CORPUS = json.load(open(canon.__file__.replace("canon.py", "portable/conformance/canonical.json")))


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), [1, float("nan")], {"a": {"b": [math.inf]}},
                                   {float("nan"): 1}, "\ud800", ["x", "\udbff"], {"\udc00": 1}, {"k": ("a", "\ud800")}])
def test_writers_refuse_values_with_no_canonical_form(value):
    for write in (canon.canonical_compact, canon.canonical_spaced, canon.dumps_strict):
        with pytest.raises(canon.CanonicalError):
            write(value)


def test_a_default_hook_cannot_smuggle_a_lone_surrogate_in():
    with pytest.raises(canon.CanonicalError):
        canon.canonical_spaced({1}, default=lambda item: "\ud800")
    assert canon.canonical_spaced({1}, default=lambda item: sorted(item)) == b"[1]"


def test_ordinary_values_write_the_same_bytes_as_before():
    value = {"b": [1, 2.5, None, True], "a": "é😀", "z": {"y": 1e-7, "x": 10 ** 30}}
    assert canon.canonical_compact(value) == json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    assert canon.canonical_spaced(value) == json.dumps(value, sort_keys=True).encode()
    assert canon.canonical_compact("😀".encode("utf-16", "surrogatepass").decode("utf-16")) == b'"\\ud83d\\ude00"'


def test_every_refused_corpus_input_is_refused_on_read():
    refused = CORPUS["refused"]
    assert len(refused) >= 14
    for case in refused:
        assert "compact" not in case, case["name"]
        with pytest.raises(canon.CanonicalReadError):
            canon.loads(case["json"])
        with pytest.raises(json.JSONDecodeError):   # every caller that refuses bad JSON refuses these
            canon.loads(case["json"])


def test_an_overflowing_number_is_refused_not_read_as_infinity():
    with pytest.raises(canon.CanonicalReadError, match="beyond the double range"):
        canon.loads("[1e400]")
    assert canon.loads("1e-400") == 0.0          # below the range is a finite value in both languages
    assert canon.loads("1" + "0" * 400) == 10 ** 400


def test_a_nan_manifest_is_the_bad_format_refusal_not_an_exception(tmp_path):
    """`manifest:bad-format` is the registry's "manifest unparseable": a gate that returns stable reasons
    answers NaN (or a number beyond the double range) with it and no manifest, as the Rust gate does."""
    from prismpath.hotswap import policy_pack
    path = tmp_path / "a.ppt"
    path.write_bytes(b"x")
    (tmp_path / "a.ppt.manifest.sig").write_bytes(b"x")
    for text in ('{"format": "x", "wcet_cycles": NaN}', '{"version": 1e400}', '{"v": -Infinity}', "{not json", "", "[1]"):
        (tmp_path / "a.ppt.manifest.json").write_text(text)
        assert policy_pack.verify_pack(str(path), []) == (False, ["manifest:bad-format"], None), text
    (tmp_path / "a.ppt.manifest.json").write_bytes(b"\xff\xfe{}")
    assert policy_pack.verify_pack(str(path), []) == (False, ["manifest:bad-format"], None)


def test_audit_log_refuses_an_event_it_cannot_canonicalise_and_stays_unchanged(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(str(path))
    log.append("t", "ok", {"n": 1})
    for bad in (float("nan"), float("inf"), "\ud800"):
        with pytest.raises(AuditWriteError, match="no canonical JSON form"):
            log.append("t", "bad", {"v": bad})
    assert len(log.events) == 1 and len(log.leaves) == 1
    assert len(path.read_text().splitlines()) == 1
    assert log.verify_persisted() is True


def test_audit_log_lines_the_strict_reader_refuses_are_skipped_like_unparseable_ones(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(str(path))
    log.append("t", "first", {"n": 1})
    intact = path.read_text()
    for line, offender in [("NaN", 2), ("[Infinity]", 2), ('{"x": "\\ud800"}', 2), ('{"x": 1e400}', 2), ('{"x": -Infinity}', 2)]:
        path.write_text(intact + line + "\n")
        reopened = AuditLog(str(path))
        assert reopened.skipped == [offender], line
        assert len(reopened.events) == 1
        assert reopened.verify_log() is False and reopened.verify_persisted() is False, line
