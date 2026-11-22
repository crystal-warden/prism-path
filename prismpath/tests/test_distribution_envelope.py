# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The distribution envelope and the sealed envelope (spec-policy-distribution.md, section 4). Each test names
the conformance case of section 20 it covers. The corpus cases come from portable/gen_distribution_corpus.py,
whose keys are fixed test seeds."""
import importlib.util
import json
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from prismpath import canon  # noqa: E402
from prismpath.distribution import envelope as env  # noqa: E402
from prismpath.distribution.kinds import Refused  # noqa: E402
from prismpath.hotswap import policy_pack  # noqa: E402

REPO = Path(__file__).resolve().parent.parent


def _generator():
    spec = importlib.util.spec_from_file_location("gen_distribution_corpus",
                                                  REPO / "portable" / "gen_distribution_corpus.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GEN = _generator()
BODY = GEN.image()


def _build(**changes):
    doc = GEN.envelope_doc(BODY, **changes)
    return env.build(doc["artifact"], BODY, stream=doc["stream"], seq=doc["seq"],
                     policy_sha256=doc["policy_sha256"], targets=doc["targets"], not_before=doc["not_before"],
                     expires=doc["expires"], replaces=doc["replaces"], widens=doc["widens"], meta=doc["meta"])


def _refused(cause, call, *args):
    with pytest.raises(Refused) as caught:
        call(*args)
    assert caught.value.cause == cause


def test_case_001_round_trip_keeps_the_envelope_id():
    """case_001: E1, E2, E3, S1. build, seal, unseal and read give back the same bytes and id."""
    envelope_bytes = _build()
    assert envelope_bytes == canon.canon2_bytes(GEN.envelope_doc(BODY))
    sealed = env.seal(envelope_bytes, [GEN.test_key("A")])
    out, entries = env.unseal(sealed)
    assert out == envelope_bytes and len(entries) == 1
    assert entries[0][0] == env.key_id(GEN.public_raw(GEN.test_key("A")))
    read = env.read(out)
    assert read.envelope_id == env.envelope_id(envelope_bytes) == canon.sha256_hex(envelope_bytes)
    assert read.artifact == "policy.ppt" and read.targets == ("host",) and read.seq == 1
    _priv, Public, _ser, _invalid = policy_pack._ed25519()
    Public.from_public_bytes(GEN.public_raw(GEN.test_key("A"))).verify(entries[0][1], env.DOMAIN + envelope_bytes)
    assert env.DOMAIN == b"prismpath.dist/1\x00" and len(env.DOMAIN) == 17


def test_case_002_a_missing_member_is_bad_format():
    """case_002: E1, V4."""
    doc = GEN.envelope_doc(BODY)
    for member in sorted(doc):
        partial = {name: value for name, value in doc.items() if name != member}
        _refused("dist:bad-format", env.read, canon.canon2_bytes(partial))


def test_case_003_an_extra_member_is_bad_format():
    """case_003: E1, V4."""
    _refused("dist:bad-format", env.read, canon.canon2_bytes(GEN.envelope_doc(BODY, note="x")))


def test_case_004_members_out_of_canonical_order_are_not_canonical():
    """case_004: E2, V4. canon/2 in another spelling is refused and never respelled."""
    doc = GEN.envelope_doc(BODY)
    reordered = json.dumps(dict(sorted(doc.items(), reverse=True)), separators=(",", ":")).encode()
    _refused("document:not-canonical", env.read, reordered)
    _refused("document:not-canonical", env.read, canon.canon2_bytes(doc) + b"\n")


def test_case_005_an_unknown_artifact_or_target_kind_is_bad_format():
    """case_005: E8."""
    _refused("dist:bad-format", env.read, canon.canon2_bytes(GEN.envelope_doc(BODY, artifact="policy.zip")))
    _refused("dist:bad-format", env.read, canon.canon2_bytes(GEN.envelope_doc(BODY, targets=["host", "toaster"])))
    with pytest.raises(Refused):
        _build(targets=["toaster"])


def test_case_006_expires_not_above_not_before_is_bad_format():
    """case_006: E5. On a policy kind expires must be above not_before. The writer refuses it too."""
    for expires in (GEN.NOT_BEFORE, GEN.NOT_BEFORE - 1, 0):
        _refused("dist:bad-format", env.read, canon.canon2_bytes(GEN.envelope_doc(BODY, expires=expires)))
    with pytest.raises(Refused):
        _build(expires=GEN.NOT_BEFORE)


def test_case_007_an_envelope_over_2048_bytes_is_bad_format():
    """case_007: E6, V2. The writer and the container both refuse 2,049 bytes. The body bound half is the
    verifier's (test_distribution_verify)."""
    doc = GEN.envelope_doc(BODY)
    doc["meta"] = {**doc["meta"], "overlay_of": ""}
    doc["meta"]["overlay_of"] = "o" * (env.MAX_ENVELOPE + 1 - len(canon.canon2_bytes(doc)))
    long = canon.canon2_bytes(doc)
    assert len(long) == 2049
    _refused("dist:bad-format", env.read, long)
    _refused("dist:bad-format", env.seal, long, [GEN.test_key("A")])
    _refused("dist:bad-format", env.unseal, env.seal_entries(long, [("00" * 32, b"\0" * 64)]))
    doc["meta"]["overlay_of"] = doc["meta"]["overlay_of"][1:]
    assert len(env.read(canon.canon2_bytes(doc)).raw) == 2048


def test_case_008_every_malformed_container_is_bad_format():
    """case_008: S2, V2. Wrong magic, wrong version, a short one, unsorted entries, a repeated key, zero
    entries and five entries."""
    good = _build()
    sealed = env.seal(good, [GEN.test_key("A")])
    a = env.unseal(sealed)[1][0]
    b = env.unseal(env.seal(good, [GEN.test_key("B")]))[1][0]
    low, high = sorted([a, b])
    five = sorted(env.unseal(env.seal(good, [GEN.test_key(name)]))[1][0] for name in "ABRQU")
    for bad in (b"XXDE" + sealed[4:], sealed[:4] + b"\x02" + sealed[5:], sealed[:-1], sealed + b"\0",
                env.seal_entries(good, [high, low]), env.seal_entries(good, [a, a]), env.seal_entries(good, []),
                env.seal_entries(good, five), b"PPDE", b"", "text"):
        _refused("dist:bad-format", env.unseal, bad)
    assert env.unseal(env.seal_entries(good, [low, high]))[1] == [low, high]
    with pytest.raises(Refused):
        env.seal(good, [GEN.test_key(name) for name in "ABRQU"])
    with pytest.raises(Refused):
        env.seal(good, [GEN.test_key("A"), GEN.test_key("A")])
    with pytest.raises(Refused):
        env.seal(good, [])


def test_case_015_the_body_travels_unchanged_and_its_hash_is_the_certified_image_hash(tmp_path):
    """case_015: E4. The envelope names the image by the hash a ppt-pack/1 manifest certifies, and the body is
    the image bytes, untouched."""
    pp = policy_pack
    keys = pp.keygen(str(tmp_path / "keys"))
    ppt = tmp_path / "policy.ppt"
    ppt.write_bytes(BODY)
    manifest = pp.build_pack(str(ppt), {"x": "int"}, 1, "dist-demo", keys["private"], keys["public"])
    read = env.read(_build())
    assert read.body_sha256 == manifest["image_sha256"] == canon.sha256_hex(ppt.read_bytes())
    assert ppt.read_bytes() == BODY and read.body_size == len(BODY)
    for member in ("counts", "fields", "wcet_cycles"):
        assert read.meta[member] == manifest[member]
    assert read.meta["qualification"] == manifest["envelope_id"]


def test_the_writer_refuses_what_the_reader_refuses():
    """E1: a writer never writes an envelope a reader would refuse (meta members, stream, seq, hashes)."""
    for changes in ({"meta": {}}, {"meta": {**GEN.image_meta(BODY), "note": "x"}}, {"stream": "Host"},
                    {"stream": "@trust"}, {"seq": 0}, {"seq": 2 ** 53}, {"replaces": "AB" * 32},
                    {"targets": ["host", "host"]}, {"meta": {**GEN.image_meta(BODY), "fields": {"x": {"y": 1}}}}):
        with pytest.raises(Refused):
            _build(**changes)
    assert env.read(_build(meta={**GEN.image_meta(BODY), "overlay_of": "base"})).meta["overlay_of"] == "base"
