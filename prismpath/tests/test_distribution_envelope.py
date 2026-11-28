# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The distribution envelope and the sealed envelope (spec-policy-distribution.md, section 4). Each test names
the conformance case of section 20 it covers. The corpus cases come from portable/gen_distribution_corpus.py,
whose keys are fixed test seeds."""
import base64
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
                     policy_sha256=doc["policy_sha256"], release=doc["release"], targets=doc["targets"], not_before=doc["not_before"],
                     expires=doc["expires"], replaces=doc["replaces"], widens=doc["widens"], meta=doc["meta"])


def _refused(cause, call, *args):
    with pytest.raises(Refused) as caught:
        call(*args)
    assert caught.value.cause == cause


def _dsse_pae(payload_type: bytes, payload: bytes) -> bytes:
    """The DSSE v1 pre-authentication encoding written out from the protocol text, not from intoto.pae."""
    return b" ".join([b"DSSEv1", str(len(payload_type)).encode(), payload_type, str(len(payload)).encode(), payload])


def test_case_001_round_trip_keeps_the_envelope_id():
    """case_001: E1, E2, E3, S1, S2. build, seal, unseal and read give back the same bytes and id, the
    signature covers the DSSE encoding of the envelope bytes, and the entries come before the envelope."""
    envelope_bytes = _build()
    assert envelope_bytes == canon.canon2_bytes(GEN.envelope_doc(BODY))
    sealed = env.seal(envelope_bytes, [GEN.test_key("A")])
    out, entries = env.unseal(sealed)
    assert out == envelope_bytes and len(entries) == 1
    assert entries[0][0] == env.key_id(GEN.public_raw(GEN.test_key("A")))
    read = env.read(out)
    assert read.envelope_id == env.envelope_id(envelope_bytes) == canon.sha256_hex(envelope_bytes)
    assert read.artifact == "policy.ppt" and read.targets == ("host",) and read.seq == 1
    from prismpath.onion import keys as onion_keys
    signed = _dsse_pae(b"application/vnd.prismpath.dist+json", envelope_bytes)
    assert signed.startswith(b"DSSEv1 35 application/vnd.prismpath.dist+json ") and len(b"DSSEv1 35 application/vnd.prismpath.dist+json ") == 46
    assert env.signed_message(envelope_bytes) == signed
    assert onion_keys.verify(GEN.public_raw(GEN.test_key("A")), entries[0][1], signed)
    assert sealed[:6] == b"PPDE\x01\x01" and sealed[6:38] == bytes.fromhex(entries[0][0])
    assert sealed[102:104] == len(envelope_bytes).to_bytes(2, "little") and sealed[104:] == envelope_bytes


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
    doc["meta"] = {**doc["meta"], "fields": {**doc["meta"]["fields"], "pad": ""}}
    doc["meta"]["fields"]["pad"] = "o" * (env.MAX_ENVELOPE + 1 - len(canon.canon2_bytes(doc)))
    long = canon.canon2_bytes(doc)
    assert len(long) == 2049
    _refused("dist:bad-format", env.read, long)
    _refused("dist:bad-format", env.seal, long, [GEN.test_key("A")])
    _refused("dist:bad-format", env.unseal, env.seal_entries(long, [("00" * 32, b"\0" * 64)]))
    doc["meta"]["fields"]["pad"] = doc["meta"]["fields"]["pad"][1:]
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
                sealed[:5] + b"\x02" + sealed[6:], sealed + b"\0" * (env.MAX_SEALED + 1 - len(sealed)),
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


def test_release_ids_and_the_trust_stream_zeros():
    """E1, E10: `release` is 64 hex digits, and 64 zeros on `@trust`."""
    for release in ("", "AB" * 32, "ab" * 31):
        _refused("dist:bad-format", env.read, canon.canon2_bytes(GEN.envelope_doc(BODY, release=release)))
    trust = GEN.envelope_doc(BODY, artifact="trust.revocation", stream=env.TRUST_STREAM, policy_sha256=env.ZERO_HASH,
                             expires=0, meta={})
    _refused("dist:bad-format", env.read, canon.canon2_bytes(trust))
    assert env.read(canon.canon2_bytes({**trust, "release": env.ZERO_HASH})).release == env.ZERO_HASH


def test_case_115_the_release_id_is_the_hash_of_the_sorted_artifact_pairs():
    """case_115: E10. The corpus's vectors, recomputed by hand, and one changed body changes the id."""
    corpus = json.loads((REPO / "portable" / "conformance" / "distribution.json").read_text(encoding="utf-8"))
    vectors = corpus["release_ids"]
    for vector in vectors:
        pairs = sorted(vector["artifacts"])
        assert vector["release"] == canon.sha256_hex(canon.canon2_bytes(pairs))
        assert env.release_id(reversed([tuple(pair) for pair in vector["artifacts"]])) == vector["release"]
    assert vectors[0]["release"] != vectors[1]["release"]
    with pytest.raises(Refused):
        env.release_id([])
    with pytest.raises(Refused):
        env.release_id([("policy.ppt", "aa" * 32), ("policy.ppt", "bb" * 32)])
    for kind in ("trust.widening", "trust.revocation", "trust.rotation"):
        with pytest.raises(Refused):
            env.release_id([("policy.ppt", "aa" * 32), (kind, "bb" * 32)])
    with pytest.raises(Refused):
        env.release_id([("policy.zip", "aa" * 32)])
    with pytest.raises(Refused):
        env.release_id([("policy.ppt", "AA" * 32)])


def test_case_116_a_sealed_envelope_maps_to_dsse_json_and_back():
    """case_116: S7, S1. The DSSE JSON form reads back to the same sealed bytes, and a DSSE check written
    from the protocol text verifies it: decode the payload, encode PAE, verify each signature by its keyid."""
    sealed = env.seal(_build(), [GEN.test_key("A"), GEN.test_key("B")])
    doc = env.to_dsse(sealed)
    assert env.from_dsse(json.loads(json.dumps(doc))) == sealed
    assert doc["payloadType"] == "application/vnd.prismpath.dist+json"
    from prismpath.onion import keys as onion_keys
    publics = {env.key_id(GEN.public_raw(GEN.test_key(name))): GEN.public_raw(GEN.test_key(name)) for name in "AB"}
    signed = _dsse_pae(doc["payloadType"].encode(), base64.b64decode(doc["payload"]))
    for member in doc["signatures"]:
        assert onion_keys.verify(publics[member["keyid"]], base64.b64decode(member["sig"]), signed)
    urlsafe = {**doc, "payload": base64.urlsafe_b64encode(base64.b64decode(doc["payload"])).decode().rstrip("="),
               "signatures": [{"keyid": member["keyid"],
                               "sig": base64.urlsafe_b64encode(base64.b64decode(member["sig"])).decode()}
                              for member in doc["signatures"]]}
    assert env.from_dsse(urlsafe) == sealed                        # DSSE allows URL safe base64, padded or not
    mixed = base64.b64encode(b"\xfb\xff\xfe" * 4).decode()         # holds + and /
    mixed = mixed[:2] + "-" + mixed[3:]
    for broken in ({**doc, "payloadType": "application/json"}, {**doc, "payload": "!"}, {**doc, "signatures": []},
                   {**doc, "payload": mixed},
                   {**doc, "extra": 1}, {**doc, "signatures": doc["signatures"] * 2}):
        with pytest.raises(Refused):
            env.from_dsse(broken)


def test_case_117_the_signature_block_is_not_signed():
    """case_117: S6. Entries added, removed or reordered never change the envelope id. A reordered DSSE form
    maps to the same sealed bytes. Whether the result is signed is the verifier's (test_distribution_verify)."""
    envelope_bytes = _build()
    sealed = env.seal(envelope_bytes, [GEN.test_key("A"), GEN.test_key("B")])
    entries = env.unseal(sealed)[1]
    unknown = env.unseal(env.seal(envelope_bytes, [GEN.test_key("U")]))[1][0]
    for changed in ([entries[0]], [entries[1]], sorted(entries + [unknown]), [unknown]):
        out, _ = env.unseal(env.seal_entries(envelope_bytes, changed))
        assert env.envelope_id(out) == env.envelope_id(envelope_bytes)
    doc = env.to_dsse(sealed)
    assert env.from_dsse({**doc, "signatures": list(reversed(doc["signatures"]))}) == sealed
