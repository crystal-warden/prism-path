# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""in-toto Statement v1 and DSSE v1.0 export and verification for sealed core runs."""
import base64
import copy
import shutil
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from prismpath.agent import classifier, policy, run as runmod  # noqa: E402
from prismpath.kernel import canon2  # noqa: E402
from prismpath.ledgers import core_evidence, intoto, root_statement  # noqa: E402

POL = policy.Policy.load()
CASES = Path(__file__).resolve().parent / "fixtures" / "core_evidence" / "cases.jsonl"


def _reading(n: int) -> bytes:
    cfg = classifier.Config.for_workspace(Path("/tmp/ws"))
    return POL.reading_bytes(classifier.classify({"tool": "list_dir", "args": {"path": f"d{n}"}}, cfg))


@pytest.fixture
def sealed_agent_run(tmp_path):
    store = runmod.RunStore(tmp_path)
    run = store.open("s1", POL.image)
    for n in range(4):
        raw = _reading(n)
        run.append(raw, POL.decide(raw).verdict)
    keys = tmp_path / "keys"
    run.seal(keys, time_us=1762257600123000)
    return run.dir, keys


def test_pae_matches_dsse_spec_test_vector():
    """Published DSSE v1.0 specification test vector (protocol.md)."""
    payload_type = "http://example.com/HelloWorld"
    payload = b"hello world"
    expected_ascii = b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
    expected_hex = (
        "44535345763120323920687474703a2f2f6578616d706c652e636f6d2f"
        "48656c6c6f576f726c642031312068656c6c6f20776f726c64"
    )
    computed = intoto.pae(payload_type, payload)
    assert computed == expected_ascii
    assert computed.hex() == expected_hex
    # Also check the in-toto payloadType length (28 bytes)
    body = b'{"_type":"https://in-toto.io/Statement/v1"}'
    assert intoto.pae(intoto.PAYLOAD_TYPE, body) == b"DSSEv1 28 application/vnd.in-toto+json 43 " + body


def test_round_trip_agent_run_export_and_verify(sealed_agent_run):
    run_dir, keys = sealed_agent_run
    envelopes = intoto.export(run_dir)
    assert len(envelopes) == 1
    env = envelopes[0]
    assert env["payloadType"] == "application/vnd.in-toto+json"
    assert len(env["signatures"]) == 1

    payload_bytes = base64.b64decode(env["payload"])
    stmt = canon2.loads(payload_bytes)
    assert stmt["_type"] == "https://in-toto.io/Statement/v1"
    assert stmt["predicateType"] == "https://prismpath.dev/attestations/core-run/v1"

    by_name = {item["name"]: item["digest"]["sha256"] for item in stmt["subject"]}
    assert by_name["receipts.jsonl"] == core_evidence.sha256_hex((run_dir / "receipts.jsonl").read_bytes())
    assert by_name["receipts.roots.jsonl"] == core_evidence.sha256_hex((run_dir / "receipts.roots.jsonl").read_bytes())

    root_doc = canon2.loads((run_dir / "receipts.roots.jsonl").read_bytes().rstrip(b"\n"))
    manifest = canon2.loads((run_dir / "run.json").read_bytes().rstrip(b"\n"))
    pred = stmt["predicate"]
    for key, value in root_doc.items():
        assert pred[key] == value
    assert pred["leaves"] == 4
    assert pred["root"] == root_doc["root"]
    assert pred["image_sha256"] == core_evidence.sha256_hex(POL.image)
    assert pred["images_sha256"] == manifest["images_sha256"]
    assert pred["instance_key_id"] == manifest["instance_key_id"] == root_doc["key_id"]
    assert pred["authority_key_id"] == manifest["authority_key_id"]

    summary = intoto.verify(envelopes, run_dir, keys)
    assert summary["receipts"] == 4
    assert summary["replayed"] == 4
    assert summary["disagree"] == 0
    assert summary["root_statement"] == "signed"


def test_round_trip_core_evidence_produce_and_import(tmp_path):
    run_dir = tmp_path / "run"
    keys = tmp_path / "keys"
    manifest = core_evidence.produce(CASES, run_dir, keys)
    envelopes = intoto.export(run_dir)
    assert len(envelopes) == 1

    # Remove receipts.roots.jsonl and restore it via import_envelopes
    roots_path = run_dir / "receipts.roots.jsonl"
    original_roots = roots_path.read_bytes()
    roots_path.unlink()
    summary = intoto.import_envelopes(envelopes, run_dir, keys)
    assert roots_path.read_bytes() == original_roots
    assert summary["receipts"] == manifest["receipts"]
    assert summary["root_statement"] == "signed"


def test_flipped_byte_in_receipt_file_fails(sealed_agent_run, tmp_path):
    run_dir, keys = sealed_agent_run
    envelopes = intoto.export(run_dir)

    copy_dir = tmp_path / "tampered_run"
    shutil.copytree(run_dir, copy_dir)
    receipts_path = copy_dir / "receipts.jsonl"
    data = bytearray(receipts_path.read_bytes())
    data[len(data) // 2] ^= 0x01
    receipts_path.write_bytes(bytes(data))

    with pytest.raises(intoto.Bad, match="receipts.jsonl"):
        intoto.verify(envelopes, copy_dir, keys)


def test_flipped_byte_in_payload_fails(sealed_agent_run):
    run_dir, keys = sealed_agent_run
    envelopes = intoto.export(run_dir)

    tampered = copy.deepcopy(envelopes)
    raw_payload = bytearray(base64.b64decode(tampered[0]["payload"]))
    raw_payload[len(raw_payload) // 2] ^= 0x01
    tampered[0]["payload"] = base64.b64encode(bytes(raw_payload)).decode("ascii")

    with pytest.raises(intoto.Bad, match="PAE signature|canon/2"):
        intoto.verify(tampered, run_dir, keys)


def test_resigned_modified_predicate_fails_root_statement_equality(sealed_agent_run):
    run_dir, keys = sealed_agent_run
    envelopes = intoto.export(run_dir)

    tampered = copy.deepcopy(envelopes)
    stmt = canon2.loads(base64.b64decode(tampered[0]["payload"]))
    stmt["predicate"]["time_us"] += 1
    new_payload = canon2.dumps(stmt)
    signer = root_statement.InstanceKey.load(str(keys / "instance.key"))
    new_sig = signer.sign(intoto.pae(intoto.PAYLOAD_TYPE, new_payload))
    tampered[0]["payload"] = base64.b64encode(new_payload).decode("ascii")
    tampered[0]["signatures"][0]["sig"] = base64.b64encode(new_sig).decode("ascii")

    with pytest.raises(intoto.Bad, match="predicate does not equal"):
        intoto.verify(tampered, run_dir, keys)


def test_flipped_byte_in_signature_fails(sealed_agent_run):
    run_dir, keys = sealed_agent_run
    envelopes = intoto.export(run_dir)

    tampered = copy.deepcopy(envelopes)
    raw_sig = bytearray(base64.b64decode(tampered[0]["signatures"][0]["sig"]))
    raw_sig[0] ^= 0x01
    tampered[0]["signatures"][0]["sig"] = base64.b64encode(bytes(raw_sig)).decode("ascii")

    with pytest.raises(intoto.Bad, match="PAE signature"):
        intoto.verify(tampered, run_dir, keys)


def test_wrong_pinned_key_fails(sealed_agent_run, tmp_path):
    run_dir, keys = sealed_agent_run
    envelopes = intoto.export(run_dir)

    other_keys = tmp_path / "other_keys"
    core_evidence.ensure_keys(other_keys)

    # Wrong keys directory
    with pytest.raises(intoto.Bad, match="pinned"):
        intoto.verify(envelopes, run_dir, other_keys)

    # Wrong pinned instance key only
    with pytest.raises(intoto.Bad, match="pinned instance key"):
        intoto.verify(
            envelopes,
            run_dir,
            {"authority": keys / "authority.pub", "instance": other_keys / "instance.pub"},
        )

    # Wrong pinned authority key only
    with pytest.raises(intoto.Bad, match="pinned authority key"):
        intoto.verify(
            envelopes,
            run_dir,
            {"authority": other_keys / "authority.pub", "instance": keys / "instance.pub"},
        )

    # Wrong single pinned instance key bytes
    with pytest.raises(intoto.Bad, match="pinned instance key"):
        intoto.verify(envelopes, run_dir, (other_keys / "instance.pub").read_bytes())


def test_export_does_not_find_a_live_key_object_in_memory(sealed_agent_run, tmp_path):
    run_dir, keys = sealed_agent_run
    held = root_statement.InstanceKey.load(str(keys / "instance.key"))  # live in this process
    assert held.public_raw == (run_dir / "instance.pub").read_bytes()
    elsewhere = tmp_path / "elsewhere" / "deep" / "run"
    shutil.copytree(run_dir, elsewhere)
    assert not hasattr(intoto, "_KEY_CACHE")
    assert root_statement.InstanceKey.__init__.__module__ == root_statement.__name__
    with pytest.raises(intoto.Bad, match="cannot find the instance private key"):
        intoto.export(elsewhere)
    assert len(intoto.export(elsewhere, instance_key=held)) == 1


def test_unpinned_verify_says_it_is_unpinned(sealed_agent_run):
    run_dir, keys = sealed_agent_run
    envelopes = intoto.export(run_dir)
    unpinned = intoto.verify(envelopes, run_dir)
    assert unpinned["pinned"] is False
    assert unpinned["root_statement"] == "signed-unpinned"
    pinned = intoto.verify(envelopes, run_dir, keys)
    assert pinned["pinned"] is True
    assert pinned["root_statement"] == "signed"


def test_failed_import_leaves_the_run_directory_as_it_was(tmp_path):
    run_dir = tmp_path / "run"
    keys = tmp_path / "keys"
    core_evidence.produce(CASES, run_dir, keys)
    envelopes = intoto.export(run_dir)
    roots_path = run_dir / "receipts.roots.jsonl"
    roots_path.unlink()
    before = sorted(p.name for p in run_dir.iterdir())
    tampered = copy.deepcopy(envelopes)
    raw = bytearray(base64.b64decode(tampered[0]["payload"]))
    raw[len(raw) // 2] ^= 1
    tampered[0]["payload"] = base64.b64encode(bytes(raw)).decode("ascii")
    with pytest.raises(intoto.Bad):
        intoto.import_envelopes(tampered, run_dir, keys)
    assert not roots_path.exists()
    assert sorted(p.name for p in run_dir.iterdir()) == before
