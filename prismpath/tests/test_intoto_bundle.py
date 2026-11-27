# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Root statement chains as in-toto statements, and DSSE envelopes as Sigstore bundles v0.3.

Pinned here: every statement of a chain exports as an envelope whose predicate is the statement byte for byte and
whose subject is its hash; a changed statement, a reordered or dropped envelope, an unpinned key and a re-signed
predicate are refused; the statements file keeps its bytes; a core run envelope and a root statement envelope round
trip through a bundle; a bundle with a log entry, a certificate or a hint that is not the key id is refused."""
import base64
import copy
import hashlib
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from prismpath.agent import classifier, policy, run as runmod  # noqa: E402
from prismpath.kernel import canon2  # noqa: E402
from prismpath.ledgers import intoto, root_statement as rs  # noqa: E402

POL = policy.Policy.load()


def _leaves(n):
    return [hashlib.sha256(b"receipt %d" % i).hexdigest() for i in range(n)]


@pytest.fixture
def chain(tmp_path):
    info = rs.keygen(str(tmp_path / "keys"), "instance")
    key = rs.InstanceKey.load(info["private"])
    path = tmp_path / "run.audit.roots.jsonl"
    signer = rs.RootSigner(key, str(path), rs.LOG_AUDIT)
    leaves = _leaves(7)
    for size in (2, 5, 7):
        signer.sign(rs.merkle_root(leaves[:size]), size, "test")
    return key, Path(info["public"]), path


def test_every_statement_exports_with_its_hash_as_subject(chain):
    key, pub, path = chain
    before = path.read_bytes()
    envelopes = intoto.export_root_statements(path, key)
    assert path.read_bytes() == before
    statements, _ = rs.read_statements(str(path))
    assert len(envelopes) == 3
    for envelope, statement in zip(envelopes, statements):
        body = canon2.loads(base64.b64decode(envelope["payload"]))
        assert body["predicateType"] == intoto.ROOT_STATEMENT_PREDICATE_TYPE
        assert body["predicate"] == statement
        assert body["subject"] == [{"name": f"audit-log/{statement['seq']}",
                                    "digest": {"sha256": rs.statement_hash(statement)}}]
        assert envelope["signatures"][0]["keyid"] == key.key_id
    report = intoto.verify_root_statements(envelopes, path, [pub])
    assert report == {"statements": 3, "pinned": True, "last_statement_sha256": rs.statement_hash(statements[-1])}
    assert intoto.verify_root_statements(envelopes, path)["pinned"] is False


def test_a_changed_statement_file_is_refused(chain):
    key, pub, path = chain
    envelopes = intoto.export_root_statements(path, key)
    lines = path.read_text().splitlines()
    doc = canon2.loads(lines[1].encode())
    doc["leaves"] = 4
    lines[1] = canon2.dumps(doc).decode()
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(intoto.Bad):
        intoto.verify_root_statements(envelopes, path, [pub])


def test_reordered_or_dropped_envelopes_are_refused(chain):
    key, pub, path = chain
    envelopes = intoto.export_root_statements(path, key)
    with pytest.raises(intoto.Bad):
        intoto.verify_root_statements([envelopes[1], envelopes[0], envelopes[2]], path, [pub])
    with pytest.raises(intoto.Bad):
        intoto.verify_root_statements(envelopes[:2], path, [pub])


def test_an_unpinned_key_and_another_signer_are_refused(chain, tmp_path):
    key, pub, path = chain
    other = rs.keygen(str(tmp_path / "other"), "instance")
    with pytest.raises(intoto.Bad):
        intoto.verify_root_statements(intoto.export_root_statements(path, key), path, [Path(other["public"])])
    with pytest.raises(intoto.Bad):
        intoto.export_root_statements(path, rs.InstanceKey.load(other["private"]))


def test_a_resigned_predicate_is_refused(chain, tmp_path):
    key, pub, path = chain
    envelopes = intoto.export_root_statements(path, key)
    body = canon2.loads(base64.b64decode(envelopes[2]["payload"]))
    body["predicate"] = dict(body["predicate"], leaves=6)
    forged = intoto.sign_statement(body, key)
    with pytest.raises(intoto.Bad):
        intoto.verify_root_statements(envelopes[:2] + [forged], path, [pub])


@pytest.fixture
def sealed_agent_run(tmp_path):
    cfg = classifier.Config.for_workspace(Path("/tmp/ws"))
    store = runmod.RunStore(tmp_path / "runs")
    run = store.open("s1", POL.image)
    for n in range(3):
        raw = POL.reading_bytes(classifier.classify({"tool": "list_dir", "args": {"path": f"d{n}"}}, cfg))
        run.append(raw, POL.decide(raw).verdict)
    run.seal(tmp_path / "keys", time_us=1762257600123000)
    return run.dir


def test_a_session_envelope_round_trips_through_a_bundle(sealed_agent_run):
    envelope = intoto.export(sealed_agent_run)[0]
    bundle = intoto.to_bundle(envelope)
    assert bundle["mediaType"] == "application/vnd.dev.sigstore.bundle.v0.3+json"
    assert bundle["verificationMaterial"] == {"publicKey": {"hint": envelope["signatures"][0]["keyid"]},
                                              "tlogEntries": []}
    assert bundle["dsseEnvelope"]["payload"] == envelope["payload"]
    assert intoto.from_bundle(bundle) == envelope
    summary = intoto.verify([intoto.from_bundle(bundle)], sealed_agent_run,
                            pin_authority=sealed_agent_run / "authority.pub", pin_instance=sealed_agent_run / "instance.pub")
    assert summary["receipts"] == 3


def test_a_root_statement_envelope_round_trips_through_a_bundle(chain):
    key, pub, path = chain
    envelopes = [intoto.from_bundle(intoto.to_bundle(e)) for e in intoto.export_root_statements(path, key)]
    assert intoto.verify_root_statements(envelopes, path, [pub])["statements"] == 3


def test_a_bundle_this_reader_cannot_check_is_refused(chain):
    key, _pub, path = chain
    bundle = intoto.to_bundle(intoto.export_root_statements(path, key)[0])
    for change in (
        lambda b: b["verificationMaterial"].__setitem__("tlogEntries", [{"logIndex": "1"}]),
        lambda b: b["verificationMaterial"].__setitem__("certificate", {"rawBytes": "AA=="}),
        lambda b: b["verificationMaterial"]["publicKey"].__setitem__("hint", "0" * 64),
        lambda b: b.__setitem__("mediaType", "application/vnd.dev.sigstore.bundle+json;version=0.2"),
        lambda b: b["dsseEnvelope"]["signatures"].append(dict(b["dsseEnvelope"]["signatures"][0])),
    ):
        changed = copy.deepcopy(bundle)
        change(changed)
        with pytest.raises(intoto.Bad):
            intoto.from_bundle(changed)
    with pytest.raises(intoto.Bad):
        intoto.to_bundle({"payloadType": intoto.PAYLOAD_TYPE, "payload": "", "signatures": []})
