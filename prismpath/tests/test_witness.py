# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The outside witness: a second key that cosigns a root only when it extends the last one it cosigned.

Pinned here: a growing chain is cosigned and reads as witnessed; the witness refuses a shorter log, a fork at the
same seq, the same leaves under another root, a grown root without a consistency proof, a broken prev link, a
signer it does not pin and a bad signature; it resumes from its state file after a restart; a reader who pins the
witness finds a cosignature whose statement was cut from the chain; a core run's root statement is cosigned too;
and nothing the witness does changes a byte of the statements or the receipts."""
import hashlib
import os

import pytest

pytest.importorskip("cryptography")

from prismpath import canon  # noqa: E402
from prismpath.kernel import canon2  # noqa: E402
from prismpath.ledgers import core_evidence, root_statement as rs, witness  # noqa: E402


def _key(tmp_path, name):
    info = rs.keygen(str(tmp_path / "keys"), name)
    return rs.InstanceKey.load(info["private"]), open(info["public"], "rb").read()


def _leaves(n):
    return [hashlib.sha256(b"receipt %d" % i).hexdigest() for i in range(n)]


@pytest.fixture
def setup(tmp_path):
    instance, instance_pub = _key(tmp_path, "instance")
    wkey, wpub = _key(tmp_path, "witness")
    statements = str(tmp_path / "run.audit.roots.jsonl")
    signer = rs.RootSigner(instance, statements, rs.LOG_AUDIT)
    w = witness.Witness(wkey, [instance_pub], str(tmp_path / "witness.state"))
    return instance, instance_pub, wkey, wpub, statements, signer, w


def _sign(signer, leaves):
    return signer.sign(rs.merkle_root(leaves), len(leaves), "test")


def test_a_growing_chain_is_witnessed(setup):
    _i, _ipub, _w, wpub, path, signer, w = setup
    all_leaves = _leaves(9)
    sizes = [2, 5, 9]
    cosigs, prev = [], 0
    for size in sizes:
        statement = _sign(signer, all_leaves[:size])
        proof = rs.consistency_proof(all_leaves[:size], prev) if prev else None
        cosig = w.cosign(statement, proof)
        witness.append(witness.witness_path_for(path), cosig)
        cosigs.append(cosig)
        prev = size
    statements, findings = rs.read_statements(path)
    read, rfind = witness.read(witness.witness_path_for(path))
    report = witness.verify(statements, read, [wpub], rfind)
    assert findings == [] and report["status"] == witness.WITNESSED
    assert report["witnessed_statements"] == 3 and report["unwitnessed_tail"] == 0
    assert cosigs[0]["statement_sha256"] == rs.statement_hash(statements[0])


def test_the_witness_file_sits_beside_the_statements():
    assert witness.witness_path_for("a/run.audit.roots.jsonl") == "a/run.audit.roots.witness.jsonl"
    assert witness.witness_path_for("swaps.log.roots") == "swaps.log.roots.witness.jsonl"


def test_a_witness_never_changes_the_statements(setup):
    _i, _ipub, _w, _wpub, path, signer, w = setup
    _sign(signer, _leaves(3))
    before = open(path, "rb").read()
    statements, _ = rs.read_statements(path)
    witness.append(witness.witness_path_for(path), w.cosign(statements[0]))
    assert open(path, "rb").read() == before


def test_a_shorter_log_is_refused(tmp_path, setup):
    instance, _ipub, _w, _wpub, path, signer, w = setup
    w.cosign(_sign(signer, _leaves(5)))
    # the deployment deletes its statements and signs a shorter story with the same key
    os.remove(path)
    statement = rs.make_statement(instance, log=rs.LOG_AUDIT, seq=1, root=rs.merkle_root(_leaves(3)), leaves=3,
                                  prev=w.state[next(iter(w.state))]["statement_sha256"], trigger="test")
    with pytest.raises(witness.Refused) as err:
        w.cosign(statement)
    assert err.value.reason == "truncated"


def test_a_fork_at_the_same_seq_is_refused(setup):
    instance, _ipub, _w, _wpub, _path, signer, w = setup
    first = _sign(signer, _leaves(4))
    w.cosign(first)
    other = rs.make_statement(instance, log=rs.LOG_AUDIT, seq=0, root=rs.merkle_root(_leaves(6)), leaves=6,
                              prev="", trigger="test")
    with pytest.raises(witness.Refused) as err:
        w.cosign(other)
    assert err.value.reason == "fork"
    # the same statement again is the same answer, not a fork
    assert w.cosign(first)["statement_sha256"] == rs.statement_hash(first)


def test_same_leaves_under_another_root_is_a_fork(setup):
    instance, _ipub, _w, _wpub, _path, signer, w = setup
    first = _sign(signer, _leaves(4))
    w.cosign(first)
    other = rs.make_statement(instance, log=rs.LOG_AUDIT, seq=1, root=rs.merkle_root(_leaves(5)[1:]), leaves=4,
                              prev=rs.statement_hash(first), trigger="test")
    with pytest.raises(witness.Refused) as err:
        w.cosign(other)
    assert err.value.reason == "fork"


def test_growth_needs_a_consistency_proof(setup):
    instance, _ipub, _w, _wpub, _path, signer, w = setup
    leaves = _leaves(8)
    first = _sign(signer, leaves[:3])
    w.cosign(first)
    # a root over a rewritten history: same count growth, but the first three leaves changed
    rewritten = _leaves(9)[1:]
    forged = rs.make_statement(instance, log=rs.LOG_AUDIT, seq=1, root=rs.merkle_root(rewritten), leaves=8,
                               prev=rs.statement_hash(first), trigger="test")
    with pytest.raises(witness.Refused) as err:
        w.cosign(forged, rs.consistency_proof(rewritten, 3))
    assert err.value.reason == "inconsistent"
    with pytest.raises(witness.Refused):
        w.cosign(forged)                 # no proof at all
    good = _sign(signer, leaves)
    assert w.cosign(good, rs.consistency_proof(leaves, 3))["leaves"] == 8


def test_a_broken_prev_link_is_refused(setup):
    instance, _ipub, _w, _wpub, _path, signer, w = setup
    leaves = _leaves(4)
    w.cosign(_sign(signer, leaves[:2]))
    bad = rs.make_statement(instance, log=rs.LOG_AUDIT, seq=1, root=rs.merkle_root(leaves), leaves=4,
                            prev="0" * 64, trigger="test")
    with pytest.raises(witness.Refused) as err:
        w.cosign(bad, rs.consistency_proof(leaves, 2))
    assert err.value.reason == "chain_broken"


def test_an_unpinned_signer_and_a_bad_signature_are_refused(tmp_path, setup):
    _i, _ipub, _w, _wpub, _path, signer, w = setup
    stranger, _spub = _key(tmp_path, "stranger")
    with pytest.raises(witness.Refused) as err:
        w.cosign(rs.make_statement(stranger, log=rs.LOG_AUDIT, seq=0, root="", leaves=0, prev="", trigger="t"))
    assert err.value.reason == "unpinned_signer"
    statement = _sign(signer, _leaves(2))
    statement["root"] = rs.merkle_root(_leaves(3)[1:])
    with pytest.raises(witness.Refused) as err:
        w.cosign(statement)
    assert err.value.reason == "bad_signature"


def test_the_witness_must_be_a_second_party(tmp_path):
    instance, instance_pub = _key(tmp_path, "instance")
    with pytest.raises(ValueError):
        witness.Witness(instance, [instance_pub], str(tmp_path / "s"))
    with pytest.raises(ValueError):
        witness.Witness(instance, [], str(tmp_path / "s"))


def test_the_witness_resumes_after_a_restart(tmp_path, setup):
    instance, instance_pub, wkey, _wpub, _path, signer, w = setup
    w.cosign(_sign(signer, _leaves(6)))
    restarted = witness.Witness(wkey, [instance_pub], w.state_path)
    shorter = rs.make_statement(instance, log=rs.LOG_AUDIT, seq=1, root=rs.merkle_root(_leaves(2)), leaves=2,
                                prev=restarted.state[next(iter(restarted.state))]["statement_sha256"], trigger="t")
    with pytest.raises(witness.Refused) as err:
        restarted.cosign(shorter)
    assert err.value.reason == "truncated"


def test_a_reader_finds_a_statement_cut_from_the_chain(setup):
    _i, _ipub, _w, wpub, path, signer, w = setup
    leaves = _leaves(6)
    wpath = witness.witness_path_for(path)
    witness.append(wpath, w.cosign(_sign(signer, leaves[:3])))
    witness.append(wpath, w.cosign(_sign(signer, leaves), rs.consistency_proof(leaves, 3)))
    # the tail of the statements file is deleted; the chain alone still verifies
    lines = open(path).read().splitlines(keepends=True)
    open(path, "w").write(lines[0])
    statements, _ = rs.read_statements(path)
    chain = rs.verify_chain(statements, [], lambda n: rs.merkle_root(leaves[:n]), 3)
    assert chain["status"] == rs.SIGNED_UNPINNED
    read, _ = witness.read(wpath)
    report = witness.verify(statements, read, [wpub])
    assert report["status"] == witness.INVALID
    assert report["findings"][0]["finding"] == "statement_missing" and report["findings"][0]["leaves"] == 6


def test_an_unpinned_witness_says_nothing(tmp_path, setup):
    _i, _ipub, _w, _wpub, path, signer, w = setup
    statement = _sign(signer, _leaves(2))
    cosig = w.cosign(statement)
    _other, other_pub = _key(tmp_path, "other")
    report = witness.verify([statement], [cosig], [other_pub])
    assert report["status"] == witness.UNWITNESSED and report["findings"] == []
    assert witness.verify([statement], [], [other_pub])["status"] == witness.UNWITNESSED


def test_a_tampered_cosignature_is_a_finding(setup):
    _i, _ipub, _w, wpub, _path, signer, w = setup
    statement = _sign(signer, _leaves(2))
    cosig = dict(w.cosign(statement))
    cosig["leaves"] = 3
    report = witness.verify([statement], [cosig], [wpub])
    assert report["status"] == witness.INVALID
    assert report["findings"][0]["finding"] == "bad_witness_signature"


def test_a_core_run_root_is_cosigned(tmp_path):
    keys = tmp_path / "keys"
    core_evidence.ensure_keys(keys)
    instance = rs.InstanceKey.load(str(keys / "instance.key"))
    leaves = _leaves(4)
    statement = core_evidence.make_root_statement(instance, rs.merkle_root(leaves), 4, b'{"format":"x"}', time_us=1)
    wkey, wpub = _key(tmp_path, "witness")
    w = witness.Witness(wkey, [(keys / "instance.pub").read_bytes()], str(tmp_path / "state"))
    cosig = w.cosign(statement, time_us=2)
    assert cosig["seq"] is None and cosig["statement_format"] == core_evidence.ROOT_FORMAT
    assert cosig["statement_sha256"] == hashlib.sha256(canon2.dumps(statement)).hexdigest()
    assert witness.verify([statement], [cosig], [wpub])["status"] == witness.WITNESSED
    assert canon.loads_document(canon.canon2_bytes(cosig).decode()) == cosig
