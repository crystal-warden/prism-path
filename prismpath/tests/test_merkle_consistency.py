# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""RFC 6962 consistency proofs (section 2.1.2, verified as RFC 9162 section 2.1.4.2 says): the Python
reference (`root_statement.consistency_proof`, `root_statement.verify_consistency`) against the
definition, the frozen cross-language corpus (portable/conformance/merkle_consistency.json, which the
Rust `merkle::consistency_proof`, `merkle::verify_consistency` and the collector's streaming
`merkle::ProofWindow` replay), and the transparency-dev reference implementation's own consistency probes.

A proof from m to n leaves shows that the tree over n leaves holds the tree over the first m unchanged:
the collector puts one in every seal after the first a client was sent, so a console that missed leaves
still proves the new tree extends the one it checked."""
import hashlib
import importlib.util
import json

import pytest

from prismpath.ledgers import ledger_ots, root_statement as rs
from prismpath.tests._repo import repo_file
from prismpath.tests.test_merkle_rfc6962 import RFC6962_INPUTS

VECTORS = repo_file("prismpath", "portable", "conformance", "merkle_consistency.json")
DOC = json.loads(VECTORS.read_text(encoding="utf-8"))


def _generator():
    spec = importlib.util.spec_from_file_location("gen_merkle_consistency_fixtures",
                                                  VECTORS.parent.parent / "gen_merkle_consistency_fixtures.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _leaves(count):
    return [hashlib.sha256(index.to_bytes(4, "big")).hexdigest() for index in range(count)]


def _mth(leaves):
    """RFC 6962 section 2.1 MTH, from the text."""
    if len(leaves) == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return hashlib.sha256(b"\x01" + _mth(leaves[:k]) + _mth(leaves[k:])).digest()


def _subproof(m, leaves, whole):
    """RFC 6962 section 2.1.2 SUBPROOF, from the text."""
    n = len(leaves)
    if m == n:
        return [] if whole else [_mth(leaves)]
    k = 1
    while k * 2 < n:
        k *= 2
    if m <= k:
        return _subproof(m, leaves[:k], whole) + [_mth(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [_mth(leaves[:k])]


def test_no_silent_drift():
    assert _generator().render() == VECTORS.read_text(encoding="utf-8"), (
        "merkle_consistency.json no longer matches what the live reference produces. If the change is "
        "intended, run `python prismpath/portable/gen_merkle_consistency_fixtures.py` and review the diff.")


@pytest.mark.parametrize("new", [1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 33, 64])
def test_the_proof_is_the_rfc_definition_and_verifies(new):
    leaves = _leaves(new)
    raw = [bytes.fromhex(leaf) for leaf in leaves]
    new_root = rs.merkle_root(leaves)
    for old in range(1, new + 1):
        proof = rs.consistency_proof(leaves, old)
        expected = [] if old == new else [node.hex() for node in _subproof(old, raw, True)]
        assert proof == expected, (old, new)
        old_root = rs.merkle_root(leaves[:old])
        assert rs.verify_consistency(old, new, old_root, new_root, proof), (old, new)
        # the proof is bound to both trees and both sizes
        assert not rs.verify_consistency(old, new, "11" * 32, new_root, proof)
        assert not rs.verify_consistency(old, new, old_root, "11" * 32, proof)
        for index in range(len(proof)):
            flipped = list(proof)
            flipped[index] = ("0" if flipped[index][0] != "0" else "1") + flipped[index][1:]
            assert not rs.verify_consistency(old, new, old_root, new_root, flipped), (old, new, index)
        if 0 < old < new:
            assert not rs.verify_consistency(old, new, old_root, new_root, proof[:-1])
            assert not rs.verify_consistency(old, new, old_root, new_root, proof + [proof[-1]])
            assert not rs.verify_consistency(old, new + 1, old_root, rs.merkle_root(_leaves(new + 1)), proof)


def test_a_tree_that_rewrote_an_old_leaf_has_no_proof():
    leaves = _leaves(20)
    forged = list(leaves)
    forged[3] = "ff" * 32
    for old in range(4, 20):
        proof = rs.consistency_proof(forged, old)
        assert not rs.verify_consistency(old, 20, rs.merkle_root(leaves[:old]), rs.merkle_root(forged), proof)


def test_the_edges_of_the_definition():
    leaves = _leaves(5)
    root = rs.merkle_root(leaves)
    # RFC 9162 defines no proof from the empty tree, which every tree extends: there is nothing to verify
    assert rs.consistency_proof(leaves, 0) == []
    assert not rs.verify_consistency(0, 5, "", root, [])
    assert not rs.verify_consistency(0, 0, "", "", [])
    assert rs.verify_consistency(5, 5, root, root, [])
    assert not rs.verify_consistency(5, 5, root, "11" * 32, [])
    assert not rs.verify_consistency(6, 5, root, root, [])     # the old tree is never the larger
    assert not rs.verify_consistency(2, 5, rs.merkle_root(leaves[:2]), root, [])
    for bad in (None, "ab", ["zz" * 32], [b"\x00" * 32], [1]):
        assert not rs.verify_consistency(2, 5, rs.merkle_root(leaves[:2]), root, bad)
    for bad_size in (-1, True, 1.0, None, 1 << 64):
        assert not rs.verify_consistency(bad_size, 5, "", root, [])
    with pytest.raises(ValueError):
        rs.consistency_proof(leaves, 6)
    with pytest.raises(ValueError):
        rs.consistency_proof(leaves, -1)


def test_a_proof_is_at_most_one_hash_per_level_and_one_more():
    for new in range(1, 130):
        leaves = _leaves(new)
        for old in range(1, new):
            assert len(rs.consistency_proof(leaves, old)) <= (new - 1).bit_length() + 1, (old, new)


def test_the_corpus_is_the_reference():
    assert DOC["scheme"] == ledger_ots.MERKLE_SCHEME
    names = [entry["name"] for entry in DOC["sets"]]
    assert names == ["rfc6962", "hash_leaves", "large"]
    checked = 0
    for entry in DOC["sets"]:
        leaves = entry["leaves"]
        for case in entry["proofs"]:
            old, new = case["old"], case["new"]
            assert case["old_root"] == (rs.merkle_root(leaves[:old]) or None)
            assert case["new_root"] == rs.merkle_root(leaves[:new])
            assert case["proof"] == rs.consistency_proof(leaves[:new], old)
            assert rs.verify_consistency(old, new, case["old_root"] or "", case["new_root"], case["proof"])
            checked += 1
    assert checked == DOC["counts"]["proofs"]


def test_the_transparency_dev_probes():
    """The consistency probes of transparency-dev/merkle (Apache-2.0), the Certificate Transparency
    reference trees over the eight RFC 6962 inputs: every valid one verifies, every tampered one does not,
    and every valid proof between two different sizes is the one this reference generates."""
    probes = DOC["probes"]
    assert len(probes) == DOC["counts"]["probes"] and any(not probe["valid"] for probe in probes)
    generated = 0
    for probe in probes:
        got = rs.verify_consistency(probe["old"], probe["new"], probe["old_root"] or "", probe["new_root"] or "",
                                    probe["proof"])
        assert got is probe["valid"], probe["name"]
        if probe["valid"] and 0 < probe["old"] < probe["new"] <= len(RFC6962_INPUTS) \
                and probe["new_root"] == rs.merkle_root(RFC6962_INPUTS[:probe["new"]]):
            assert rs.consistency_proof(RFC6962_INPUTS[:probe["new"]], probe["old"]) == probe["proof"], probe["name"]
            generated += 1
    assert generated >= 4
