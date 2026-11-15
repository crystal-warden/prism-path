# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The Merkle tree every ledger shares (`prismpath.ledgers.ledger_ots`) is RFC 6962's: a leaf hashes as
SHA-256(0x00 || leaf), a node as SHA-256(0x01 || left || right), split at the largest power of two below the
count, nothing duplicated. The retired tree (no prefixes, the last node of an odd layer repeated) gave
[a, b, c] and [a, b, c, c] one root; these tests hold the new one to the RFC's own construction and its
published vectors, and the formats that carry its roots to refusing the old ones."""
import hashlib
import json

import pytest

from prismpath.ledgers import ledger_ots, root_statement as rs

# The eight inputs of the Certificate Transparency reference implementations' Merkle tree tests, and the
# RFC 6962 root of the first n of them for n = 1..8.
RFC6962_INPUTS = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657",
                  "606162636465666768696a6b6c6d6e6f"]
RFC6962_ROOTS = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]


def _mth(leaves):
    """RFC 6962 section 2.1, MTH, written from the text and nothing else."""
    if len(leaves) == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return hashlib.sha256(b"\x01" + _mth(leaves[:k]) + _mth(leaves[k:])).digest()


def _leaves(count):
    return [hashlib.sha256(bytes([index % 256, index // 256])).hexdigest() for index in range(count)]


@pytest.mark.parametrize("count", range(1, 9))
def test_the_rfc6962_known_answer_vectors(count):
    leaves = RFC6962_INPUTS[:count]
    assert ledger_ots.merkle_root(leaves) == RFC6962_ROOTS[count - 1]
    assert ledger_ots.merkle_root_and_paths(leaves)[0] == RFC6962_ROOTS[count - 1]
    assert rs.merkle_root(leaves) == rs.MerkleAccumulator(leaves).root() == RFC6962_ROOTS[count - 1]


def test_a_repeated_last_leaf_is_another_root():
    a, b, c = (hashlib.sha256(name).hexdigest() for name in (b"a", b"b", b"c"))
    assert rs.merkle_root([a, b, c]) != rs.merkle_root([a, b, c, c])
    assert ledger_ots.merkle_root_and_paths([a, b, c])[0] != ledger_ots.merkle_root_and_paths([a, b, c, c])[0]
    # and for every odd count, which is where the retired tree duplicated
    for count in range(1, 40, 2):
        leaves = _leaves(count)
        assert rs.merkle_root(leaves) != rs.merkle_root(leaves + leaves[-1:]), count


def test_a_leaf_is_never_a_node():
    """With the prefixes, a node's two children concatenated, given as one leaf, is another root."""
    left, right = _leaves(2)
    node = ledger_ots.node_hash(ledger_ots.leaf_hash(bytes.fromhex(left)), ledger_ots.leaf_hash(bytes.fromhex(right)))
    as_leaf = (ledger_ots.leaf_hash(bytes.fromhex(left)) + ledger_ots.leaf_hash(bytes.fromhex(right))).hex()
    assert rs.merkle_root([left, right]) == node.hex() != rs.merkle_root([as_leaf])


@pytest.mark.parametrize("count", [1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 31, 32, 33, 100, 257])
def test_odd_and_even_sizes_match_the_definition_and_every_path_folds(count):
    leaves = _leaves(count)
    root, paths = ledger_ots.merkle_root_and_paths(leaves)
    assert root == _mth([bytes.fromhex(leaf) for leaf in leaves]).hex()
    assert root == rs.merkle_root(leaves) == rs.MerkleAccumulator(leaves).root()
    for index, leaf in enumerate(leaves):
        assert ledger_ots.verify_leaf(leaf, paths[index], root)
        assert not ledger_ots.verify_leaf(_leaves(count + 1)[-1], paths[index], root)
    # a path is at most ceil(log2 n) steps, and no step repeats the node it is paired with
    assert max(len(path) for path in paths) == (count - 1).bit_length()


def test_the_scheme_is_named():
    assert ledger_ots.MERKLE_SCHEME == "rfc6962-sha256"
    assert rs.STATEMENT_FORMAT == "prismpath-root-statement/3"
    assert "prismpath-root-statement/2" in rs.OLD_SCHEME_FORMATS


# ----------------------------------------------------------------- old-scheme evidence is refused by name
def _old_statement(key, leaves):
    retired = [bytes.fromhex(leaf) for leaf in leaves]
    while len(retired) > 1:
        retired = retired + retired[-1:] if len(retired) % 2 else retired
        retired = [hashlib.sha256(retired[i] + retired[i + 1]).digest() for i in range(0, len(retired), 2)]
    body = {"format": "prismpath-root-statement/2", "encoding": "canon/2", "log": rs.LOG_AUDIT, "seq": 0,
            "root": retired[0].hex(), "leaves": len(leaves), "prev": "", "time_us": 1762257600123000,
            "trigger": "run-end", "key_id": key.key_id, "public_key": key.public_raw.hex(), "policy": None}
    body["sig"] = key.sign(b"prismpath-root-statement/2\x00" + rs.canon.canon2_bytes(body)).hex()
    return body


def test_an_old_scheme_root_statement_is_refused_as_such(tmp_path):
    pytest.importorskip("cryptography")
    key = rs.InstanceKey.load(rs.keygen(str(tmp_path), "instance")["private"])
    leaves = _leaves(3)
    statement = _old_statement(key, leaves)
    report = rs.verify_chain([statement], [], lambda count: rs.merkle_root(leaves[:count]), len(leaves),
                             pinned=[key.public_raw])
    assert report["status"] == rs.INVALID
    assert [finding["finding"] for finding in report["findings"]] == ["old_merkle_scheme"]
    assert report["findings"][0]["format"] == "prismpath-root-statement/2"
    from prismpath import trail
    assert "retired Merkle tree" in trail._finding_text(report["findings"][0])
    # and one receipt in a bundle under it
    event = {"idx": 0, "encoding": "canon/2"}
    bundle = {"receipt": event, "index": 0, "leaf": leaves[0], "path": [], "statement": statement}
    verdict = rs.verify_receipt_bundle(bundle, [key.public_raw])
    assert verdict["status"] == rs.INVALID and "retired Merkle tree" in verdict["problem"]


def test_an_old_scheme_anchor_batch_is_refused_as_such(tmp_path):
    leaves = _leaves(3)
    root, paths = ledger_ots.merkle_root_and_paths(leaves)
    manifest = {"label": "old", "root": root, "leaf_count": 3, "leaves": dict(zip(leaves, paths)),
                "encoding": "canon/2"}
    (tmp_path / "manifest_old.json").write_bytes(rs.canon.canon2_bytes(json.loads(json.dumps(manifest))) + b"\n")
    result = ledger_ots.verify_unit(leaves[0], str(tmp_path), "old")
    assert result["merkle_ok"] is False and "retired Merkle tree" in result["reason"]
