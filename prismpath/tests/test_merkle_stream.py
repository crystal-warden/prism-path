# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The streaming form of the RFC 6962 root (`root_statement.MerkleAccumulator`) is the batch tree
(`ledger_ots.merkle_root`) for every count, and the frozen cross-language vectors
(portable/conformance/merkle_stream.json) are what the live reference produces.

`formal/Core/Merkle.lean` proves the two forms equal for every list (`acc_root_eq_mth`); this holds the
Python code to it for every count from 0 to 1000 over fixed leaves, the RFC 6962 known-answer vectors and
the Merkle cases of the receipts corpus. The Rust and C accumulators replay the same frozen vectors
(`prismpath-rs/tests/test_merkle_stream.rs`, `prismpath-ebpf/test_merkle.c`)."""
import hashlib
import importlib.util
import json

import pytest

from prismpath.ledgers import ledger_ots, root_statement as rs
from prismpath.tests._repo import repo_file

VECTORS = repo_file("prismpath", "portable", "conformance", "merkle_stream.json")
DOC = json.loads(VECTORS.read_text(encoding="utf-8"))


def _generator():
    spec = importlib.util.spec_from_file_location("gen_merkle_stream_fixtures",
                                                  VECTORS.parent.parent / "gen_merkle_stream_fixtures.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_no_silent_drift():
    assert _generator().render() == VECTORS.read_text(encoding="utf-8"), (
        "merkle_stream.json no longer matches what the live reference produces. If the change is intended, "
        "run `python prismpath/portable/gen_merkle_stream_fixtures.py` and review the diff.")


def test_the_accumulator_is_the_tree_for_every_count_to_a_thousand():
    leaves = [hashlib.sha256(index.to_bytes(4, "big")).hexdigest() for index in range(1000)]
    accumulator = rs.MerkleAccumulator()
    assert accumulator.root() == rs.merkle_root([]) == ""
    assert ledger_ots.merkle_root([]) is None
    for count in range(1, len(leaves) + 1):
        accumulator.add(leaves[count - 1])
        assert accumulator.count == count
        assert accumulator.root() == ledger_ots.merkle_root(leaves[:count]), count
    # and prefix_roots, which serves every count from one accumulator, agrees at every one of them
    every = rs.prefix_roots(leaves, range(len(leaves) + 1))
    assert every[0] == "" and all(every[count] == ledger_ots.merkle_root(leaves[:count]) for count in range(1, 1001))


def test_the_rfc6962_vectors_pass_through_the_accumulator():
    rfc = next(entry for entry in DOC["sets"] if entry["name"] == "rfc6962")
    from prismpath.tests.test_merkle_rfc6962 import RFC6962_INPUTS, RFC6962_ROOTS
    assert rfc["leaves"] == RFC6962_INPUTS and rfc["roots"] == [None] + RFC6962_ROOTS
    accumulator = rs.MerkleAccumulator()
    for leaf, root in zip(RFC6962_INPUTS, RFC6962_ROOTS, strict=True):
        accumulator.add(leaf)
        assert accumulator.root() == root


@pytest.mark.parametrize("name", [entry["name"] for entry in DOC["sets"]])
def test_the_frozen_vectors_replay_through_both_forms(name):
    entry = next(entry for entry in DOC["sets"] if entry["name"] == name)
    assert DOC["scheme"] == ledger_ots.MERKLE_SCHEME
    assert len(entry["roots"]) == len(entry["leaves"]) + 1 and entry["roots"][0] is None
    accumulator = rs.MerkleAccumulator()
    for count, leaf in enumerate(entry["leaves"], start=1):
        accumulator.add(leaf)
        assert accumulator.root() == ledger_ots.merkle_root(entry["leaves"][:count]) == entry["roots"][count], count


def test_the_receipts_corpus_merkle_cases_pass_through_the_accumulator():
    receipts = json.loads(repo_file("prismpath", "portable", "conformance", "receipts.json").read_text(encoding="utf-8"))
    cases = [case for case in receipts["cases"] if case["kind"] == "merkle"]
    assert cases
    for case in cases:
        assert rs.MerkleAccumulator(case["leaves"]).root() == case["root"] == rs.merkle_root(case["leaves"]), case["name"]
