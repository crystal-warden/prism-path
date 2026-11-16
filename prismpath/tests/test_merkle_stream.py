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


# ----------------------------------------------------------------- resuming from peaks
# A reader handed a count and its peaks partway through a stream (the collector's `seal` records, tallest
# peak first) carries the same tree on from leaf `count` without the leaves before it, as Rust's
# `Accumulator::from_peaks` does.
def _cut(leaves, cut):
    head = rs.MerkleAccumulator(leaves[:cut])
    return head, head.peaks()


def test_the_peaks_are_one_hash_per_set_bit_tallest_first():
    leaves = [hashlib.sha256(index.to_bytes(4, "big")).hexdigest() for index in range(13)]
    head, peaks = _cut(leaves, 13)                     # 13 = 8 + 4 + 1
    assert len(peaks) == 3
    assert peaks[0] == ledger_ots.merkle_root(leaves[:8])
    assert peaks[1] == ledger_ots.merkle_root(leaves[8:12])
    assert peaks[2] == ledger_ots.merkle_root(leaves[12:13])
    assert rs.MerkleAccumulator().peaks() == []


def test_resuming_from_peaks_is_the_batch_tree_for_every_prefix_after_every_cut():
    leaves = [hashlib.sha256(index.to_bytes(4, "big")).hexdigest() for index in range(160)]
    batch = {count: ledger_ots.merkle_root(leaves[:count]) for count in range(1, len(leaves) + 1)}
    for cut in range(len(leaves) + 1):
        head, peaks = _cut(leaves, cut)
        resumed = rs.MerkleAccumulator.from_peaks(cut, peaks)
        assert resumed.count == cut and resumed.peaks() == peaks
        assert resumed.root() == head.root() == (batch[cut] if cut else "")
        for count in range(cut + 1, len(leaves) + 1):
            resumed.add(leaves[count - 1])
            assert resumed.root() == batch[count], (cut, count)


@pytest.mark.parametrize("name", [entry["name"] for entry in DOC["sets"]])
def test_resuming_from_peaks_replays_the_frozen_vectors(name):
    entry = next(entry for entry in DOC["sets"] if entry["name"] == name)
    leaves, roots = entry["leaves"], entry["roots"]
    for cut in range(len(leaves) + 1):
        resumed = rs.MerkleAccumulator.from_peaks(cut, _cut(leaves, cut)[1])
        assert resumed.root() == (roots[cut] or ""), (name, cut)
        for count in range(cut + 1, len(leaves) + 1):
            resumed.add(leaves[count - 1])
        assert resumed.root() == (roots[-1] or ""), (name, cut)


@pytest.mark.parametrize("count, peaks", [
    (3, ["00" * 32]),                    # 3 has two set bits
    (0, ["00" * 32]),                    # no leaves, no peaks
    (1, []),
    (-1, []),
    (True, ["00" * 32]),
    (1.0, ["00" * 32]),
    (2 ** 64, ["00" * 32]),
    (1, ["00" * 31]),                    # not a 32 byte hash
    (1, ["AA" * 32]),                    # not lowercase hex, as every hash in a canon/2 record is
    (1, ["zz" * 32]),
    (1, [b"\x00" * 32]),
    (1, "00" * 32),                      # a string is not a list of peaks
])
def test_from_peaks_refuses_a_state_that_is_not_one_peak_per_set_bit(count, peaks):
    with pytest.raises(ValueError):
        rs.MerkleAccumulator.from_peaks(count, peaks)
