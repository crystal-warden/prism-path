# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Self-heal contract, pinned:
  * a lost block is a detected gap;
  * a forged or corrupted block is REJECTED (fails its Merkle proof), never silently accepted;
  * selective retransmission fills exactly the gaps and reassembles the original stream bit-for-bit
    (verified through the codec round-trip);
  * an unrecoverable block stays a PROVABLE gap  -  assemble() refuses rather than emit a silent hole.
"""
import sys
from pathlib import Path

import pytest

_ADAPTER = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ADAPTER))
sys.path.insert(0, str(_ADAPTER.parent.parent))          # repo root, for prismpath
from prismpath.telemetry import selfheal as sh   # noqa: E402
from prismpath.telemetry import zeckendorf as zeck  # noqa: E402

VALUES = list(range(1, 501))                              # a real Fibonacci stream to protect
STREAM = zeck.encode_stream(VALUES)
BLOCK = 256


def _deliver(sender, receiver, lost):
    """First delivery over a lossy link: every non-lost block arrives (with its proof) and is accepted."""
    for block_index in range(sender.n_blocks()):
        if block_index in lost:
            continue
        block, proof = sender.serve(block_index)
        assert receiver.accept(block_index, block, proof)


def test_commit_and_verify_all_blocks():
    sender = sh.Sender(STREAM, BLOCK)
    assert sender.n_blocks() >= 5
    for block_index in range(sender.n_blocks()):
        block, proof = sender.serve(block_index)
        assert sh.verify_block(block, proof, sender.root)


def test_gap_detection():
    sender = sh.Sender(STREAM, BLOCK)
    receiver = sh.Receiver(sender.root, sender.n_blocks())
    lost = {2, 5, 6, sender.n_blocks() - 1}
    _deliver(sender, receiver, lost)
    assert set(receiver.missing()) == lost
    assert not receiver.complete()


def test_forged_and_corrupted_blocks_are_rejected():
    sender = sh.Sender(STREAM, BLOCK)
    receiver = sh.Receiver(sender.root, sender.n_blocks())
    good_block, good_proof = sender.serve(3)
    # corrupted payload (bit flipped) with the real proof -> rejected
    corrupt = ("0" if good_block[0] == "1" else "1") + good_block[1:]
    assert not receiver.accept(3, corrupt, good_proof)
    # right payload but someone else's proof -> rejected
    _other_block, other_proof = sender.serve(4)
    assert not receiver.accept(3, good_block, other_proof)
    # 3 is still a gap; only a valid (block, proof) fills it
    assert 3 in receiver.missing()
    assert receiver.accept(3, good_block, good_proof)
    assert 3 not in receiver.missing()


def test_selective_repair_restores_the_stream():
    sender = sh.Sender(STREAM, BLOCK)
    receiver = sh.Receiver(sender.root, sender.n_blocks())
    lost = {1, 4, 7, 8}
    _deliver(sender, receiver, lost)
    retransmitted = sh.repair(sender, receiver)
    assert set(retransmitted) == lost            # only the gaps were resent (selective, cf. the benchmark)
    assert receiver.complete()
    assert receiver.assemble() == STREAM                # bit-for-bit
    assert zeck.decode_stream(receiver.assemble()) == VALUES   # and it decodes to the original telemetry


def test_unrecoverable_block_is_a_provable_gap():
    sender = sh.Sender(STREAM, BLOCK)
    receiver = sh.Receiver(sender.root, sender.n_blocks())
    _deliver(sender, receiver, lost={4})                      # block 4 lost and never retransmitted
    with pytest.raises(ValueError) as raised:
        receiver.assemble()
    assert "4" in str(raised.value)                    # the gap is named/provable, not silent
