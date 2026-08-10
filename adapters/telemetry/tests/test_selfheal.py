"""Self-heal contract, pinned:
  * a lost block is a detected gap;
  * a forged or corrupted block is REJECTED (fails its Merkle proof), never silently accepted;
  * selective retransmission fills exactly the gaps and reassembles the original stream bit-for-bit
    (verified through the codec round-trip);
  * an unrecoverable block stays a PROVABLE gap — assemble() refuses rather than emit a silent hole.
"""
import sys
from pathlib import Path

import pytest

_ADAPTER = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ADAPTER))
sys.path.insert(0, str(_ADAPTER.parent.parent))          # repo root, for prismpath
import selfheal as sh   # noqa: E402
import zeckendorf as z  # noqa: E402

VALUES = list(range(1, 501))                              # a real Fibonacci stream to protect
STREAM = z.encode_stream(VALUES)
BLOCK = 256


def _deliver(sender, receiver, lost):
    """First delivery over a lossy link: every non-lost block arrives (with its proof) and is accepted."""
    for i in range(sender.n_blocks()):
        if i in lost:
            continue
        block, proof = sender.serve(i)
        assert receiver.accept(i, block, proof)


def test_commit_and_verify_all_blocks():
    s = sh.Sender(STREAM, BLOCK)
    assert s.n_blocks() >= 5
    for i in range(s.n_blocks()):
        block, proof = s.serve(i)
        assert sh.verify_block(block, proof, s.root)


def test_gap_detection():
    s = sh.Sender(STREAM, BLOCK)
    r = sh.Receiver(s.root, s.n_blocks())
    lost = {2, 5, 6, s.n_blocks() - 1}
    _deliver(s, r, lost)
    assert set(r.missing()) == lost
    assert not r.complete()


def test_forged_and_corrupted_blocks_are_rejected():
    s = sh.Sender(STREAM, BLOCK)
    r = sh.Receiver(s.root, s.n_blocks())
    good_block, good_proof = s.serve(3)
    # corrupted payload (bit flipped) with the real proof -> rejected
    corrupt = ("0" if good_block[0] == "1" else "1") + good_block[1:]
    assert not r.accept(3, corrupt, good_proof)
    # right payload but someone else's proof -> rejected
    _other_block, other_proof = s.serve(4)
    assert not r.accept(3, good_block, other_proof)
    # 3 is still a gap; only a valid (block, proof) fills it
    assert 3 in r.missing()
    assert r.accept(3, good_block, good_proof)
    assert 3 not in r.missing()


def test_selective_repair_restores_the_stream():
    s = sh.Sender(STREAM, BLOCK)
    r = sh.Receiver(s.root, s.n_blocks())
    lost = {1, 4, 7, 8}
    _deliver(s, r, lost)
    retransmitted = sh.repair(s, r)
    assert set(retransmitted) == lost            # only the gaps were resent (selective, cf. the benchmark)
    assert r.complete()
    assert r.assemble() == STREAM                # bit-for-bit
    assert z.decode_stream(r.assemble()) == VALUES   # and it decodes to the original telemetry


def test_unrecoverable_block_is_a_provable_gap():
    s = sh.Sender(STREAM, BLOCK)
    r = sh.Receiver(s.root, s.n_blocks())
    _deliver(s, r, lost={4})                      # block 4 lost and never retransmitted
    with pytest.raises(ValueError) as e:
        r.assemble()
    assert "4" in str(e.value)                    # the gap is named/provable, not silent
