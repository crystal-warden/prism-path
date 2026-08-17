# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Epoch chaining + retention contract:
  * chained roots link each epoch to the last (total ordering + tamper-evidence across time);
  * altering a sealed epoch breaks the chain;
  * drop-on-ACK forgets bytes but keeps roots (chain still verifies);
  * the retention cap drops oldest data, distinguishing a clean acked-drop from a PROVABLE
    pressure-drop (un-acked data forced out is a named gap, never a silent hole).
"""
import sys
from pathlib import Path

_ADAPTER = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ADAPTER))
sys.path.insert(0, str(_ADAPTER.parent.parent))         # repo root, for prismpath (via selfheal)
import epochs as E      # noqa: E402
import zeckendorf as z  # noqa: E402


def _bits(seed):
    return z.encode_stream(list(range(1 + seed, 60 + seed)))


def test_seal_and_chain():
    s = E.EpochStore(block_bits=64, max_data_epochs=5)
    for k in range(3):
        s.seal(_bits(k))
    assert len(s.chain()) == 3
    assert len(set(s.chain())) == 3            # roots distinct
    assert s.verify_chain()
    # each chained root links prev -> this merkle root
    assert s.epochs[1].chained_root == E.chain_root(s.epochs[0].chained_root, s.epochs[1].merkle_root)


def test_tamper_breaks_the_chain():
    s = E.EpochStore(block_bits=64, max_data_epochs=5)
    s.seal(_bits(0)); s.seal(_bits(1))
    assert s.verify_chain()
    s.epochs[0].merkle_root = "deadbeef" * 8   # someone altered a sealed epoch
    assert not s.verify_chain()


def test_drop_on_ack_keeps_roots():
    s = E.EpochStore(block_bits=64, max_data_epochs=5)
    for k in range(3):
        s.seal(_bits(k))
    dropped = s.ack(s.epochs[1].chained_root)
    assert dropped == 2
    assert s.retransmittable() == [2]          # only the un-acked epoch still holds data
    assert s.gaps() == []                       # acked drops are not gaps
    assert s.verify_chain()                      # roots retained -> chain intact
    assert len(s.chain()) == 3


def test_retention_pressure_drop_is_provable():
    s = E.EpochStore(block_bits=64, max_data_epochs=2)
    for k in range(4):
        s.seal(_bits(k))                        # never acked -> cap forces data out
    assert s.retransmittable() == [2, 3]        # only the newest 2 keep data
    assert s.gaps() == [0, 1]                    # the forced-out un-acked epochs are PROVABLE gaps
    assert s.verify_chain()                      # roots kept -> loss is provable, not silent


def test_acked_drop_is_not_counted_as_a_gap():
    s = E.EpochStore(block_bits=64, max_data_epochs=2)
    s.seal(_bits(0))
    s.ack(s.epochs[0].chained_root)             # clean drop
    for k in range(1, 4):
        s.seal(_bits(k))                        # pushes e1 out under pressure
    assert 0 not in s.gaps()                     # acked drop: clean
    assert 1 in s.gaps()                         # un-acked pressure drop: provable gap
