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
from prismpath.telemetry import epochs as E      # noqa: E402
from prismpath.telemetry import zeckendorf as zeck  # noqa: E402


def _bits(seed):
    return zeck.encode_stream(list(range(1 + seed, 60 + seed)))


def test_seal_and_chain():
    store = E.EpochStore(block_bits=64, max_data_epochs=5)
    for epoch_index in range(3):
        store.seal(_bits(epoch_index))
    assert len(store.chain()) == 3
    assert len(set(store.chain())) == 3            # roots distinct
    assert store.verify_chain()
    # each chained root links prev -> this merkle root
    assert store.epochs[1].chained_root == E.chain_root(store.epochs[0].chained_root,
                                                        store.epochs[1].merkle_root)


def test_tamper_breaks_the_chain():
    store = E.EpochStore(block_bits=64, max_data_epochs=5)
    store.seal(_bits(0)); store.seal(_bits(1))
    assert store.verify_chain()
    store.epochs[0].merkle_root = "deadbeef" * 8   # someone altered a sealed epoch
    assert not store.verify_chain()


def test_drop_on_ack_keeps_roots():
    store = E.EpochStore(block_bits=64, max_data_epochs=5)
    for epoch_index in range(3):
        store.seal(_bits(epoch_index))
    dropped = store.ack(store.epochs[1].chained_root)
    assert dropped == 2
    assert store.retransmittable() == [2]          # only the un-acked epoch still holds data
    assert store.gaps() == []                       # acked drops are not gaps
    assert store.verify_chain()                      # roots retained -> chain intact
    assert len(store.chain()) == 3


def test_retention_pressure_drop_is_provable():
    store = E.EpochStore(block_bits=64, max_data_epochs=2)
    for epoch_index in range(4):
        store.seal(_bits(epoch_index))                        # never acked -> cap forces data out
    assert store.retransmittable() == [2, 3]        # only the newest 2 keep data
    assert store.gaps() == [0, 1]                    # the forced-out un-acked epochs are PROVABLE gaps
    assert store.verify_chain()                      # roots kept -> loss is provable, not silent


def test_acked_drop_is_not_counted_as_a_gap():
    store = E.EpochStore(block_bits=64, max_data_epochs=2)
    store.seal(_bits(0))
    store.ack(store.epochs[0].chained_root)             # clean drop
    for epoch_index in range(1, 4):
        store.seal(_bits(epoch_index))                        # pushes e1 out under pressure
    assert 0 not in store.gaps()                     # acked drop: clean
    assert 1 in store.gaps()                         # un-acked pressure drop: provable gap
