# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Authenticated ACK contract:
  * a valid, advancing ACK applies drop-on-ACK;
  * a forged, tampered, wrong-secret, or replayed ACK is ignored  -  and CRUCIALLY drops no data
    (the data-loss-by-spoof attack the doc names is prevented).
"""
import sys
from pathlib import Path

_ADAPTER = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ADAPTER))
sys.path.insert(0, str(_ADAPTER.parent.parent))          # repo root, for prismpath (via selfheal)
from prismpath.telemetry import ackchannel as ack  # noqa: E402
from prismpath.telemetry import epochs as E         # noqa: E402
from prismpath.telemetry import zeckendorf as zeck     # noqa: E402

SECRET = b"edge<->ground shared secret"


def _store(epoch_count=3):
    store = E.EpochStore(block_bits=64, max_data_epochs=9)
    for epoch_index in range(epoch_count):
        store.seal(zeck.encode_stream(list(range(1 + epoch_index, 60 + epoch_index))))
    return store


def test_sign_verify_round_trip():
    tag = ack.sign_ack(SECRET, "abc123", 4)
    assert ack.verify_ack(SECRET, "abc123", 4, tag)
    assert not ack.verify_ack(SECRET, "abc123", 5, tag)      # seq bound into the tag
    assert not ack.verify_ack(SECRET, "abcXXX", 4, tag)      # root bound into the tag


def test_valid_ack_applies_drop():
    store = _store(3)
    receiver = ack.AckReceiver(store, SECRET)
    root = store.epochs[1].chained_root
    res = receiver.on_ack(root, 1, ack.sign_ack(SECRET, root, 1))
    assert res["accepted"] and res["dropped"] == 2
    assert store.retransmittable() == [2]


def test_forged_ack_drops_nothing():
    store = _store(3)
    receiver = ack.AckReceiver(store, SECRET)
    root = store.epochs[1].chained_root
    before = store.retransmittable()
    res = receiver.on_ack(root, 1, "deadbeef" * 8)                  # no valid tag
    assert not res["accepted"] and res["reason"] == "bad-tag"
    assert store.retransmittable() == before                      # NOTHING dropped by a spoof
    assert store.gaps() == []


def test_tampered_root_rejected():
    store = _store(3)
    receiver = ack.AckReceiver(store, SECRET)
    real_root = store.epochs[0].chained_root
    tag = ack.sign_ack(SECRET, real_root, 1)                 # tag for epoch 0
    res = receiver.on_ack(store.epochs[2].chained_root, 1, tag)         # ...presented against epoch 2
    assert not res["accepted"]
    assert store.retransmittable() == [0, 1, 2]


def test_wrong_secret_rejected():
    store = _store(2)
    receiver = ack.AckReceiver(store, SECRET)
    root = store.epochs[0].chained_root
    forged = ack.sign_ack(b"attacker-secret", root, 1)
    assert not receiver.on_ack(root, 1, forged)["accepted"]
    assert store.retransmittable() == [0, 1]


def test_replay_is_rejected():
    store = _store(4)
    receiver = ack.AckReceiver(store, SECRET)
    root2 = store.epochs[2].chained_root
    assert receiver.on_ack(root2, 5, ack.sign_ack(SECRET, root2, 5))["accepted"]
    # a later replay at an equal/lower seq is refused, even with a valid tag
    root0 = store.epochs[0].chained_root
    res = receiver.on_ack(root0, 5, ack.sign_ack(SECRET, root0, 5))
    assert not res["accepted"] and res["reason"] == "stale-seq"
