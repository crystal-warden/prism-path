"""Authenticated ACK contract:
  * a valid, advancing ACK applies drop-on-ACK;
  * a forged, tampered, wrong-secret, or replayed ACK is ignored — and CRUCIALLY drops no data
    (the data-loss-by-spoof attack the doc names is prevented).
"""
import sys
from pathlib import Path

_ADAPTER = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ADAPTER))
sys.path.insert(0, str(_ADAPTER.parent.parent))          # repo root, for prismpath (via selfheal)
import ackchannel as ack  # noqa: E402
import epochs as E         # noqa: E402
import zeckendorf as z     # noqa: E402

SECRET = b"edge<->ground shared secret"


def _store(n=3):
    s = E.EpochStore(block_bits=64, max_data_epochs=9)
    for k in range(n):
        s.seal(z.encode_stream(list(range(1 + k, 60 + k))))
    return s


def test_sign_verify_round_trip():
    tag = ack.sign_ack(SECRET, "abc123", 4)
    assert ack.verify_ack(SECRET, "abc123", 4, tag)
    assert not ack.verify_ack(SECRET, "abc123", 5, tag)      # seq bound into the tag
    assert not ack.verify_ack(SECRET, "abcXXX", 4, tag)      # root bound into the tag


def test_valid_ack_applies_drop():
    s = _store(3)
    r = ack.AckReceiver(s, SECRET)
    root = s.epochs[1].chained_root
    res = r.on_ack(root, 1, ack.sign_ack(SECRET, root, 1))
    assert res["accepted"] and res["dropped"] == 2
    assert s.retransmittable() == [2]


def test_forged_ack_drops_nothing():
    s = _store(3)
    r = ack.AckReceiver(s, SECRET)
    root = s.epochs[1].chained_root
    before = s.retransmittable()
    res = r.on_ack(root, 1, "deadbeef" * 8)                  # no valid tag
    assert not res["accepted"] and res["reason"] == "bad-tag"
    assert s.retransmittable() == before                      # NOTHING dropped by a spoof
    assert s.gaps() == []


def test_tampered_root_rejected():
    s = _store(3)
    r = ack.AckReceiver(s, SECRET)
    real_root = s.epochs[0].chained_root
    tag = ack.sign_ack(SECRET, real_root, 1)                 # tag for epoch 0
    res = r.on_ack(s.epochs[2].chained_root, 1, tag)         # ...presented against epoch 2
    assert not res["accepted"]
    assert s.retransmittable() == [0, 1, 2]


def test_wrong_secret_rejected():
    s = _store(2)
    r = ack.AckReceiver(s, SECRET)
    root = s.epochs[0].chained_root
    forged = ack.sign_ack(b"attacker-secret", root, 1)
    assert not r.on_ack(root, 1, forged)["accepted"]
    assert s.retransmittable() == [0, 1]


def test_replay_is_rejected():
    s = _store(4)
    r = ack.AckReceiver(s, SECRET)
    root2 = s.epochs[2].chained_root
    assert r.on_ack(root2, 5, ack.sign_ack(SECRET, root2, 5))["accepted"]
    # a later replay at an equal/lower seq is refused, even with a valid tag
    root0 = s.epochs[0].chained_root
    res = r.on_ack(root0, 5, ack.sign_ack(SECRET, root0, 5))
    assert not res["accepted"] and res["reason"] == "stale-seq"
