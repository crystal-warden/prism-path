# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Authenticated ACK / retransmission-control channel.

Drop-on-ACK is a data-loss weapon if the control channel is unauthenticated: a forged "verified up to
root R" makes the edge discard data the ground never actually confirmed. So every ACK is HMAC-signed with
a secret shared out-of-band between edge and ground (the same HMAC-SHA256 pattern `guard_ledger` uses),
and the edge applies a drop ONLY for an ACK whose tag verifies AND whose sequence advances (replay-safe).
A forged, tampered, wrong-secret, or stale ACK is ignored — no drop happens.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Dict


def _canon(root: str, seq: int) -> bytes:
    return json.dumps({"root": root, "seq": seq}, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_ack(secret: bytes, root: str, seq: int) -> str:
    """Ground side: HMAC-SHA256 tag over (high-water chained root, monotonic seq)."""
    return hmac.new(secret, _canon(root, seq), hashlib.sha256).hexdigest()


def verify_ack(secret: bytes, root: str, seq: int, tag: str) -> bool:
    """Constant-time verification of an ACK's tag."""
    return hmac.compare_digest(sign_ack(secret, root, seq), tag)


class AckReceiver:
    """Edge side: applies `store.ack(root)` (drop-on-ACK) only for authentic, non-stale ACKs.

    `store` is anything with `ack(chained_root) -> int` (e.g. epochs.EpochStore). Holds the shared secret
    and the last accepted sequence number.
    """

    def __init__(self, store, secret: bytes):
        self.store = store
        self.secret = secret
        self.last_seq = -1

    def on_ack(self, root: str, seq: int, tag: str) -> Dict:
        if not verify_ack(self.secret, root, seq, tag):
            return {"accepted": False, "reason": "bad-tag", "dropped": 0}     # forged/tampered -> no drop
        if seq <= self.last_seq:
            return {"accepted": False, "reason": "stale-seq", "dropped": 0}   # replay -> no drop
        self.last_seq = seq
        dropped = self.store.ack(root)
        return {"accepted": True, "reason": "ok", "dropped": dropped}
