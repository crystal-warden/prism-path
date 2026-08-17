# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Daily-chained epochs + retention — bound what the edge stores without losing provability.

Each epoch is a sealed window: its blocks get a Merkle root (via `selfheal`/`ledger_ots`), and its
*chained* root commits to the previous epoch's chained root — so the tiny chain of roots gives total
ordering + tamper-evidence across all time, while only recent epochs keep their raw data (for
retransmission). Retention:
  * **drop-on-ACK** — once the ground verifies up to a chained root, the edge forgets those epochs' bytes
    but keeps their root ("verified up to R; here's exactly what's committed").
  * **retention cap** — at most `max_data_epochs` keep raw data; the oldest is dropped when over the cap.
  * **provable pressure-drop** — if the cap forces dropping an *un-acked* epoch, it's marked a gap
    (root kept), never a silent hole. "detect + prove", per the doc.
Anchor a sealed root with `ledger_ots` (OTS/Bitcoin) to make the chain externally tamper-evident.
"""
from __future__ import annotations

import hashlib
from typing import List, Optional

import selfheal as sh


def chain_root(prev_chained: str, merkle_root: str) -> str:
    """Link an epoch into the chain: H(prev_chained_root || this_merkle_root)."""
    return hashlib.sha256(((prev_chained or "") + merkle_root).encode("ascii")).hexdigest()


class Epoch:
    def __init__(self, epoch_id: int, blocks: Optional[List[str]], merkle_root: str, chained: str):
        self.id = epoch_id
        self.blocks = blocks                 # None once the raw data is dropped
        self.merkle_root = merkle_root
        self.chained_root = chained
        self.acked = False
        self.dropped_under_pressure = False   # a provable gap (un-acked data forced out by the cap)

    def has_data(self) -> bool:
        return self.blocks is not None


class EpochStore:
    def __init__(self, block_bits: int, max_data_epochs: int = 3):
        self.block_bits = block_bits
        self.max_data_epochs = max_data_epochs
        self.epochs: List[Epoch] = []

    def seal(self, bits: str) -> Epoch:
        """Seal a window of stream bits into a new chained epoch, then enforce the retention cap."""
        blocks = sh.chunk(bits, self.block_bits)
        merkle_root, _proofs = sh.commit(blocks)
        prev = self.epochs[-1].chained_root if self.epochs else ""
        ep = Epoch(len(self.epochs), blocks, merkle_root, chain_root(prev, merkle_root))
        self.epochs.append(ep)
        self._enforce_cap()
        return ep

    def ack(self, chained_root: str) -> int:
        """Ground verified up to `chained_root`: drop those epochs' bytes (keep roots). Returns #dropped."""
        idx = next((i for i, ep in enumerate(self.epochs) if ep.chained_root == chained_root), None)
        if idx is None:
            return 0
        dropped = 0
        for ep in self.epochs[:idx + 1]:
            ep.acked = True
            if ep.has_data():
                ep.blocks = None
                dropped += 1
        return dropped

    def _enforce_cap(self) -> None:
        with_data = [ep for ep in self.epochs if ep.has_data()]
        while len(with_data) > self.max_data_epochs:
            victim = with_data.pop(0)         # oldest epoch still holding data
            if not victim.acked:
                victim.dropped_under_pressure = True   # forced out un-acked -> provable gap
            victim.blocks = None

    # ------------------------------------------------ provenance / queries
    def chain(self) -> List[str]:
        """The permanent, tiny chain of chained roots — total ordering + tamper-evidence, kept forever."""
        return [ep.chained_root for ep in self.epochs]

    def verify_chain(self) -> bool:
        """Each epoch's chained root correctly links its Merkle root to the previous — tamper-evident."""
        prev = ""
        for ep in self.epochs:
            if ep.chained_root != chain_root(prev, ep.merkle_root):
                return False
            prev = ep.chained_root
        return True

    def retransmittable(self) -> List[int]:
        return [ep.id for ep in self.epochs if ep.has_data()]

    def gaps(self) -> List[int]:
        """Epochs whose un-acked data was forced out under storage pressure — provable losses, not holes."""
        return [ep.id for ep in self.epochs if ep.dropped_under_pressure]

    def anchor(self, epoch: Epoch, out_dir: str, label: str):
        """OTS/Bitcoin-anchor a sealed epoch's chained root (reuses ledger_ots). Network side effect — not
        exercised in unit tests; this is the seam that makes the chain externally tamper-evident."""
        from prismpath import ledger_ots
        return ledger_ots.anchor([epoch.chained_root], out_dir, label)
