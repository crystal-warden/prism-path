# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Self-healing transport — Merkle-committed blocks + selective retransmission, reusing the repo's real
Merkle primitive (`prismpath.ledger_ots`, which is also OTS/Bitcoin-anchorable). NOT a new subsystem.

(The doc named `audit_log`'s MMR, but that is a stub in the open release — no roots/proofs. `ledger_ots`
is the genuine one. A batch Merkle tree recomputed per window/epoch fits the daily-chained-epoch design;
an append-only MMR with O(log n) peaks is a later streaming optimization.)

The self-framing Fibonacci stream is chunked into fixed-size blocks (the retransmit + Merkle-leaf unit).
The root commits to every block; a lost block is a known gap the receiver requests by index; a
retransmitted (or first-delivery) block is accepted ONLY if its inclusion proof verifies against the
trusted (anchored) root — so a forged or corrupted block is detected, never silently accepted. A block
that is never recoverable stays a *provable* gap: "detect + selectively repair + prove", not magic.
"""
from __future__ import annotations

import hashlib
from typing import Dict, List, Optional, Tuple

from prismpath import ledger_ots as _mk


def chunk(bits: str, block_bits: int) -> List[str]:
    """Split a bitstream into fixed-size blocks (the retransmit unit). Always >= 1 block."""
    if block_bits <= 0:
        raise ValueError("block_bits must be positive")
    return [bits[i:i + block_bits] for i in range(0, len(bits), block_bits)] or [""]


def _leaf(block: str) -> str:
    return hashlib.sha256(block.encode("ascii")).hexdigest()


def commit(blocks: List[str]) -> Tuple[str, List[list]]:
    """(root_hex, per-block inclusion proof) over the block hashes — reuses ledger_ots's Merkle."""
    return _mk.merkle_root_and_paths([_leaf(b) for b in blocks])


def verify_block(block: str, proof: list, root: str) -> bool:
    return _mk.verify_leaf(_leaf(block), proof, root)


class Sender:
    """Holds the committed blocks; serves any block + its proof on a retransmit request."""

    def __init__(self, bits: str, block_bits: int):
        self.blocks = chunk(bits, block_bits)
        self.block_bits = block_bits
        self.root, self.proofs = commit(self.blocks)

    def n_blocks(self) -> int:
        return len(self.blocks)

    def serve(self, idx: int) -> Tuple[str, list]:
        return self.blocks[idx], self.proofs[idx]


class Receiver:
    """Holds only the trusted root (e.g. OTS-anchored) + accepted blocks. Every block — first delivery or
    retransmit — must verify against the root before it is accepted."""

    def __init__(self, root: str, n_blocks: int):
        self.root = root
        self.n = n_blocks
        self._blocks: Dict[int, str] = {}

    def accept(self, idx: int, block: str, proof: list) -> bool:
        """Verify the block's proof against the root; accept iff valid. Returns acceptance."""
        if not (0 <= idx < self.n):
            return False
        if not verify_block(block, proof, self.root):
            return False                       # forged / corrupted -> reject, stays a gap
        self._blocks[idx] = block
        return True

    def missing(self) -> List[int]:
        return [i for i in range(self.n) if i not in self._blocks]

    def complete(self) -> bool:
        return len(self._blocks) == self.n

    def assemble(self) -> str:
        """The recovered bitstream. Raises if any block is still missing — a gap is provable, never a
        silent hole."""
        if not self.complete():
            raise ValueError(f"cannot assemble: blocks still missing (provable gap): {self.missing()}")
        return "".join(self._blocks[i] for i in range(self.n))


def repair(sender: Sender, receiver: Receiver) -> List[int]:
    """Selective retransmission: fetch + verify only the blocks the receiver is missing. Returns the list
    of block indices retransmitted (the selective-repair cost — cf. the Phase A benchmark)."""
    retransmitted = []
    for idx in receiver.missing():
        block, proof = sender.serve(idx)
        if receiver.accept(idx, block, proof):
            retransmitted.append(idx)
    return retransmitted
