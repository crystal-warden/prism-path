"""context_ledger.py — attest WHAT a frozen model was conditioned on.

For a hardwired / frozen-weights model, the weights are fixed silicon: the CONTEXT (system prompt,
retrieved documents, conversation turns — the material that becomes the KV cache) is the only
mutable state left, and therefore the governance surface. This module makes that surface
attestable: an append-only ledger of context segments, each committed by content hash and chained,
rolled into a Merkle root, and bound into the SAME provenance manifest the rest of the attestation
stack uses (`ledger_airgap.provenance_manifest` — zero new manifest machinery).

Privacy is structural: the ledger stores HASHES, never content. A low-entropy segment (a short
command, a yes/no) can be committed salted (`ledger_airgap.salt_leaf`, C4) so a leaked artifact
cannot be confirmed by guessing the text.

The claim this earns: "this answer was produced by policy P over EXACTLY this context" — the
manifest binds the context root (what was in the window), the segment hashes (order and identity),
the policy hash (which flow governed), the gate id, and the model identity, all content-addressed
and tamper-evident (`verify_manifest`).

Mirrored bit-for-bit in the Rust kernel (`prismpath-rs::durable::ContextLedger`), gated by the
frozen cross-language fixtures in `portable/conformance/context.json`.
"""
from __future__ import annotations

import hashlib
from typing import Dict, List, Optional

from prismpath import ledger_airgap
from prismpath import ledger_ots

GENESIS = "0" * 64


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ContextLedger:
    """Append-only, hash-chained commitments to context segments.

    Each segment records `{idx, role, leaf, salted, chain}` where `leaf` is sha256(content) —
    or HMAC(secret, sha256(content)) when salted — and `chain` binds order:
    chain_i = sha256(chain_{i-1} || leaf_i) over raw bytes, chain_{-1} = 64 zero hex chars.
    """

    def __init__(self) -> None:
        self.segments: List[Dict] = []

    def commit(self, role: str, content: str, salt_secret: Optional[str] = None) -> Dict:
        """Commit one context segment by hash; content is NEVER stored."""
        leaf = _sha256_hex(content.encode("utf-8"))
        salted = salt_secret is not None
        if salted:
            leaf = ledger_airgap.salt_leaf(leaf, salt_secret)
        prev = self.segments[-1]["chain"] if self.segments else GENESIS
        chain = _sha256_hex(bytes.fromhex(prev) + bytes.fromhex(leaf))
        seg = {"idx": len(self.segments), "role": role, "leaf": leaf,
               "salted": salted, "chain": chain}
        self.segments.append(seg)
        return seg

    @property
    def leaves(self) -> List[str]:
        return [s["leaf"] for s in self.segments]

    def head(self) -> str:
        """The chain head — commits to every leaf AND their order."""
        return self.segments[-1]["chain"] if self.segments else GENESIS

    def root(self) -> str:
        """Merkle root over the segment leaves (inclusion-provable per segment); "" when empty."""
        root, _paths = ledger_ots.merkle_root_and_paths(self.leaves)
        return root or ""

    def prove(self, i: int) -> dict:
        """Inclusion proof for segment `i` against `root()`."""
        root, paths = ledger_ots.merkle_root_and_paths(self.leaves)
        if not (0 <= i < len(paths)):
            raise IndexError(f"segment index out of range: {i}")
        return {"leaf": self.leaves[i], "path": paths[i], "root": root}

    def attest(self, policy_hash: Optional[str], gate_id: Optional[str],
               model_id: str, label: str = "context") -> dict:
        """Bind the context to the run: a standard provenance manifest whose root is the context
        Merkle root, whose ingestion hashes are the segment leaves (order per the chain head,
        carried in the label), and whose knowledge hash is the MODEL identity — for a frozen
        model, the model IS the knowledge snapshot."""
        model_hash = "sha256:" + _sha256_hex(model_id.encode("utf-8"))
        return ledger_airgap.provenance_manifest(
            root_hex=self.root(),
            label=f"{label}:chain:{self.head()}",
            policy_hash=policy_hash,
            gate_id=gate_id,
            ingestion_hashes=self.leaves,
            knowledge_base_hash=model_hash,
        )


def verify_chain(segments: List[Dict]) -> bool:
    """Recompute the chain over a ledger's segments — any edit, reorder, insertion, or deletion
    of a past segment flips this to False."""
    prev = GENESIS
    for i, seg in enumerate(segments):
        if seg.get("idx") != i:
            return False
        expect = _sha256_hex(bytes.fromhex(prev) + bytes.fromhex(seg["leaf"]))
        if seg.get("chain") != expect:
            return False
        prev = expect
    return True
