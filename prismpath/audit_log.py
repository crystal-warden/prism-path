# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""audit_log.py — an append-only action log for Mission Control, with a real (tamper-evident) Merkle root.

Every control action (start/stop a sprint, edit a file, run an ad-hoc query, …) is appended as a line to
a JSONL file, so the console has a chronological record of what happened and who did it — the
*observability* layer.

Each event is committed as a Merkle leaf (sha256 of its canonical form) using the repo's own Merkle
primitive (`prismpath.ledger_ots`), so `current_root()` is a real root that changes if any past event is
altered, `prove(i)` yields a real inclusion proof, and `verify()` checks it. Anchor `current_root()` with
`ledger_ots` (OTS / Bitcoin) to make the trail externally tamper-evident over time. The interface is
unchanged from the earlier stub, so Mission Control and the guard ledger consume it as-is.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time

from prismpath import ledger_ots as _mk


def _leaf_hex(ev: dict) -> str:
    """A stable content hash of an event — its Merkle leaf. Commits to every field, so editing any past
    event changes its leaf and therefore the root."""
    canon = json.dumps(ev, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self.events: list = []
        self.leaves: list = []
        if path and os.path.exists(path):
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                    except Exception:
                        continue
                    self.events.append(ev)
                    self.leaves.append(_leaf_hex(ev))

    def append(self, actor: str, action: str, data: dict) -> dict:
        with self._lock:
            idx = len(self.events)
            ev = {"idx": idx, "id": f"{idx}", "ts": time.time(),
                  "actor": actor, "action": action, "data": data}
            self.events.append(ev)
            self.leaves.append(_leaf_hex(ev))
            if self.path:
                os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
                with open(self.path, "a") as f:
                    f.write(json.dumps(ev) + "\n")
            return ev

    def current_root(self) -> str:
        """The Merkle root over all event leaves (hex); empty string for an empty log. Anchor it via
        `ledger_ots` (OTS) to make the trail externally tamper-evident."""
        root, _paths = _mk.merkle_root_and_paths(self.leaves)
        return root or ""

    def verify_log(self) -> bool:
        """Every leaf's inclusion proof verifies against the current root (structural integrity). Detecting
        tampering *over time* comes from anchoring `current_root()` and re-deriving it later."""
        if not self.leaves:
            return True
        root, paths = _mk.merkle_root_and_paths(self.leaves)
        return all(_mk.verify_leaf(self.leaves[i], paths[i], root) for i in range(len(self.leaves)))

    def prove(self, i: int) -> dict:
        """Inclusion proof for event `i`: {'path': [...], 'peaks': [root]}. `path` feeds `verify()`."""
        root, paths = _mk.merkle_root_and_paths(self.leaves)
        if not (0 <= i < len(paths)):
            raise IndexError(f"leaf index out of range: {i}")
        return {"path": paths[i], "peaks": [root] if root else []}


def verify(leaf, proof, root) -> bool:
    """Verify a leaf's inclusion against the root. `proof` may be a `prove()` dict or a raw path list."""
    path = proof.get("path", []) if isinstance(proof, dict) else proof
    if not root:
        return False
    return _mk.verify_leaf(leaf, path, root)
