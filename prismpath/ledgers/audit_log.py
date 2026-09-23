# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""audit_log.py  -  an append-only action log for Mission Control, with a real (tamper-evident) Merkle root.

Every control action (start/stop a sprint, edit a file, run an ad-hoc query, …) is appended as a line to
a JSONL file, so the console has a chronological record of what happened and who did it  -  the
*observability* layer.

Each event is committed as a Merkle leaf (sha256 of its canonical form) using the repo's own Merkle
primitive (`prismpath.ledger_ots`), so `current_root()` is a real root that changes if any past event is
altered, `prove(i)` yields a real inclusion proof, and `verify()` checks it. Anchor `current_root()` with
`ledger_ots` (OTS / Bitcoin) to make the trail externally tamper-evident over time. The interface is
unchanged from the earlier stub, so Mission Control and the guard ledger consume it as-is.

Persistence is part of the promise. `append` writes the event to the file, flushes and fsyncs it, and
only then commits the event to the in memory tree, so an event the file does not hold never has a leaf.
A write that fails raises `AuditWriteError` and leaves the log exactly as it was. `verify_log` checks
the structure of what is in memory; `verify_persisted` checks that the file holds the same events, the
question the structural check cannot answer. A caller that must not act without evidence appends
first and acts only when append returned, which is how the policy host commits a swap; a caller that
records after acting must surface the error rather than continue as if the record existed.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time

from prismpath.ledgers import ledger_ots as merkle
from prismpath import canon as _canon

class AuditWriteError(RuntimeError):
    """The event could not be persisted. The in memory log was not changed; nothing was committed."""


def _leaf_hex(ev: dict) -> str:
    """A stable content hash of an event  -  its Merkle leaf. Commits to every field, so editing any past
    event changes its leaf and therefore the root."""
    return _canon.sha256_hex(_canon.canonical_compact(ev))


class AuditLog:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self.events: list = []
        self.leaves: list = []
        self.skipped: list = []
        if path and os.path.exists(path):
            with open(path) as log_file:
                for line_num, line in enumerate(log_file, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                    except Exception:
                        self.skipped.append(line_num)
                        continue
                    self.events.append(ev)
                    self.leaves.append(_leaf_hex(ev))

    def append(self, actor: str, action: str, data: dict) -> dict:
        """Persist the event, then commit it to the tree. Raises AuditWriteError, with the log
        unchanged, when the file cannot take it."""
        with self._lock:
            index = len(self.events)
            event = {"idx": index, "id": f"{index}", "ts": time.time(),
                     "actor": actor, "action": action, "data": data}
            line = json.dumps(event) + "\n"
            if self.path:
                try:
                    os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
                    with open(self.path, "a") as log_file:
                        log_file.write(line)
                        log_file.flush()
                        os.fsync(log_file.fileno())
                except OSError as error:
                    raise AuditWriteError(f"audit event not persisted to {self.path}: {error}") from error
            self.events.append(event)
            self.leaves.append(_leaf_hex(event))
            return event

    def verify_persisted(self) -> bool:
        """True when the file holds exactly the events in memory, line for line. A log with no path is
        never persisted and answers False, so a caller cannot mistake an in memory log for evidence."""
        if not self.path or not os.path.exists(self.path):
            return False
        with self._lock:
            on_disk = []
            with open(self.path) as log_file:
                for line in log_file:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        on_disk.append(_leaf_hex(json.loads(line)))
                    except Exception:
                        return False
            return on_disk == self.leaves

    def current_root(self) -> str:
        """The Merkle root over all event leaves (hex); empty string for an empty log. Anchor it via
        `ledger_ots` (OTS) to make the trail externally tamper-evident."""
        root, _paths = merkle.merkle_root_and_paths(self.leaves)
        return root or ""

    def verify_log(self) -> bool:
        """Every leaf's inclusion proof verifies against the current root: structural integrity of what
        is in memory, and nothing about the file. `verify_persisted` answers the persistence question.
        Detecting tampering *over time* comes from anchoring `current_root()` and re-deriving it later."""
        # A log with a line that cannot be read is not a log that verifies
        if self.skipped:
            return False
        if not self.leaves:
            return True
        root, paths = merkle.merkle_root_and_paths(self.leaves)
        return all(merkle.verify_leaf(self.leaves[i], paths[i], root) for i in range(len(self.leaves)))

    def prove(self, leaf_index: int) -> dict:
        """Inclusion proof for event `leaf_index`: {'path': [...], 'peaks': [root]}. `path` feeds `verify()`."""
        root, paths = merkle.merkle_root_and_paths(self.leaves)
        if not (0 <= leaf_index < len(paths)):
            raise IndexError(f"leaf index out of range: {leaf_index}")
        return {"path": paths[leaf_index], "peaks": [root] if root else []}


def verify(leaf, proof, root) -> bool:
    """Verify a leaf's inclusion against the root. `proof` may be a `prove()` dict or a raw path list."""
    path = proof.get("path", []) if isinstance(proof, dict) else proof
    if not root:
        return False
    return merkle.verify_leaf(leaf, path, root)
