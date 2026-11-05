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

Signing is optional and lives beside the log, never in it. Given an instance key, `checkpoint()` writes
a root statement (`prismpath.ledgers.root_statement`) to `<log>.roots.jsonl`: the root and leaf count
now, chained to the statement before and signed. With `sign_appends`, every append is followed by one,
which is what the hosts use. A log written before signing existed has no statements file, still reads
and still verifies, and `verify_statements` reports it as unsigned rather than failed.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time

from typing import Callable, Iterable, Optional

from prismpath.ledgers import ledger_ots as merkle
from prismpath.ledgers import root_statement as _statements
from prismpath import canon as _canon

class AuditWriteError(RuntimeError):
    """The event could not be persisted. The in memory log was not changed; nothing was committed."""


class AnchorRefused(ValueError):
    """The log is not in a state worth timestamping: it is empty, a line cannot be read, or its root
    statements do not verify. Anchoring it would put a third party's time on a record that does not hold."""


class StatementWriteError(AuditWriteError):
    """The event was persisted, and the root statement that should cover it was not. A caller that
    fails closed on AuditWriteError still does; the next statement that is written covers the event."""


def _leaf_hex(ev: dict) -> str:
    """A stable content hash of an event  -  its Merkle leaf. Commits to every field, so editing any past
    event changes its leaf and therefore the root."""
    return _canon.sha256_hex(_canon.canonical_compact(ev))


class AuditLog:
    def __init__(self, path: str, instance_key: Optional["_statements.InstanceKey"] = None,
                 sign_appends: bool = False, policy_of: Optional[Callable[[], Optional[dict]]] = None,
                 statements_path: Optional[str] = None):
        self.path = path
        self.instance_key = instance_key
        self.sign_appends = sign_appends
        self.policy_of = policy_of            # the policy identity in force, when the owner knows it
        self.statements_path = statements_path or (_statements.statements_path_for(path) if path else None)
        self._signer: Optional[_statements.RootSigner] = None
        self._lock = threading.Lock()
        self.events: list = []
        self.leaves: list = []
        self.skipped: list = []
        self._accumulator = _statements.MerkleAccumulator()      # the root as leaves arrive, for signing
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
                    self._accumulator.add(self.leaves[-1])

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
            self._accumulator.add(self.leaves[-1])
            if self.sign_appends and self.instance_key is not None:
                self._sign_locked("append", None)
            return event

    @property
    def signing(self) -> bool:
        """True when this log writes root statements: it has an instance key and a file to sit beside."""
        return self.instance_key is not None and bool(self.statements_path)

    def _sign_locked(self, trigger: str, policy: Optional[dict]) -> Optional[dict]:
        if not self.signing or not self.leaves:
            return None
        if policy is None and self.policy_of is not None:
            policy = self.policy_of()
        if self._signer is None:
            self._signer = _statements.RootSigner(self.instance_key, self.statements_path, _statements.LOG_AUDIT)
        if self._accumulator.count != len(self.leaves):        # the leaves were edited under us: rebuild
            self._accumulator = _statements.MerkleAccumulator(self.leaves)
        try:
            return self._signer.sign(self._accumulator.root(), len(self.leaves), trigger, policy)
        except OSError as error:
            raise StatementWriteError(f"root statement not persisted to {self.statements_path}: {error}") from error

    def checkpoint(self, trigger: str = "checkpoint", policy: Optional[dict] = None) -> Optional[dict]:
        """Sign the root as it stands: one root statement covering every leaf so far. Returns it, or
        None when there is no instance key or nothing to cover. Raises StatementWriteError when the
        statement cannot be persisted."""
        with self._lock:
            return self._sign_locked(trigger, policy)

    def root_at(self, leaf_count: int) -> str:
        """The Merkle root over the first `leaf_count` leaves: what a statement of that count signed."""
        return _statements.merkle_root(self.leaves[:leaf_count])

    def verify_statements(self, pinned: Optional[Iterable[bytes]] = None) -> dict:
        """Check the root statements beside the log against the log: status signed, signed-unpinned,
        unsigned or invalid, with every finding (truncation, a rewritten leaf, a wrong key, a broken
        chain, a statement whose root does not match). Checking a signature needs the signing extra."""
        statements, read_findings = _statements.read_statements(self.statements_path)
        if self.skipped:
            read_findings = read_findings + [{"finding": "bad_format", "log_lines": list(self.skipped)}]
        # One pass over the leaves gives the root at every signed count, so a log signed after every event
        # is checked in linear time, not by rebuilding the tree once per statement.
        roots = _statements.prefix_roots(self.leaves, (statement.get("leaves") for statement in statements))
        return _statements.verify_chain(
            statements, read_findings, lambda count: roots.get(count, ""), len(self.leaves), log=_statements.LOG_AUDIT,
            pinned=pinned, authority_key_ids=_statements.authority_key_ids_in(self.events))

    def anchor_target(self) -> dict:
        """What `ledger anchor --log` timestamps, and which kind it is. With root statements it is the hash
        of the latest one, which covers its signature and, through the chain, every statement before it;
        `kind` is `root-statement`, and `unsigned_tail` counts the events after the leaves it signed, which
        a timestamp on that statement does not cover. Without any it is the Merkle root over every event,
        `kind` `merkle-root`: the events are timestamped, who recorded them is not. Raises `AnchorRefused`
        for an empty log, an unreadable line, or root statements that do not verify (checking them needs
        the signing extra)."""
        if not self.events:
            raise AnchorRefused("the log holds no events: there is nothing to anchor")
        if self.skipped:
            raise AnchorRefused(f"the log has unreadable lines {self.skipped}: it does not verify")
        statements, _findings = _statements.read_statements(self.statements_path)
        if not statements:
            root = self.current_root()
            return {"kind": "merkle-root", "hash": root, "root": root, "leaves": len(self.leaves),
                    "log_leaves": len(self.leaves), "unsigned_tail": 0, "statement": None, "key": None}
        report = self.verify_statements()
        if report["status"] == _statements.INVALID:
            fatal = list(dict.fromkeys(finding["finding"] for finding in report["findings"]
                                       if finding["finding"] in _statements.FATAL_FINDINGS))
            raise AnchorRefused(f"the log's root statements do not verify ({', '.join(fatal)}); "
                                f"`prismpath trail` names each finding")
        last = next(statement for statement in reversed(statements) if statement)
        return {"kind": "root-statement", "hash": _statements.statement_hash(last), "root": last["root"],
                "leaves": last["leaves"], "log_leaves": len(self.leaves), "unsigned_tail": report["unsigned_tail"],
                "statement": last["seq"], "key": report["keys"][-1] if report["keys"] else None}

    def holds_anchor(self, record: dict) -> bool:
        """True when the log still holds what an `anchor_target` record names: the root statement with
        that hash in its chain, or the Merkle root over the first `leaves` events. Appending to the log
        after the anchor does not change the answer; editing or dropping what was anchored does."""
        if record.get("kind") == "root-statement":
            statements, _findings = _statements.read_statements(self.statements_path)
            return any(statement and _statements.statement_hash(statement) == record.get("hash") for statement in statements)
        count = record.get("leaves")
        return isinstance(count, int) and 0 < count <= len(self.leaves) and self.root_at(count) == record.get("hash")

    def receipt_bundle(self, index: int) -> dict:
        """One receipt with its inclusion path and the signed statement that covers it, checkable
        offline by `root_statement.verify_receipt_bundle`."""
        if not (0 <= index < len(self.events)):
            raise IndexError(f"receipt index out of range: {index} (the log holds {len(self.events)})")
        statements, _findings = _statements.read_statements(self.statements_path)
        return _statements.receipt_bundle(self.events[index], self.leaves, index, statements)

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
