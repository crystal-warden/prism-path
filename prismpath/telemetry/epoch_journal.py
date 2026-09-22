# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A durable journal around the epoch store, so retention and acknowledgment survive a restart.

The edge seals stream windows into chained epochs (`epochs.EpochStore`) and forgets their bytes when
the ground acknowledges them (`ackchannel.AckReceiver`). Both kept everything in memory, so a power
loss during an unreliable connection lost the retained readings and the acknowledgment state at once.
This journal keeps the same objects and writes each state change to a directory in a fixed order,
so what a restart finds is either complete or explicitly reported.

Files under the journal directory:
  chain.jsonl        one line per sealed epoch: id, Merkle root, chained root, sha256 and byte length
                     of the data file; appended and fsynced AFTER the data file is durable. The chain
                     is the authority of what was sealed.
  epochs/<id>.json   the epoch's blocks, written atomically (temp file, fsync, rename) BEFORE its chain
                     line. Deleted on acknowledgment or under pressure, never edited.
  acks.json          the acknowledgment state, `last_seq` and `acked_through`, written atomically
                     after the tag and the sequence verified and BEFORE any data file is deleted.
  gaps.jsonl         one line per epoch whose unacknowledged data was dropped under pressure,
                     appended and fsynced BEFORE the data file is deleted, so a loss is recorded
                     before it happens and never after the fact.

Recovery order, at every start:
  1. chain.jsonl is read. A torn final line is discarded and reported as `interrupted_seal`; a torn
     line anywhere else is corruption and the journal refuses to open, because a chain with a hole
     proves nothing.
  2. Every data file named by the chain is loaded when present. A file whose sha256 or length does
     not match its chain line is reported as `corrupt_data` and treated as a pressure drop: the
     readings are lost, and the loss is a named gap. A data file the chain does not name is an
     orphan of an interrupted seal, reported and removed.
  3. acks.json is applied: every epoch up to `acked_through` is acknowledged and any data file it
     still has is deleted, reported as `completed_ack`, so an acknowledgment interrupted between the
     state write and the deletion finishes here and never repeats a deletion the state does not cover.
  4. gaps.jsonl marks the pressure drops, and any such data file still present is deleted.
  5. The retention caps are enforced as at any seal.
`recovery_report()` lists every finding; a caller that wants no surprises reads it.

Disk limits: `max_data_epochs` caps the epochs holding data, as in the memory store, and
`max_bytes` caps the bytes of data files on disk. When either forces an unacknowledged epoch out,
the gap is recorded before the file goes.

An acknowledgment deletes data only through `DurableAckReceiver`, which verifies the tag, checks
the sequence against the persisted one, persists the new sequence and the acknowledged root, and
only then deletes. A replayed acknowledgment, before or after a restart, has a stale sequence and
deletes nothing; a forged one fails its tag and deletes nothing.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Dict, List, Optional

from prismpath import canon
from prismpath.telemetry import ackchannel
from prismpath.telemetry import epochs as epoch_module
from prismpath.telemetry import selfheal as sh

CHAIN_FILE = "chain.jsonl"
ACKS_FILE = "acks.json"
GAPS_FILE = "gaps.jsonl"
EPOCH_DIRECTORY = "epochs"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _append_line(path: str, record: dict) -> None:
    """Append one JSON line and fsync it, so the line is on disk before the caller moves on. A crash
    mid write leaves a torn final line, which recovery discards and reports."""
    line = json.dumps(record, sort_keys=True) + "\n"
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())


class JournalCorrupt(RuntimeError):
    """The chain has a hole that is not a torn final line; the journal refuses to open."""


class EpochJournal:
    def __init__(self, directory: str, block_bits: int, max_data_epochs: int = 3, max_bytes: Optional[int] = None):
        self.directory = directory
        self.block_bits = block_bits
        self.max_data_epochs = max_data_epochs
        self.max_bytes = max_bytes
        self.store = epoch_module.EpochStore(block_bits, max_data_epochs)
        self.last_seq = -1
        self.acked_through: Optional[str] = None
        self._recovery: List[dict] = []
        os.makedirs(os.path.join(directory, EPOCH_DIRECTORY), exist_ok=True)
        self._recover()

    # ------------------------------------------------------------------ paths
    def _chain_path(self) -> str:
        return os.path.join(self.directory, CHAIN_FILE)

    def _acks_path(self) -> str:
        return os.path.join(self.directory, ACKS_FILE)

    def _gaps_path(self) -> str:
        return os.path.join(self.directory, GAPS_FILE)

    def _data_path(self, epoch_id: int) -> str:
        return os.path.join(self.directory, EPOCH_DIRECTORY, f"{epoch_id}.json")

    # ------------------------------------------------------------------ recovery
    def _read_jsonl(self, path: str, torn_finding: str) -> List[dict]:
        if not os.path.exists(path):
            return []
        with open(path, "r", encoding="utf-8") as handle:
            raw_lines = handle.read().split("\n")
        if raw_lines and raw_lines[-1] == "":
            raw_lines.pop()
        records = []
        for index, line in enumerate(raw_lines):
            try:
                records.append(json.loads(line))
            except ValueError:
                if index == len(raw_lines) - 1:
                    self._recovery.append({"finding": torn_finding, "file": os.path.basename(path), "line": index + 1})
                    self._truncate_to(path, raw_lines[:-1])
                    break
                raise JournalCorrupt(f"{path}: line {index + 1} is not JSON and is not the last line")
        return records

    def _truncate_to(self, path: str, lines: List[str]) -> None:
        canon.atomic_write(path, "".join(line + "\n" for line in lines))

    def _recover(self) -> None:
        self._recovery = []
        chain = self._read_jsonl(self._chain_path(), "interrupted_seal")
        acks = {}
        if os.path.exists(self._acks_path()):
            try:
                acks = json.loads(open(self._acks_path(), encoding="utf-8").read())
            except ValueError:
                # atomic_write means a torn acks.json cannot exist; a corrupt one is a real fault
                raise JournalCorrupt(f"{self._acks_path()} is not JSON")
        gaps = {record["epoch_id"] for record in self._read_jsonl(self._gaps_path(), "interrupted_gap_record")}

        expected_prev = ""
        for record in chain:
            epoch_id = record["epoch_id"]
            if epoch_module.chain_root(expected_prev, record["merkle_root"]) != record["chained_root"]:
                raise JournalCorrupt(f"chain link broken at epoch {epoch_id}")
            expected_prev = record["chained_root"]
            blocks = None
            data_path = self._data_path(epoch_id)
            if os.path.exists(data_path):
                data = open(data_path, "rb").read()
                if len(data) != record["data_length"] or _sha256(data) != record["data_sha256"]:
                    self._recovery.append({"finding": "corrupt_data", "epoch_id": epoch_id, "lost": True})
                    _append_line(self._gaps_path(), {"epoch_id": epoch_id, "reason": "corrupt_data"})
                    gaps.add(epoch_id)
                    os.remove(data_path)
                else:
                    blocks = json.loads(data.decode("utf-8"))
            epoch = epoch_module.Epoch(epoch_id, blocks, record["merkle_root"], record["chained_root"])
            self.store.epochs.append(epoch)
        named = {record["epoch_id"] for record in chain}
        for name in sorted(os.listdir(os.path.join(self.directory, EPOCH_DIRECTORY))):
            if name.endswith(".json") and int(name[:-5]) not in named:
                self._recovery.append({"finding": "orphan_data", "epoch_id": int(name[:-5]), "lost": True})
                os.remove(os.path.join(self.directory, EPOCH_DIRECTORY, name))

        self.last_seq = int(acks.get("last_seq", -1))
        self.acked_through = acks.get("acked_through")
        if self.acked_through is not None:
            completed = self._apply_ack_to_files(self.acked_through)
            if completed:
                self._recovery.append({"finding": "completed_ack", "epochs": completed})
        for epoch in self.store.epochs:
            if epoch.id in gaps and not epoch.acked:
                epoch.dropped_under_pressure = True
                if epoch.has_data():
                    self._recovery.append({"finding": "completed_gap", "epoch_id": epoch.id})
                    epoch.blocks = None
                    self._remove_data(epoch.id)
        self._enforce_caps()

    def recovery_report(self) -> List[dict]:
        """Every finding of the last recovery; empty when the journal was found complete."""
        return list(self._recovery)

    # ------------------------------------------------------------------ sealing
    def seal(self, bits: str) -> epoch_module.Epoch:
        """Data file first, chain line second, caps third. A crash between the first two leaves an
        orphan that recovery reports and removes; the chain never names an epoch it lacks."""
        blocks = sh.chunk(bits, self.block_bits)
        merkle_root, _proofs = sh.commit(blocks)
        prev = self.store.epochs[-1].chained_root if self.store.epochs else ""
        epoch_id = len(self.store.epochs)
        data = json.dumps(blocks).encode("utf-8")
        canon.atomic_write(self._data_path(epoch_id), data.decode("utf-8"))
        chained = epoch_module.chain_root(prev, merkle_root)
        _append_line(self._chain_path(), {"epoch_id": epoch_id, "merkle_root": merkle_root, "chained_root": chained,
                                          "data_sha256": _sha256(data), "data_length": len(data)})
        epoch = epoch_module.Epoch(epoch_id, blocks, merkle_root, chained)
        self.store.epochs.append(epoch)
        self._enforce_caps()
        return epoch

    def _remove_data(self, epoch_id: int) -> None:
        try:
            os.remove(self._data_path(epoch_id))
        except FileNotFoundError:
            pass

    def _data_bytes_on_disk(self) -> int:
        total = 0
        for epoch in self.store.epochs:
            path = self._data_path(epoch.id)
            if os.path.exists(path):
                total += os.path.getsize(path)
        return total

    def _drop_under_pressure(self, epoch: epoch_module.Epoch) -> None:
        """Record the loss, then delete. An acknowledged epoch's bytes are simply gone; an
        unacknowledged one is a provable gap."""
        if not epoch.acked:
            _append_line(self._gaps_path(), {"epoch_id": epoch.id, "reason": "pressure"})
            epoch.dropped_under_pressure = True
        epoch.blocks = None
        self._remove_data(epoch.id)

    def _enforce_caps(self) -> None:
        with_data = [epoch for epoch in self.store.epochs if epoch.has_data()]
        while len(with_data) > self.max_data_epochs:
            self._drop_under_pressure(with_data.pop(0))
        if self.max_bytes is not None:
            while with_data and self._data_bytes_on_disk() > self.max_bytes:
                self._drop_under_pressure(with_data.pop(0))

    # ------------------------------------------------------------------ acknowledgment
    def _apply_ack_to_files(self, chained_root: str) -> List[int]:
        """Mark every epoch up to the root acknowledged and delete its data file. Idempotent, so
        recovery can finish an interrupted acknowledgment."""
        index = next((position for position, epoch in enumerate(self.store.epochs) if epoch.chained_root == chained_root), None)
        if index is None:
            return []
        completed = []
        for epoch in self.store.epochs[:index + 1]:
            epoch.acked = True
            if epoch.has_data() or os.path.exists(self._data_path(epoch.id)):
                epoch.blocks = None
                self._remove_data(epoch.id)
                completed.append(epoch.id)
        return completed

    def ack(self, chained_root: str, seq: int) -> int:
        """State first, deletion second. Only DurableAckReceiver should call this, after the tag
        and the sequence verified; the persisted sequence is what makes a replay stale after a
        restart. Returns the number of epochs whose data was dropped."""
        if not any(epoch.chained_root == chained_root for epoch in self.store.epochs):
            return 0
        canon.atomic_write(self._acks_path(), json.dumps({"last_seq": seq, "acked_through": chained_root}, sort_keys=True))
        self.last_seq = seq
        self.acked_through = chained_root
        return len(self._apply_ack_to_files(chained_root))

    # ------------------------------------------------------------------ queries, delegated
    def chain(self) -> List[str]:
        return self.store.chain()

    def verify_chain(self) -> bool:
        return self.store.verify_chain()

    def gaps(self) -> List[int]:
        return self.store.gaps()

    def retransmittable(self) -> List[int]:
        return self.store.retransmittable()

    def retained(self) -> Dict[int, List[str]]:
        """The readings still recoverable: epoch id to its blocks."""
        return {epoch.id: list(epoch.blocks) for epoch in self.store.epochs if epoch.has_data()}


class DurableAckReceiver:
    """The edge side of the acknowledgment channel over a journal: verify, persist, then delete."""

    def __init__(self, journal: EpochJournal, secret: bytes):
        self.journal = journal
        self.secret = secret

    def on_ack(self, root: str, seq: int, tag: str) -> dict:
        if not ackchannel.verify_ack(self.secret, root, seq, tag):
            return {"accepted": False, "reason": "bad-tag", "dropped": 0}
        if seq <= self.journal.last_seq:
            return {"accepted": False, "reason": "stale-seq", "dropped": 0}
        dropped = self.journal.ack(root, seq)
        return {"accepted": True, "reason": "ok", "dropped": dropped}
