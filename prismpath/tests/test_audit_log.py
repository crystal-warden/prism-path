# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""audit_log now carries a real, tamper-evident Merkle root (via ledger_ots), behind the unchanged
interface Mission Control + the guard ledger consume. Pin that."""
import os

import builtins

import pytest

from prismpath.ledgers.audit_log import AuditLog, AuditWriteError, _leaf_hex, verify


def _log(tmp_path, count=5):
    log = AuditLog(str(tmp_path / "audit.log"))
    for i in range(count):
        log.append("tester", "act", {"n": i})
    return log


def test_root_is_a_real_hash(tmp_path):
    log = _log(tmp_path)
    root = log.current_root()
    assert len(root) == 64 and all(character in "0123456789abcdef" for character in root)   # sha256 hex


def test_empty_log(tmp_path):
    log = AuditLog(str(tmp_path / "e.log"))
    assert log.current_root() == "" and log.verify_log() is True


def test_every_leaf_proves_and_verifies(tmp_path):
    log = _log(tmp_path, 9)
    root = log.current_root()
    for leaf_index in range(len(log.leaves)):
        pr = log.prove(leaf_index)
        assert "path" in pr and "peaks" in pr
        assert verify(log.leaves[leaf_index], pr, root)
    assert log.verify_log() is True


def test_tampered_leaf_fails_verify(tmp_path):
    log = _log(tmp_path)
    pr = log.prove(2)
    assert verify(log.leaves[2], pr, log.current_root())        # genuine
    assert not verify("00" * 32, pr, log.current_root())        # substituted leaf -> rejected


def test_leaf_commits_to_content(tmp_path):
    e1 = {"idx": 0, "id": "0", "ts": 1.0, "actor": "x", "action": "a", "data": {"n": 1}}
    e2 = {"idx": 0, "id": "0", "ts": 1.0, "actor": "x", "action": "a", "data": {"n": 2}}
    assert _leaf_hex(e1) != _leaf_hex(e2)                       # content change -> different leaf
    assert _leaf_hex(e1) == _leaf_hex(dict(e1))                 # same content -> stable leaf


def test_root_stable_across_reopen(tmp_path):
    path = str(tmp_path / "persist.log")
    log = AuditLog(path)
    for i in range(4):
        log.append("x", "act", {"n": i})
    root = log.current_root()
    assert AuditLog(path).current_root() == root                # reload re-derives the same root


def test_failed_write_commits_nothing(tmp_path, monkeypatch):
    """A write the file refuses must not leave an event in the tree: the tree would then verify while
    the evidence does not exist."""
    log = AuditLog(str(tmp_path / "audit.log"))
    log.append("tester", "first", {})
    real_open = builtins.open

    def refusing_open(path, *args, **kwargs):
        if str(path).endswith("audit.log") and "a" in (args[0] if args else kwargs.get("mode", "r")):
            raise OSError(28, "No space left on device")
        return real_open(path, *args, **kwargs)
    monkeypatch.setattr(builtins, "open", refusing_open)
    with pytest.raises(AuditWriteError):
        log.append("tester", "second", {})
    monkeypatch.setattr(builtins, "open", real_open)
    assert len(log.events) == 1 and len(log.leaves) == 1
    assert log.verify_log() is True and log.verify_persisted() is True


def test_verify_persisted_distinguishes_structure_from_the_file(tmp_path):
    log = _log(tmp_path, 3)
    assert log.verify_log() is True and log.verify_persisted() is True
    with open(str(tmp_path / "audit.log"), "w") as log_file:
        log_file.write("")
    assert log.verify_log() is True, "the structure in memory is intact"
    assert log.verify_persisted() is False, "the file no longer holds the events"
    assert AuditLog("").verify_persisted() is False, "a log without a path is not evidence"
