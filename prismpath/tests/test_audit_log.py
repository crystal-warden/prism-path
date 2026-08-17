# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""audit_log now carries a real, tamper-evident Merkle root (via ledger_ots), behind the unchanged
interface Mission Control + the guard ledger consume. Pin that."""
import os

from prismpath.audit_log import AuditLog, _leaf_hex, verify


def _log(tmp_path, n=5):
    log = AuditLog(str(tmp_path / "audit.log"))
    for i in range(n):
        log.append("tester", "act", {"n": i})
    return log


def test_root_is_a_real_hash(tmp_path):
    log = _log(tmp_path)
    root = log.current_root()
    assert len(root) == 64 and all(c in "0123456789abcdef" for c in root)   # sha256 hex


def test_empty_log(tmp_path):
    log = AuditLog(str(tmp_path / "e.log"))
    assert log.current_root() == "" and log.verify_log() is True


def test_every_leaf_proves_and_verifies(tmp_path):
    log = _log(tmp_path, 9)
    root = log.current_root()
    for i in range(len(log.leaves)):
        pr = log.prove(i)
        assert "path" in pr and "peaks" in pr
        assert verify(log.leaves[i], pr, root)
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
