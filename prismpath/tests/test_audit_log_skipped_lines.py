# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Regression: an unparseable line in the audit log is not silently dropped.

Found in the September 2026 readability review: a truncated or edited JSONL line was skipped with a bare
except and the log then verified clean over the survivors. A reader of the log must be told, and
verify_log must not call a log with holes in it intact.
"""
from prismpath.ledgers.audit_log import AuditLog


def _write_two_events(path):
    log = AuditLog(str(path))
    log.append("tester", "first", {"n": 1})
    log.append("tester", "second", {"n": 2})
    return log


def test_clean_log_has_no_skipped_lines(tmp_path):
    p = tmp_path / "audit.jsonl"
    _write_two_events(p)
    reopened = AuditLog(str(p))
    assert reopened.skipped == []
    assert len(reopened.events) == 2
    assert reopened.verify_log() is True


def test_corrupt_line_is_recorded_and_fails_verify(tmp_path):
    p = tmp_path / "audit.jsonl"
    _write_two_events(p)
    with open(p, "a") as f:
        f.write('{"actor": "tester", "action": "third", "data": {"n": 3}\n')   # truncated: no closing brace
    reopened = AuditLog(str(p))
    assert len(reopened.events) == 2
    assert reopened.skipped == [3]                # one based line numbers of the lines that did not parse
    assert reopened.verify_log() is False
