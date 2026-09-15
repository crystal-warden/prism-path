# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Regression: the OpenTimestamps tool's exit code is part of the answer.

Found in the September 2026 readability review: anchor() reported stamped from the existence of a
.ots file, upgrade() returned only the tool's text, and verify_unit() returned the verifier's text as
an opaque blob, so a failed stamp, upgrade or verification could look like success to the caller.
"""
import json
import subprocess
import types

from prismpath.ledgers import ledger_ots as ledger_ots

LEAVES = ["ab" * 32, "cd" * 32]


def _fake_run(rc, make_ots=False):
    def run(cmd, **kw):
        if make_ots and cmd[0] == "ots" and cmd[1] == "stamp":
            open(cmd[2] + ".ots", "wb").write(b"\x00")
        return types.SimpleNamespace(returncode=rc, stdout=f"fake ots rc={rc}", stderr="")
    return run


def test_anchor_reports_the_tool_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(ledger_ots.subprocess, "run", _fake_run(1))
    res = ledger_ots.anchor(LEAVES, str(tmp_path), "t")
    assert res["ots_rc"] == 1
    assert res["stamped"] is False


def test_anchor_reports_success_only_with_rc_zero_and_the_file(tmp_path, monkeypatch):
    monkeypatch.setattr(ledger_ots.subprocess, "run", _fake_run(0, make_ots=True))
    res = ledger_ots.anchor(LEAVES, str(tmp_path), "t")
    assert res["ots_rc"] == 0
    assert res["stamped"] is True


def test_upgrade_returns_the_exit_code(tmp_path, monkeypatch):
    monkeypatch.setattr(ledger_ots.subprocess, "run", _fake_run(2))
    res = ledger_ots.upgrade(str(tmp_path), "t")
    assert isinstance(res, dict) and res["ots_rc"] == 2 and "fake ots" in res["ots_msg"]


def test_verify_unit_reports_the_verifier_exit_code(tmp_path, monkeypatch):
    monkeypatch.setattr(ledger_ots.subprocess, "run", _fake_run(0, make_ots=True))
    ledger_ots.anchor(LEAVES, str(tmp_path), "t")
    monkeypatch.setattr(ledger_ots.subprocess, "run", _fake_run(1))
    res = ledger_ots.verify_unit(LEAVES[0], str(tmp_path), "t")
    assert res["merkle_ok"] is True
    assert res["ots_ok"] is False
    monkeypatch.setattr(ledger_ots.subprocess, "run", _fake_run(0))
    assert ledger_ots.verify_unit(LEAVES[0], str(tmp_path), "t")["ots_ok"] is True
