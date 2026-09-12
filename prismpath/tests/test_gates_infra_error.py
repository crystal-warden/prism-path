# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Regression: a gate whose own machinery crashes must not report a clean pass.

Found in the September 2026 readability review: behavioral_check caught any exception from the
browser harness, printed "gate infra error (skipped)" and returned no errors, so a broken gate
looked like a passing one. The deliberate skip when playwright is not installed stays; a crash
after the gate has started is a failed gate.
"""
import os

import pytest

pytest.importorskip("playwright")

from prismpath.orchestration import gates


def test_gate_crash_is_a_failure_not_a_pass(tmp_path, monkeypatch):
    (tmp_path / "index.html").write_text("<html><body><button id='go'>go</button></body></html>")

    def boom(*a, **k):
        raise RuntimeError("chromium exploded")

    import playwright.sync_api
    monkeypatch.setattr(playwright.sync_api, "sync_playwright", boom)
    errs = gates.behavioral_check(str(tmp_path))
    assert errs, "a crashed gate returned no errors"
    assert any("infrastructure" in e or "infra" in e for e in errs)
    assert any("chromium exploded" in e for e in errs)
