# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Every crate copy is byte identical to the product corpus it copies, in the real tree, and a drifted
or missing copy is reported on a fixture tree."""
from pathlib import Path

from tools import fixture_sync


def test_real_tree_copies_are_identical():
    assert fixture_sync.check() == []


def test_drift_and_absence_are_reported(tmp_path):
    for copy, authority in fixture_sync.pairs():
        (tmp_path / authority).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / authority).write_bytes(b"{}")
        (tmp_path / copy).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / copy).write_bytes(b"{}")
    first_copy, _ = fixture_sync.pairs()[0]
    (tmp_path / first_copy).write_bytes(b"{ }")
    second_copy, _ = fixture_sync.pairs()[1]
    (tmp_path / second_copy).unlink()
    problems = fixture_sync.check(tmp_path)
    assert any(problem.startswith(first_copy) and "differs" in problem for problem in problems)
    assert any(problem.startswith(second_copy) and "missing" in problem for problem in problems)
    assert len(problems) == 2
