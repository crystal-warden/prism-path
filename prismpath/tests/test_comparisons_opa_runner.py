# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The OPA runner's failure path: an exception while evaluating is a Decision, not a crash.

The handler that turns a subprocess or parse failure into `Decision("error", ...)` named an
identifier the except clause did not bind, so every failure raised NameError out of the runner and
the harness lost the cell instead of grading it.
"""
from pathlib import Path

from prismpath.comparisons.systems import opa


def test_a_failed_eval_is_reported_as_an_error_decision(tmp_path, monkeypatch):
    def refuse(*_args, **_kwargs):
        raise FileNotFoundError("opa binary is not installed")

    monkeypatch.setattr(opa.subprocess, "run", refuse)
    runner = opa.Runner({"id": "any_policy"}, Path(tmp_path))
    decision = runner.decide({"amount": 10})
    assert decision.observed == "error"
    assert "opa binary is not installed" in decision.raw
