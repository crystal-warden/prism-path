# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Regression: an error edge whose guard cannot be evaluated is recorded, not swallowed.

Found in the September 2026 readability review: a PredicateError raised while evaluating an
`on error when` guard was caught with `pass`, so a handler that never fired left no trace. The
deterministic tier's documented rule (an unevaluable predicate does not match) is kept; what
changes is that the run's state now says it happened, and the step that took the fallback says
how many guards failed.
"""
import pytest

from prismpath.kernel.engine import run
from prismpath.kernel.parser import parse

FLOW = """---
name: guard
start: work
---

## work
-> handled: on error when len(error_message) > 3
-> fallback: on error
-> done: when ok

## handled
Handled.

## fallback
Fallback.

## done
Done.
"""


def _raising_worker(node, instruction, state):
    if node == "work":
        raise RuntimeError("boom")
    return {"ok": True}


def test_unevaluable_guard_is_recorded_and_skipped():
    graph = parse(FLOW)
    state = {"transcript": [], "visits": {}}
    res = run(graph, _raising_worker, state=state, max_steps=5)
    assert res.path[:2] == ["work", "fallback"]
    assert state["_guard_errors"] == [{"node": "work", "guard": "when len(error_message) > 3", "error": state["_guard_errors"][0]["error"]}]
    assert "disallowed" in state["_guard_errors"][0]["error"]
    step = res.steps[0]
    assert step.info["used"] == "error" and step.info["guard_errors"] == 1


def test_evaluable_guard_leaves_no_record():
    graph = parse(FLOW.replace("len(error_message) > 3", "error_count >= 2"))
    state = {"transcript": [], "visits": {}}
    res = run(graph, _raising_worker, state=state, max_steps=5)
    assert res.path[:2] == ["work", "fallback"]
    assert "_guard_errors" not in state
    assert "guard_errors" not in res.steps[0].info
