# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Error-edge tests (critic capability #3) — failure handling in the readable document.

`-> t: on error` routes when the worker raises; `on error when error_count >= N` conditions on the
error context. No handler => the exception propagates (backward compatible).
"""
import pytest

from prismpath import predicates
from prismpath.engine import run
from prismpath.parser import parse

RETRY = """---
name: retry
start: work
---
## work
Do the thing; may fail.
-> done: when ok
-> work: on error when error_count < 3
-> give_up: on error
## done
## give_up
"""


def test_predicate_tiers():
    assert predicates.is_error("on error")
    assert predicates.is_error("on error when error_count >= 2")
    assert not predicates.is_error("the bug is reproduced")
    assert predicates.is_semantic("the bug is reproduced")
    assert not predicates.is_semantic("on error")           # error edges are NOT semantic
    assert not predicates.is_semantic("when tests_pass")
    assert predicates.error_expr("on error") == ""
    assert predicates.error_expr("on error when error_count < 3") == "when error_count < 3"


def test_on_error_routes_on_raise():
    calls = {"n": 0}
    def agent(node, instr, state):
        if node == "work":
            calls["n"] += 1
            if calls["n"] <= 2:
                raise RuntimeError("boom")          # fail twice, then succeed
            return {"text": "done", "ok": True}
        return {"text": node, "always": True}
    res = run(parse(RETRY), agent)
    # work (err)->work (err)->work (ok)->done ; error_count hits 2 (<3) both times -> retry
    assert res.path == ["work", "work", "work", "done"]
    assert res.stopped == "terminal"


def test_error_count_predicate_falls_through_to_give_up():
    def agent(node, instr, state):
        if node == "work":
            raise RuntimeError("always broken")
        return {"text": node, "always": True}
    res = run(parse(RETRY), agent)
    # error_count 1,2 -> retry; 3 -> `error_count < 3` false -> falls to bare `on error` -> give_up
    assert res.path[-1] == "give_up"
    assert res.path.count("work") == 3


def test_no_error_edge_reraises():
    flow = parse("---\nstart: a\n---\n## a\n-> b: when always\n## b\n")
    def agent(node, instr, state):
        raise ValueError("unhandled")
    with pytest.raises(ValueError):
        run(flow, agent)                            # no `on error` edge -> propagate (unchanged)


def test_error_step_recorded_with_used_error():
    def agent(node, instr, state):
        if node == "work":
            raise KeyError("k")
        return {"text": node, "always": True}
    res = run(RETRY_ONE := parse("---\nstart: work\n---\n## work\n-> done: on error\n## done\n"), agent)
    assert res.path == ["work", "done"]
    assert res.steps[0].info["used"] == "error" and res.steps[0].info["error_type"] == "KeyError"
