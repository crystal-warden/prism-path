# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Tranche 3 of item #4: join policies (all_done / any / quorum), gate-based child success, and the
fan-out timeout — which reuses the EXISTING scheduler (a fan-out parent is just a `waiting` checkpoint
with a timer, so scheduler.fire_due_timeouts delivers `__timeout__` and takes the `on timeout` edge).

Stub agents throughout; real durable child runs on disk.
"""
from prismpath import composer, scheduler
from prismpath.checkpoint import run_durable, load_checkpoint


CHILD = """---
name: child
start: review
---

## review
Review one file.
-> done: always

## done
Finish.
"""

# a parent that can join on all_done, quorum, any, OR time out — one edge per possibility.
PARENT = """---
name: parent
start: dispatch
---

## dispatch
Fan out.
-> aggregate: on event all_done
-> aggregate: on event quorum
-> aggregate: on event any
-> escalate: on timeout

## aggregate
Combine.

## escalate
Timed out -> human.
"""


def _setup(tmp_path):
    (tmp_path / "parent.md").write_text(PARENT)
    (tmp_path / "child.md").write_text(CHILD)
    qdir = tmp_path / "queue"
    qdir.mkdir()
    return qdir


def _agent(spec, child_behaviour=None):
    def agent(node, instruction, state):
        if node == "dispatch":
            return {"text": "dispatch", "wait": True, "timeout_s": 600, "spawn": spec}
        if node == "review":
            item = state.get("_item", {})
            if child_behaviour:
                b = child_behaviour(item)
                if b is not None:
                    return b
            return {"text": f"reviewed {item.get('path')}", "verdict": "ok"}
        return {"text": node}
    return agent


def _items(n):
    return [{"path": f"f{i}.py"} for i in range(n)]


# --- quorum ---------------------------------------------------------------------------
def test_quorum_fires_with_a_straggler_left_running(tmp_path):
    qdir = _setup(tmp_path)
    spec = {"child": "child.md", "item_id": "path", "join": "quorum:2", "items": _items(3)}

    def behaviour(item):
        return {"text": "blocked", "wait": True} if item["path"] == "f2.py" else None  # 1 straggler

    agent = _agent(spec, behaviour)
    run_durable(str(tmp_path / "parent.md"), agent, str(qdir / "p.json"))
    recs = composer.advance_fanouts(agent, qdir=str(qdir))
    assert recs[0]["done"] == 2 and recs[0]["joined"] is True and recs[0]["event"] == "quorum"
    parent = load_checkpoint(str(qdir / "p.json"))
    assert parent["stopped"] == "terminal"
    agg = parent["state"]["_spawned"]["dispatch"]
    assert agg["n"] == 3 and agg["done"] == 2          # straggler reported but did not block


def test_quorum_not_met_holds_open(tmp_path):
    qdir = _setup(tmp_path)
    spec = {"child": "child.md", "item_id": "path", "join": "quorum:3", "items": _items(3)}

    def behaviour(item):
        return {"text": "blocked", "wait": True} if item["path"] in ("f1.py", "f2.py") else None

    agent = _agent(spec, behaviour)
    run_durable(str(tmp_path / "parent.md"), agent, str(qdir / "p.json"))
    recs = composer.advance_fanouts(agent, qdir=str(qdir))
    assert recs[0]["done"] == 1 and recs[0]["joined"] is False
    assert load_checkpoint(str(qdir / "p.json"))["stopped"] == "waiting"


def test_quorum_threshold_int_and_fraction():
    assert composer._quorum_threshold("quorum:2", 5) == 2
    assert composer._quorum_threshold("quorum:0.6", 5) == 3     # ceil(3.0)
    assert composer._quorum_threshold("quorum:0.5", 3) == 2     # ceil(1.5)
    assert composer._quorum_threshold("quorum:9", 3) == 3       # clamped to n
    assert composer._quorum_threshold("quorum:junk", 4) == 4    # malformed -> all_done-like


# --- any ------------------------------------------------------------------------------
def test_any_fires_on_first_done(tmp_path):
    qdir = _setup(tmp_path)
    spec = {"child": "child.md", "item_id": "path", "join": "any", "items": _items(3)}

    def behaviour(item):
        return None if item["path"] == "f0.py" else {"text": "blocked", "wait": True}

    agent = _agent(spec, behaviour)
    run_durable(str(tmp_path / "parent.md"), agent, str(qdir / "p.json"))
    recs = composer.advance_fanouts(agent, qdir=str(qdir))
    assert recs[0]["done"] == 1 and recs[0]["joined"] is True and recs[0]["event"] == "any"
    assert load_checkpoint(str(qdir / "p.json"))["stopped"] == "terminal"


# --- gate-based success ---------------------------------------------------------------
def test_gate_field_defines_child_success(tmp_path):
    # a child that reaches terminal WITHOUT the gate field truthy does not count as done
    qdir = _setup(tmp_path)
    spec = {"child": "child.md", "item_id": "path", "join": "all_done", "gate": "approved",
            "items": _items(2)}

    def behaviour(item):
        return {"text": "reviewed", "approved": item["path"] == "f0.py"}   # only f0 approved

    agent = _agent(spec, behaviour)
    run_durable(str(tmp_path / "parent.md"), agent, str(qdir / "p.json"))
    recs = composer.advance_fanouts(agent, qdir=str(qdir))
    assert recs[0]["done"] == 1 and recs[0]["joined"] is False   # f1 terminal but not approved
    assert load_checkpoint(str(qdir / "p.json"))["stopped"] == "waiting"


def test_gate_with_quorum(tmp_path):
    qdir = _setup(tmp_path)
    spec = {"child": "child.md", "item_id": "path", "join": "quorum:2", "gate": "approved",
            "items": _items(3)}

    def behaviour(item):
        return {"text": "reviewed", "approved": item["path"] in ("f0.py", "f1.py")}

    agent = _agent(spec, behaviour)
    run_durable(str(tmp_path / "parent.md"), agent, str(qdir / "p.json"))
    recs = composer.advance_fanouts(agent, qdir=str(qdir))
    assert recs[0]["done"] == 2 and recs[0]["joined"] is True    # 2 approved meets quorum:2


# --- timeout via the existing scheduler ----------------------------------------------
def test_fanout_times_out_through_the_scheduler(tmp_path):
    # No composer run at all: a fan-out parent is a waiting checkpoint with a timer, so the ordinary
    # scheduler delivers __timeout__ and the parent takes its `on timeout` edge -> escalate.
    qdir = _setup(tmp_path)
    spec = {"child": "child.md", "item_id": "path", "join": "all_done", "items": _items(3)}
    agent = _agent(spec)
    run_durable(str(tmp_path / "parent.md"), agent, str(qdir / "p.json"))
    cp = load_checkpoint(str(qdir / "p.json"))
    deadline = cp["saved_at"] + cp["pending_decision"]["timeout_s"] + 1
    fired = scheduler.fire_due_timeouts(agent, qdir=str(qdir), now=deadline)
    assert len(fired) == 1
    parent = load_checkpoint(str(qdir / "p.json"))
    assert parent["stopped"] == "terminal"
    assert parent["path"][-1] == "escalate"             # took the on-timeout edge


def test_missing_join_edge_is_recorded_not_raised(tmp_path):
    # a fan-out whose join event has no matching edge (author error) must not crash the scan — the
    # harness records the error and moves on (analysis.py will flag this statically in T4).
    (tmp_path / "child.md").write_text(CHILD)
    (tmp_path / "parent.md").write_text("""---
name: parent
start: dispatch
---

## dispatch
Fan out with no join edge.
-> escalate: on timeout

## escalate
Human.
""")
    qdir = tmp_path / "queue"
    qdir.mkdir()
    spec = {"child": "child.md", "item_id": "path", "join": "all_done", "items": _items(2)}
    agent = _agent(spec)
    run_durable(str(tmp_path / "parent.md"), agent, str(qdir / "p.json"))
    recs = composer.advance_fanouts(agent, qdir=str(qdir))
    assert "error" in recs[0] and recs[0]["joined"] is False     # recorded, scan survived
