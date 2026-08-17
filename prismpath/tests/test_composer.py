# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Tranche 2 of item #4: the composer harness (fan-out spawn -> run -> join -> aggregate -> resume).

All stub agents — no model, no network. Real durable child runs on disk under tmp_path. These pin the
load-bearing guarantees: children run to terminal and the parent resumes with the aggregation; the scan
is idempotent (deterministic child ids -> no double-spawn, no double-resume); and a child that isn't
done holds the join open.
"""
import json

import pytest

from prismpath import composer
from prismpath.checkpoint import run_durable, load_checkpoint

PARENT = """---
name: parent
start: dispatch
---

## dispatch
Fan out one review per file.
@spawn(child=child.md, over=files, item_id=path, join=all_done)
-> aggregate: on event all_done
-> escalate: on timeout

## aggregate
Combine the child verdicts.

## escalate
A child timed out — hand to a human.
"""

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


def _write_flows(tmp_path):
    (tmp_path / "parent.md").write_text(PARENT)
    (tmp_path / "child.md").write_text(CHILD)


def make_agent(child_behaviour=None):
    """One agent dispatching on node name across BOTH parent and child flows. `child_behaviour(item)`
    can override a child's review outcome (e.g. to make it wait) — default: terminal 'ok' verdict."""
    def agent(node, instruction, state):
        if node == "dispatch":
            files = [{"path": "a.py"}, {"path": "b.py"}, {"path": "c.py"}]
            state["files"] = files
            return {"text": "dispatch", "wait": True, "timeout_s": 600,
                    "spawn": {"child": "child.md", "over": "files", "item_id": "path",
                              "join": "all_done", "items": files}}
        if node == "review":
            item = state.get("_item", {})
            if child_behaviour is not None:
                b = child_behaviour(item)
                if b is not None:
                    return b
            return {"text": f"reviewed {item.get('path')}", "verdict": "ok"}
        return {"text": f"ran {node}"}
    return agent


def _start_parent(tmp_path):
    _write_flows(tmp_path)
    qdir = tmp_path / "queue"
    qdir.mkdir()
    parent_ckpt = qdir / "parent.json"
    res = run_durable(str(tmp_path / "parent.md"), make_agent(), str(parent_ckpt))
    assert res.stopped == "waiting"                       # suspended at the fan-out node
    return qdir, parent_ckpt


def test_fanout_spawns_children_joins_and_resumes_parent(tmp_path):
    qdir, parent_ckpt = _start_parent(tmp_path)
    recs = composer.advance_fanouts(make_agent(), qdir=str(qdir))
    assert len(recs) == 1
    r = recs[0]
    assert r["spawned"] == 3 and r["done"] == 3 and r["joined"] is True and r["event"] == "all_done"

    parent = load_checkpoint(str(parent_ckpt))
    assert parent["stopped"] == "terminal"                # resumed through aggregate to a terminal node
    agg = parent["state"]["_spawned"]["dispatch"]
    assert agg["n"] == 3 and agg["done"] == 3
    assert sorted(k["item_id"] for k in agg["children"]) == ["a.py", "b.py", "c.py"]
    # each child was seeded with its own item and produced its verdict
    for k in agg["children"]:
        assert k["stopped"] == "terminal"
        assert any(o.get("verdict") == "ok" for o in k["outcomes"].values())


def test_children_are_durable_on_disk_under_a_children_dir(tmp_path):
    qdir, parent_ckpt = _start_parent(tmp_path)
    composer.advance_fanouts(make_agent(), qdir=str(qdir))
    child_dir = tmp_path / "queue" / "parent.children"
    assert child_dir.is_dir()
    kids = sorted(p.name for p in child_dir.glob("*.json"))
    assert kids == ["a.py.json", "b.py.json", "c.py.json"]
    # the parent scan globs queue/*.json (files) so it never sees the children subdir
    assert "parent.children" not in [p.name for p in (tmp_path / "queue").glob("*.json")]


def test_scan_is_idempotent_no_double_spawn_or_double_resume(tmp_path):
    qdir, parent_ckpt = _start_parent(tmp_path)
    first = composer.advance_fanouts(make_agent(), qdir=str(qdir))
    assert first[0]["joined"] is True
    # capture child mtimes; a second scan must NOT re-run children or re-resume the (now terminal) parent
    child_dir = tmp_path / "queue" / "parent.children"
    mtimes = {p.name: p.stat().st_mtime_ns for p in child_dir.glob("*.json")}
    second = composer.advance_fanouts(make_agent(), qdir=str(qdir))
    assert second == []                                   # parent no longer waiting -> nothing to do
    assert {p.name: p.stat().st_mtime_ns for p in child_dir.glob("*.json")} == mtimes  # untouched


def test_deterministic_child_ids_reattach_not_respawn(tmp_path):
    # If children already exist and are terminal, a scan re-attaches to them (same ids) instead of
    # spawning a second set — proven by the child checkpoints being reused, count staying at 3.
    qdir, parent_ckpt = _start_parent(tmp_path)
    composer.advance_fanouts(make_agent(), qdir=str(qdir))
    child_dir = tmp_path / "queue" / "parent.children"
    assert len(list(child_dir.glob("*.json"))) == 3
    assert composer.child_run_id("parent", "dispatch", "a.py") == "parent.dispatch.a.py"


def test_incomplete_child_holds_the_join_open(tmp_path):
    # one child suspends (wait) instead of finishing -> not terminal -> all_done not ready -> the parent
    # stays waiting and gets no aggregation.
    qdir, parent_ckpt = _start_parent(tmp_path)

    def behaviour(item):
        if item.get("path") == "b.py":
            return {"text": "b needs a signal", "wait": True}   # child suspends, never terminal
        return None

    recs = composer.advance_fanouts(make_agent(behaviour), qdir=str(qdir))
    assert recs[0]["done"] == 2 and recs[0]["joined"] is False
    parent = load_checkpoint(str(parent_ckpt))
    assert parent["stopped"] == "waiting"                  # still open
    assert "_spawned" not in parent.get("state", {})


def test_single_child_composition_is_fanout_of_one(tmp_path):
    _write_flows(tmp_path)
    qdir = tmp_path / "queue"
    qdir.mkdir()
    parent_ckpt = qdir / "p.json"

    def agent(node, instruction, state):
        if node == "dispatch":
            return {"text": "one", "wait": True,
                    "spawn": {"child": "child.md", "join": "all_done", "item_id": "path",
                              "item": {"path": "only.py"}}}
        if node == "review":
            return {"text": f"reviewed {state.get('_item', {}).get('path')}", "verdict": "ok"}
        return {"text": node}

    run_durable(str(tmp_path / "parent.md"), agent, str(parent_ckpt))
    recs = composer.advance_fanouts(agent, qdir=str(qdir))
    assert recs[0]["spawned"] == 1 and recs[0]["joined"] is True
    parent = load_checkpoint(str(parent_ckpt))
    assert parent["stopped"] == "terminal"
    assert parent["state"]["_spawned"]["dispatch"]["children"][0]["item_id"] == "only.py"


def test_item_id_precedence_field_scalar_hash():
    assert composer.item_id({"path": "x.py", "n": 1}, "path") == "x.py"   # field
    assert composer.item_id("ticket-7") == "ticket-7"                     # scalar
    h = composer.item_id({"a": 1, "b": 2})                                # content hash (no field)
    assert h.startswith("h") and h == composer.item_id({"b": 2, "a": 1})  # order-independent


def test_advance_fanouts_ignores_non_fanout_checkpoints(tmp_path):
    # a plain waiting checkpoint (no spawn spec) must be left alone by the composer scan
    _write_flows(tmp_path)
    qdir = tmp_path / "queue"
    qdir.mkdir()

    def waiter(node, instruction, state):
        return {"text": "waiting", "wait": True} if node == "review" else {"text": node}

    run_durable(str(tmp_path / "child.md"), waiter, str(qdir / "plain.json"))
    assert composer.advance_fanouts(make_agent(), qdir=str(qdir)) == []
