# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Regression tests for the six bugs the adversarial pass found in item #4 (fan-out & composition).
Each test fails against the pre-fix code and passes after. Stub agents; real durable runs on disk.
"""
from prismpath import composer, checkpoint
from prismpath.checkpoint import run_durable, load_checkpoint


CHILD = """---
name: child
start: review
---

## review
Review one item.
-> done: always

## done
Done.
"""

PARENT = """---
name: parent
start: dispatch
---

## dispatch
Fan out.
@spawn(child=child.md, over=items, item_id=path, join=all_done)
-> aggregate: on event all_done
-> escalate: on timeout

## aggregate
Combine.

## escalate
Human.
"""


def _flows(tmp_path, parent=PARENT, child=CHILD):
    (tmp_path / "parent.md").write_text(parent)
    (tmp_path / "child.md").write_text(child)
    q = tmp_path / "queue"
    q.mkdir()
    return q


# --- Bug 1: collision-free child identity --------------------------------------------
def test_lossy_item_ids_do_not_collide(tmp_path):
    q = _flows(tmp_path)

    def agent(node, instruction, state):
        if node == "dispatch":
            items = [{"path": "a/b"}, {"path": "a_b"}]      # distinct ids, both -> 'a_b' under _safe
            state["items"] = items
            return {"text": "d", "wait": True, "spawn": {"items": items}}
        if node == "review":
            return {"text": f"reviewed {state['_item']['path']}", "seen": state["_item"]["path"]}
        return {"text": node}

    run_durable(str(tmp_path / "parent.md"), agent, str(q / "p.json"))
    rec = composer.advance_fanouts(agent, qdir=str(q))[0]
    assert rec["spawned"] == 2 and rec["done"] == 2
    kids = load_checkpoint(str(q / "p.json"))["state"]["_spawned"]["dispatch"]["children"]
    seen = {o["seen"] for k in kids for o in k["outcomes"].values()}
    assert seen == {"a/b", "a_b"}                          # both distinct items were actually reviewed


# --- Bug 2: nested composition (depth > 1) -------------------------------------------
def test_nested_composition_completes(tmp_path):
    (tmp_path / "top.md").write_text("""---
name: top
start: dispatch_top
---

## dispatch_top
@spawn(child=mid.md, over=items, item_id=id, join=all_done)
-> agg: on event all_done

## agg
Done top.
""")
    (tmp_path / "mid.md").write_text("""---
name: mid
start: dispatch_mid
---

## dispatch_mid
@spawn(child=leaf.md, over=items, item_id=id, join=all_done)
-> agg: on event all_done

## agg
Done mid.
""")
    (tmp_path / "leaf.md").write_text("""---
name: leaf
start: work
---

## work
-> fin: always

## fin
Done leaf.
""")
    q = tmp_path / "queue"
    q.mkdir()

    def agent(node, instruction, state):
        if node == "dispatch_top":
            state["items"] = [{"id": "m1"}]
            return {"text": "top", "wait": True, "spawn": {"items": state["items"]}}
        if node == "dispatch_mid":
            state["items"] = [{"id": "l1"}, {"id": "l2"}]
            return {"text": "mid", "wait": True, "spawn": {"items": state["items"]}}
        return {"text": node}

    run_durable(str(tmp_path / "top.md"), agent, str(q / "top.json"))
    rec = composer.advance_fanouts(agent, qdir=str(q))[0]
    assert rec["joined"] is True                            # top joined -> its whole subtree finished
    assert load_checkpoint(str(q / "top.json"))["stopped"] == "terminal"


# --- Bug 3: the @spawn annotation is authoritative for the join (no drift deadlock) --
def test_annotation_join_overrides_a_diverging_runtime_join(tmp_path):
    # annotation says join=all_done (edge present); a buggy worker spec says quorum:5 (no such edge).
    # The annotation wins, so the fan-out still joins instead of firing an eventless 'quorum'.
    q = _flows(tmp_path)

    def agent(node, instruction, state):
        if node == "dispatch":
            items = [{"path": "a.py"}, {"path": "b.py"}]
            state["items"] = items
            return {"text": "d", "wait": True,
                    "spawn": {"items": items, "join": "quorum:5"}}   # divergent — must be ignored
        return {"text": node}

    run_durable(str(tmp_path / "parent.md"), agent, str(q / "p.json"))
    rec = composer.advance_fanouts(agent, qdir=str(q))[0]
    assert rec["joined"] is True and rec["event"] == "all_done"     # annotation's join, not the spec's
    assert "error" not in rec


def test_over_reads_items_from_parent_state(tmp_path):
    # the worker need not hand items in the spec — @spawn(over=items) reads them from parent state
    q = _flows(tmp_path)

    def agent(node, instruction, state):
        if node == "dispatch":
            state["items"] = [{"path": "x.py"}, {"path": "y.py"}]
            return {"text": "d", "wait": True, "spawn": {}}          # no items in the spec
        return {"text": node}

    run_durable(str(tmp_path / "parent.md"), agent, str(q / "p.json"))
    rec = composer.advance_fanouts(agent, qdir=str(q))[0]
    assert rec["spawned"] == 2 and rec["joined"] is True


# --- Bug 4: a non-serializable child is marked errored, not resumed forever -----------
def test_unserializable_child_is_errored_not_looped(tmp_path):
    q = _flows(tmp_path)

    def agent(node, instruction, state):
        if node == "dispatch":
            state["items"] = [{"path": "a.py"}]
            return {"text": "d", "wait": True, "spawn": {"items": state["items"]}}
        if node == "review":
            return {"text": "r", "bad": {1, 2, 3}}             # a set -> not JSON serializable
        return {"text": node}

    run_durable(str(tmp_path / "parent.md"), agent, str(q / "p.json"))
    rec1 = composer.advance_fanouts(agent, qdir=str(q))[0]
    child_dir = tmp_path / "queue" / "p.children"
    child = load_checkpoint(str(next(child_dir.glob("*.json"))))
    assert child["stopped"] == "error"                        # marked, not left mid-run
    assert rec1["joined"] is False                            # all_done can't be met with a failed child
    # a second scan must NOT re-run the errored child (no infinite loop) — its checkpoint is stable
    mtime = next(child_dir.glob("*.json")).stat().st_mtime_ns
    composer.advance_fanouts(agent, qdir=str(q))
    assert next(child_dir.glob("*.json")).stat().st_mtime_ns == mtime


# --- Bug 5: aggregation 'done' agrees with the gate-based join ------------------------
def test_aggregate_done_is_gate_consistent(tmp_path):
    # join + gate declared in the ANNOTATION (the authoritative place, per the bug-3 fix)
    q = _flows(tmp_path, parent="""---
name: parent
start: dispatch
---

## dispatch
Fan out.
@spawn(child=child.md, over=items, item_id=path, join=quorum:1, gate=ok)
-> aggregate: on event quorum

## aggregate
Combine.
""")

    def agent(node, instruction, state):
        if node == "dispatch":
            items = [{"path": "a.py"}, {"path": "b.py"}, {"path": "c.py"}]
            state["items"] = items
            return {"text": "d", "wait": True, "spawn": {"items": items}}
        if node == "review":
            return {"text": "r", "ok": state["_item"]["path"] == "a.py"}   # only a.py passes the gate
        return {"text": node}

    run_durable(str(tmp_path / "parent.md"), agent, str(q / "p.json"))
    composer.advance_fanouts(agent, qdir=str(q))
    agg = load_checkpoint(str(q / "p.json"))["state"]["_spawned"]["dispatch"]
    assert agg["done"] == 1 and agg["terminal"] == 3         # gate-passing vs raw-terminal, distinct


# --- Bug 6: a needs_human child is discoverable in the queue -------------------------
def test_needs_human_child_is_visible_in_the_queue(tmp_path):
    q = _flows(tmp_path)

    def agent(node, instruction, state):
        if node == "dispatch":
            state["items"] = [{"path": "a.py"}]
            return {"text": "d", "wait": True, "spawn": {"items": state["items"]}}
        if node == "review":
            return {"text": "needs a person", "needs_human": True, "reason": "unsure"}
        return {"text": node}

    run_durable(str(tmp_path / "parent.md"), agent, str(q / "p.json"))
    composer.advance_fanouts(agent, qdir=str(q))
    items = checkpoint.list_queue(str(q))
    child_items = [it for it in items if it.get("child_of")]
    assert child_items and child_items[0]["child_of"] == "p"   # surfaced, tagged with its parent
    assert child_items[0]["reason"] == "unsure"
