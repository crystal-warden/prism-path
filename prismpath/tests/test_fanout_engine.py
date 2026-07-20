"""Tranche 1 of roadmap item #4 (fan-out & sub-flow composition): the ENGINE side.

The engine's whole contribution to fan-out is a single, pure passthrough: a worker that returns
{"wait": True, "spawn": <data spec>} suspends as an ordinary `waiting` node AND the spawn spec is
recorded in RunResult.pending — so the durable checkpoint carries everything the out-of-band harness
(composer.py) needs, while the engine itself spawns nothing and does no I/O. These tests pin exactly
that contract with stub agents (no model, no network, no child runs yet).
"""
import json

from prismpath.engine import run
from prismpath.parser import parse
from prismpath import checkpoint as ckpt

# A parent flow whose fan-out node declares its structure with @spawn and its joins as event edges.
PARENT = """---
name: parent
start: dispatch
---

## dispatch
Fan out one review sub-run per changed file.
@spawn(child=flows/review_one.md, over=files, item_id=path, join=all_done)
-> aggregate: on event all_done
-> escalate: on timeout

## aggregate
Combine the child verdicts.

## escalate
A child timed out; hand to a human.
"""

SPAWN_SPEC = {
    "child": "flows/review_one.md",
    "join": "all_done",
    "items": [{"path": "a.py"}, {"path": "b.py"}, {"path": "c.py"}],
}


def fanout_agent(node, instruction, state):
    """At the fan-out node, produce the item list into state and ask to wait, handing over a spawn
    spec. Any other node is a plain terminal-ish worker."""
    if node == "dispatch":
        state["files"] = SPAWN_SPEC["items"]
        return {"text": "dispatching 3 reviews", "wait": True, "spawn": SPAWN_SPEC,
                "timeout_s": 600}
    return {"text": f"ran {node}"}


def test_fanout_node_suspends_waiting_with_spawn_spec_in_pending():
    g = parse(PARENT)
    res = run(g, fanout_agent)
    assert res.stopped == "waiting"
    assert res.pending["node"] == "dispatch"
    # the join events the node can be resumed by are surfaced from its event edges
    assert set(res.pending["awaiting"]) == {"all_done", "__timeout__"}
    # the spawn spec is passed through UNCHANGED as data — the engine neither interprets nor mutates it
    assert res.pending["spawn"] == SPAWN_SPEC
    assert res.pending["timeout_s"] == 600


def test_wait_without_spawn_has_no_spawn_key():
    # backward compatibility: an ordinary wait-for-event node (no fan-out) carries no 'spawn'
    flow = parse("""---
name: w
start: hold
---

## hold
Wait for a webhook.
-> go: on event ping

## go
Done.
""")

    def agent(node, instruction, state):
        return {"text": "waiting", "wait": True} if node == "hold" else {"text": "done"}

    res = run(flow, agent)
    assert res.stopped == "waiting"
    assert "spawn" not in res.pending


def test_engine_is_pure_spawn_spec_is_untouched_data(tmp_path):
    # The engine spawns nothing and writes nothing: it only records the spec. A nested/complex spec
    # survives byte-for-byte, and the run wrote no files of its own.
    g = parse(PARENT)
    before = set(p.name for p in tmp_path.iterdir())
    res = run(g, fanout_agent)
    after = set(p.name for p in tmp_path.iterdir())
    assert before == after                              # run() touched the filesystem not at all
    assert res.pending["spawn"] is not None
    assert json.loads(json.dumps(res.pending["spawn"])) == SPAWN_SPEC   # pure JSON data, no objects


def test_spawn_spec_round_trips_through_the_checkpoint(tmp_path):
    # The durable checkpoint must carry the spawn spec (in pending_decision) so the harness can read it
    # after a crash without the parent's in-memory state.
    g = parse(PARENT)
    cp_path = tmp_path / "parent.ckpt.json"
    flow_path = tmp_path / "parent.md"
    flow_path.write_text(PARENT)

    saved = {}

    def on_step(res, pending_node):
        ckpt.save_checkpoint(cp_path, flow_path, res, pending_node)
        saved["last"] = pending_node

    res = run(g, fanout_agent, on_step=on_step)
    assert res.stopped == "waiting"
    cp = ckpt.load_checkpoint(cp_path)
    assert cp["stopped"] == "waiting"
    assert cp["pending_decision"]["spawn"] == SPAWN_SPEC
    assert cp["pending_decision"]["node"] == "dispatch"


def test_spawn_implies_wait():
    # a worker returning `spawn` WITHOUT `wait` still suspends — fanning out is meaningless without
    # suspending for the join, so the footgun (spawn silently dropped) is closed at the engine.
    g = parse(PARENT)

    def forgot_wait(node, instruction, state):
        if node == "dispatch":
            return {"text": "d", "spawn": SPAWN_SPEC}      # no "wait" key
        return {"text": node}

    res = run(g, forgot_wait)
    assert res.stopped == "waiting"
    assert res.pending["spawn"] == SPAWN_SPEC


def test_single_child_composition_is_fanout_of_one():
    # sub-flow composition is just a fan-out whose item list has one element — identical code path.
    g = parse(PARENT)

    def one_agent(node, instruction, state):
        if node == "dispatch":
            spec = {"child": "flows/review_one.md", "join": "all_done", "items": [{"path": "only.py"}]}
            return {"text": "one child", "wait": True, "spawn": spec}
        return {"text": node}

    res = run(g, one_agent)
    assert res.stopped == "waiting"
    assert len(res.pending["spawn"]["items"]) == 1
