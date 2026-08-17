# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Routing-runner tests (Area 6, Slice 2) — per-item loop, proof-per-item, resume-from-ledger.

DoD: a run stopped mid-stream resumes at the first item with no green commit; no duplicate proofs
or appends on replay; the committed proof-hash matches the item's produced artifact.
"""
import subprocess

import pytest

from prismpath.ledger import Ledger, sha256_files
from prismpath.ledger_runner import run_ledgered_loop, upsert_jsonl, find_checkpoint
from prismpath.parser import parse
from prismpath import ledger_runner

HAS_GIT = subprocess.run(["git", "--version"], capture_output=True).returncode == 0
pytestmark = pytest.mark.skipif(not HAS_GIT, reason="git not available")

QUEUE = """---
name: queue
start: fetch
---
## fetch
Pull the next unhandled item; idle when the queue is drained.
-> idle: when no_item
-> handle: when always
## handle
@checkpoint(unit=item_id, proof=result)
Process the item and produce a result.
-> done: when always
## done
Item handled.
## idle
Nothing left to do.
"""

GATED = """---
name: gated
start: fetch
---
## fetch
-> idle: when no_item
-> check: when always
## check
@checkpoint(unit=item_id, proof=result, gate=ok)
-> done: when always
## done
## idle
"""


def _flow(tmp_path, text, name="queue.md"):
    p = tmp_path / name
    p.write_text(text)
    return str(p)


def _led(tmp_path):
    return Ledger(flow="queue", run_id="01HRUN", state_dir=tmp_path / "ledger")


class QueueAgent:
    """Mock worker: `fetch` pops the first item not already proven (via _done_units); `handle`
    processes it (optionally crashing on one item to simulate a mid-stream failure)."""
    def __init__(self, items, crash_on=None, gate=True):
        self.items = list(items)
        self.crash_on = crash_on
        self.gate = gate
        self.handled = []

    def __call__(self, node, instruction, state):
        if node in ("fetch",):
            done = state.get("_done_units", set())
            nxt = next((i for i in self.items if i not in done), None)
            if nxt is None:
                return {"text": "idle", "no_item": True}
            state["item_id"] = nxt
            state["result"] = f"result-for-{nxt}"
            return {"text": f"fetched {nxt}", "no_item": False}
        if node in ("handle", "check"):
            if self.crash_on is not None and state.get("item_id") == self.crash_on:
                raise RuntimeError(f"crash on {self.crash_on}")
            self.handled.append(state["item_id"])
            return {"text": "handled", "ok": self.gate, "always": True}
        return {"text": node, "always": True}


def test_finds_the_checkpoint_node(tmp_path):
    g = parse(QUEUE)
    node, ann = find_checkpoint(g)
    assert node == "handle"
    assert ann == {"unit": "item_id", "proof": "result"}


def test_commit_per_item_and_hash_matches(tmp_path):
    flow = _flow(tmp_path, QUEUE)
    led = _led(tmp_path)
    committed = run_ledgered_loop(flow, QueueAgent(["a", "b", "c"]), led)
    assert committed == ["a", "b", "c"]
    done = led.done_set()
    assert set(done) == {"a", "b", "c"}
    # the proof hash is exactly the content hash of the produced artifact
    assert done["b"]["output_hash"] == sha256_files({"b.proof": "result-for-b"})


def test_resume_from_ledger_skips_committed_items(tmp_path):
    flow = _flow(tmp_path, QUEUE)
    led = _led(tmp_path)
    # crash while handling "b": only "a" gets a proof
    with pytest.raises(RuntimeError):
        run_ledgered_loop(flow, QueueAgent(["a", "b", "c"], crash_on="b"), led)
    assert set(led.done_set()) == {"a"}
    # resume with a healthy worker -> processes b and c, skips the already-proven a
    agent = QueueAgent(["a", "b", "c"])
    committed = run_ledgered_loop(flow, agent, led)
    assert committed == ["b", "c"]              # a was skipped via _done_units
    assert "a" not in agent.handled            # the healthy run never re-processed a
    assert set(led.done_set()) == {"a", "b", "c"}


def test_no_duplicate_proof_on_replay(tmp_path):
    flow = _flow(tmp_path, QUEUE)
    led = _led(tmp_path)
    run_ledgered_loop(flow, QueueAgent(["a", "b"]), led)
    run_ledgered_loop(flow, QueueAgent(["a", "b"]), led)   # a full replay
    # each item has exactly one proof-commit — the replay is a no-op
    units = [r["unit"] for r in led.log()]
    assert units == ["a", "b"]


def test_gate_red_stops_without_committing(tmp_path):
    flow = _flow(tmp_path, GATED, name="gated.md")
    led = Ledger(flow="gated", run_id="01HG", state_dir=tmp_path / "ledger")
    committed = run_ledgered_loop(flow, QueueAgent(["a", "b"], gate=False), led)
    assert committed == []                      # gate never green -> no proof
    assert led.done_set() == {}


def test_missing_checkpoint_is_an_error(tmp_path):
    flow = _flow(tmp_path, "---\nstart: a\n---\n## a\n-> a: when always\n", name="nocp.md")
    led = _led(tmp_path)
    with pytest.raises(Exception):
        run_ledgered_loop(flow, QueueAgent(["a"]), led)


# --- upsert_jsonl: idempotent side effects (the "no duplicate watchlist lines" DoD) ---

def test_upsert_jsonl_dedupes_on_key(tmp_path):
    p = tmp_path / "watchlist.jsonl"
    assert upsert_jsonl(p, {"alert_id": "1", "rule": "5710", "note": "x"}, "alert_id") is True
    assert upsert_jsonl(p, {"alert_id": "1", "rule": "5710", "note": "y"}, "alert_id") is False
    assert upsert_jsonl(p, {"alert_id": "2", "rule": "5710"}, "alert_id") is True
    lines = [l for l in p.read_text().splitlines() if l.strip()]
    assert len(lines) == 2                       # replay of alert_id=1 did not add a line


def test_upsert_jsonl_composite_key(tmp_path):
    p = tmp_path / "w.jsonl"
    upsert_jsonl(p, {"agent": "vm1", "rule": "10", "v": 1}, ("agent", "rule"))
    upsert_jsonl(p, {"agent": "vm1", "rule": "10", "v": 2}, ("agent", "rule"))
    upsert_jsonl(p, {"agent": "vm1", "rule": "20", "v": 3}, ("agent", "rule"))
    assert len([l for l in p.read_text().splitlines() if l.strip()]) == 2
