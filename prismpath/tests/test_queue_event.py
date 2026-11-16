# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Event delivery through the queue (Mission Control O3): an event recorded into a `waiting`
checkpoint the way a decision is recorded into a suspended one, applied by the run's next resume, so
the console never needs the flow's worker to deliver it. No model, no .md writes."""
import pytest

from prismpath.ledgers import checkpoint

WATCH = """---
name: watch
start: hold
---
## hold
Wait for the stand down signal, or give up after a while.
-> clear: on event stand_down
-> late: on timeout
## clear
Stood down.
## late
Timed out.
"""

GATE = """---
name: gate
start: gate
---
## gate
A human must approve.
-> approve: when approved
-> deny: when denied
## approve
-> done: when always
## deny
-> done: when always
## done
Done.
"""


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


def _waiting_agent(node, instruction, state):
    if node == "hold":
        return {"text": "holding", "wait": True, "timeout_s": 60}
    return {"text": node}


def _gate_agent(node, instruction, state):
    if node == "gate":
        return {"text": "unsure", "needs_human": True, "reason": "policy sign-off"}
    return {"text": node, "always": True}


def _scripted_worker(seen):
    """A worker that only records which nodes it was asked to run: a resume that re-ran `hold` would
    show it here."""
    def worker(node, instruction, state):
        seen.append(node)
        return {"text": node}
    return worker


@pytest.fixture
def waiting(tmp_path):
    ckpt = tmp_path / "queue" / "w1.json"
    ckpt.parent.mkdir(parents=True, exist_ok=True)
    result = checkpoint.run_durable(_write(tmp_path, "watch.md", WATCH), _waiting_agent, str(ckpt))
    assert result.stopped == "waiting"
    return ckpt


@pytest.fixture
def suspended(tmp_path):
    ckpt = tmp_path / "queue" / "h1.json"
    ckpt.parent.mkdir(parents=True, exist_ok=True)
    result = checkpoint.run_durable(_write(tmp_path, "gate.md", GATE), _gate_agent, str(ckpt))
    assert result.stopped == "needs_human"
    return ckpt


# ── the checkpoint half: record an event, resume applies it ────────────────────────────────────
def test_a_waiting_checkpoint_with_a_recorded_event_resumes_along_its_on_event_edge(waiting):
    recorded = checkpoint.record_event(str(waiting), "stand_down", decided_by="console/operating/abc")
    assert recorded["pending_event"] == {"event": "stand_down", "decided_by": "console/operating/abc"}
    seen = []
    result = checkpoint.resume(str(waiting), _scripted_worker(seen))     # no explicit event
    assert result.path == ["hold", "clear"]
    assert result.stopped == "terminal"
    assert "hold" not in seen, "the resume re-ran the waiting node instead of delivering the event"
    delivered = [entry for entry in result.state["transcript"] if entry.get("event")]
    assert delivered == [{"node": "hold", "outcome": "[event: stand_down]", "event": "stand_down",
                          "decided_by": "console/operating/abc"}]


def test_the_timeout_is_delivered_as_an_event_along_the_on_timeout_edge(waiting):
    checkpoint.record_event(str(waiting), checkpoint.TIMEOUT_EVENT)
    assert checkpoint.TIMEOUT_EVENT == "__timeout__"
    result = checkpoint.resume(str(waiting), _scripted_worker([]))
    assert result.path == ["hold", "late"]


def test_an_explicit_event_on_resume_wins_over_the_recorded_one(waiting):
    checkpoint.record_event(str(waiting), "stand_down")
    assert checkpoint.resume(str(waiting), _scripted_worker([]), event="__timeout__").path == ["hold", "late"]


def test_a_needs_human_checkpoint_refuses_an_event(suspended):
    before = suspended.read_bytes()
    with pytest.raises(checkpoint.CheckpointError, match="not waiting for an event"):
        checkpoint.record_event(str(suspended), "stand_down")
    assert suspended.read_bytes() == before


def test_an_event_the_node_does_not_await_is_refused(waiting):
    before = waiting.read_bytes()
    with pytest.raises(checkpoint.CheckpointError, match="awaiting"):
        checkpoint.record_event(str(waiting), "launch")
    assert waiting.read_bytes() == before


def test_the_queue_lists_waiting_runs_only_when_asked(waiting, suspended):
    qdir = str(waiting.parent)
    assert [item["id"] for item in checkpoint.list_queue(qdir)] == ["h1"]      # unchanged default
    items = {item["id"]: item for item in checkpoint.list_queue(qdir, include_waiting=True)}
    assert set(items) == {"h1", "w1"}
    assert items["h1"]["stopped"] == "needs_human"
    assert items["w1"]["stopped"] == "waiting"
    assert items["w1"]["awaiting"] == ["stand_down", "__timeout__"]
    assert items["w1"]["timeout_s"] == 60 and items["w1"]["pending_event"] is None and items["w1"]["fanout"] is False
