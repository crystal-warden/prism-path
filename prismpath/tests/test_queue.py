# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Human-queue tests (Area 6) — the Mission Control queue backend: list suspended runs, record a
human's decision, and resume by applying it. No real model, no .md writes."""
import json

import pytest

from prismpath.ledgers import checkpoint

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


def _flow(tmp_path):
    path = tmp_path / "gate.md"
    path.write_text(GATE)
    return str(path)


def _suspend_agent(node, instruction, state):
    if node == "gate":
        return {"text": "unsure — escalating", "needs_human": True, "reason": "policy sign-off"}
    return {"text": node, "always": True}


def _plain_agent(node, instruction, state):
    return {"text": node, "always": True}


def test_list_queue_shows_only_suspended_with_evidence(tmp_path):
    queue_dir = tmp_path / "queue"
    queue_dir.mkdir()
    flow = _flow(tmp_path)
    # one suspended run in the queue...
    checkpoint.run_durable(flow, _suspend_agent, str(queue_dir / "run1.json"))
    # ...and one that finished (should NOT appear)
    checkpoint.run_durable(flow, _plain_agent, str(queue_dir / "run2.json"))

    items = checkpoint.list_queue(str(queue_dir))
    assert len(items) == 1
    it = items[0]
    assert it["id"] == "run1" and it["flow"] == "gate" and it["node"] == "gate"
    assert it["reason"] == "policy sign-off"
    assert {candidate["target"] for candidate in it["candidates"]} == {"approve", "deny"}
    assert it["decision"] is None


def test_record_decision_validates_and_persists(tmp_path):
    queue_dir = tmp_path / "queue"
    queue_dir.mkdir()
    ckpt = str(queue_dir / "r.json")
    checkpoint.run_durable(_flow(tmp_path), _suspend_agent, ckpt)
    with pytest.raises(checkpoint.CheckpointError):
        checkpoint.record_decision(ckpt, "nonexistent")
    checkpoint.record_decision(ckpt, "approve")
    saved = json.load(open(ckpt))
    assert saved["decision"] == {"choose": "approve", "decided_by": "human"}
    # it now shows as decided in the queue listing
    assert checkpoint.list_queue(str(queue_dir))[0]["decision"]["choose"] == "approve"


def test_resume_applies_recorded_decision(tmp_path):
    queue_dir = tmp_path / "queue"
    queue_dir.mkdir()
    ckpt = str(queue_dir / "r.json")
    checkpoint.run_durable(_flow(tmp_path), _suspend_agent, ckpt)
    checkpoint.record_decision(ckpt, "approve")          # operator clicked "approve" in the UI
    res = checkpoint.resume(ckpt, _plain_agent)          # runner resumes with NO explicit choose
    assert res.path == ["gate", "approve", "done"]
    assert res.stopped == "terminal"
    human = [entry for entry in res.state["transcript"] if entry.get("decided_by") == "human"]
    assert human and human[0]["node"] == "gate"


def test_record_decision_rejects_non_suspended(tmp_path):
    queue_dir = tmp_path / "queue"
    queue_dir.mkdir()
    ckpt = str(queue_dir / "r.json")
    checkpoint.run_durable(_flow(tmp_path), _plain_agent, ckpt)   # terminal, not awaiting a human
    with pytest.raises(checkpoint.CheckpointError):
        checkpoint.record_decision(ckpt, "approve")


def test_queue_dir_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMPATH_QUEUE_DIR", str(tmp_path / "myq"))
    assert checkpoint.queue_dir() == str(tmp_path / "myq")


def test_list_queue_missing_dir_is_empty():
    assert checkpoint.list_queue("/nonexistent/queue/dir") == []


# --- follow-on to item #4: nested child queue items are actionable, safely ---------------
def test_resolve_queue_item_top_level_and_child(tmp_path):
    queue_dir = tmp_path / "q"
    (queue_dir / "p.children").mkdir(parents=True)
    (queue_dir / "run1.json").write_text("{}")
    (queue_dir / "p.children" / "a.py.json").write_text("{}")
    assert checkpoint.resolve_queue_item("run1", str(queue_dir)).endswith("run1.json")
    assert checkpoint.resolve_queue_item("p.children/a.py", str(queue_dir)).endswith("a.py.json")


def test_resolve_queue_item_blocks_traversal(tmp_path):
    import pytest
    queue_dir = tmp_path / "q"
    queue_dir.mkdir()
    (tmp_path / "outside.json").write_text("{}")
    with pytest.raises(checkpoint.CheckpointError):
        checkpoint.resolve_queue_item("../outside", str(queue_dir))
    with pytest.raises(checkpoint.CheckpointError):
        checkpoint.resolve_queue_item("/etc/passwd", str(queue_dir))
    with pytest.raises(checkpoint.CheckpointError):
        checkpoint.resolve_queue_item("nope", str(queue_dir))            # missing item
