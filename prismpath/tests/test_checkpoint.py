"""Durable-execution tests (Area 6, Slice 0) — checkpoint + resume, no real model, no .md writes.

The load-bearing guarantees:
  * crash-and-resume is deterministic: same checkpoint => identical continuation;
  * a needs_human suspension resumes on the human's chosen edge;
  * the router's absolute-score floor suspends instead of guessing;
  * the flow .md is NEVER written;
  * checkpointing is off the critical path (bad state disables it, run still completes).
"""
import json

import pytest

from prismpath.parser import parse_file
from prismpath.engine import run, RunResult
from prismpath.router import RouteDecision
from prismpath import checkpoint

LINEAR = """---
name: linear
start: a
---
## a
Step a.
-> b: when always
## b
Step b.
-> c: when always
## c
Step c.
-> done: when always
## done
Done.
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

SEMANTIC = """---
name: semantic
start: triage
---
## triage
Decide.
-> stage: the alert is malicious and must be contained
-> ignore: the alert is benign noise
## stage
-> done: when always
## ignore
-> done: when always
## done
Done.
"""


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return str(p)


class CrashAt:
    """Mock agent that raises the first time it reaches `crash_node` (simulating a process death)."""
    def __init__(self, crash_node=None):
        self.crash_node = crash_node
        self.seen = []

    def __call__(self, node, instruction, state):
        self.seen.append(node)
        if node == self.crash_node:
            raise RuntimeError(f"simulated crash at {node}")
        return {"text": node, "always": True}


def test_full_run_baseline(tmp_path):
    flow = _write(tmp_path, "linear.md", LINEAR)
    ckpt = str(tmp_path / "ck.json")
    res = checkpoint.run_durable(flow, CrashAt(None), ckpt)
    assert res.path == ["a", "b", "c", "done"]
    assert res.stopped == "terminal"


def _crash_at_b(tmp_path):
    flow = _write(tmp_path, "linear.md", LINEAR)
    ckpt = str(tmp_path / "ck.json")
    with pytest.raises(RuntimeError):
        checkpoint.run_durable(flow, CrashAt("b"), ckpt)
    return flow, ckpt


def test_resume_refuses_when_flow_edited(tmp_path):
    flow, ckpt = _crash_at_b(tmp_path)
    with open(flow, "a") as f:
        f.write("\n## extra\nan added node\n")            # the flow changed while suspended
    with pytest.raises(checkpoint.CheckpointError):
        checkpoint.resume(ckpt, CrashAt(None))            # default policy: refuse (audit-safe)


def test_resume_warn_policy_proceeds_on_edit(tmp_path, monkeypatch, capsys):
    flow, ckpt = _crash_at_b(tmp_path)
    with open(flow, "a") as f:
        f.write("\n## extra\nx\n")
    monkeypatch.setenv("PRISMPATH_RESUME_ON_FLOW_CHANGE", "warn")
    res = checkpoint.resume(ckpt, CrashAt(None))
    assert res.stopped == "terminal"
    assert "WARNING" in capsys.readouterr().out


def test_resume_unchanged_flow_passes_the_guard(tmp_path):
    flow, ckpt = _crash_at_b(tmp_path)
    res = checkpoint.resume(ckpt, CrashAt(None))          # untouched flow -> hash matches
    assert res.path == ["a", "b", "c", "done"]


def test_legacy_checkpoint_without_flow_hash_resumes(tmp_path):
    flow, ckpt = _crash_at_b(tmp_path)
    cp = json.load(open(ckpt))
    cp.pop("flow_hash", None)                             # a pre-flow-hash checkpoint
    json.dump(cp, open(ckpt, "w"))
    with open(flow, "a") as f:
        f.write("\n## extra\nx\n")
    res = checkpoint.resume(ckpt, CrashAt(None))          # no stored hash -> not blocked
    assert res.stopped == "terminal"


def test_crash_and_resume_is_deterministic(tmp_path):
    flow = _write(tmp_path, "linear.md", LINEAR)
    ckpt = str(tmp_path / "ck.json")
    # crash while running node b
    with pytest.raises(RuntimeError):
        checkpoint.run_durable(flow, CrashAt("b"), ckpt)
    cp = checkpoint.load_checkpoint(ckpt)
    assert cp["pending_node"] == "b" and cp["stopped"] == ""     # checkpointed before b completed
    # resume with a healthy agent -> identical continuation to a clean run
    res = checkpoint.resume(ckpt, CrashAt(None))
    assert res.path == ["a", "b", "c", "done"]
    assert res.stopped == "terminal"


def test_md_is_never_written(tmp_path):
    flow = _write(tmp_path, "linear.md", LINEAR)
    before = open(flow, "rb").read()
    ckpt = str(tmp_path / "ck.json")
    with pytest.raises(RuntimeError):
        checkpoint.run_durable(flow, CrashAt("b"), ckpt)
    checkpoint.resume(ckpt, CrashAt(None))
    assert open(flow, "rb").read() == before                    # byte-identical: the .md is read-only


def test_needs_human_suspends_with_evidence(tmp_path):
    flow = _write(tmp_path, "gate.md", GATE)
    ckpt = str(tmp_path / "ck.json")

    def agent(node, instruction, state):
        if node == "gate":
            return {"text": "unsure, escalating", "needs_human": True, "reason": "policy requires sign-off"}
        return {"text": node, "always": True}

    res = checkpoint.run_durable(flow, agent, ckpt)
    assert res.stopped == "needs_human"
    assert res.pending["node"] == "gate"
    assert {c["target"] for c in res.pending["candidates"]} == {"approve", "deny"}
    cp = checkpoint.load_checkpoint(ckpt)
    assert cp["stopped"] == "needs_human" and cp["pending_decision"]["reason"] == "policy requires sign-off"


def test_resume_with_choose_applies_human_edge(tmp_path):
    flow = _write(tmp_path, "gate.md", GATE)
    ckpt = str(tmp_path / "ck.json")

    def suspend(node, instruction, state):
        if node == "gate":
            return {"text": "escalate", "needs_human": True}
        return {"text": node, "always": True}

    checkpoint.run_durable(flow, suspend, ckpt)
    res = checkpoint.resume(ckpt, lambda n, i, s: {"text": n, "always": True}, choose="approve")
    assert res.path == ["gate", "approve", "done"]
    assert res.stopped == "terminal"
    # the human decision is recorded in the transcript with attribution
    human = [t for t in res.state["transcript"] if t.get("decided_by") == "human"]
    assert human and human[0]["node"] == "gate"


def test_resume_choose_rejects_invalid_edge(tmp_path):
    flow = _write(tmp_path, "gate.md", GATE)
    ckpt = str(tmp_path / "ck.json")
    checkpoint.run_durable(flow, lambda n, i, s: {"text": n, "needs_human": n == "gate", "always": True}, ckpt)
    with pytest.raises(checkpoint.CheckpointError):
        checkpoint.resume(ckpt, lambda n, i, s: {"text": n, "always": True}, choose="nonexistent")


def test_needs_human_resume_requires_choose(tmp_path):
    flow = _write(tmp_path, "gate.md", GATE)
    ckpt = str(tmp_path / "ck.json")
    checkpoint.run_durable(flow, lambda n, i, s: {"text": n, "needs_human": n == "gate", "always": True}, ckpt)
    with pytest.raises(checkpoint.CheckpointError):
        checkpoint.resume(ckpt, lambda n, i, s: {"text": n, "always": True})   # no choose


class StubRouter:
    def __init__(self, target, score, sims):
        self.target, self.score, self.sims = target, score, sims

    def route(self, outcome, edges, instruction=""):
        return RouteDecision(self.target, {"used": "embed", "score": self.score, "sims": self.sims})


def test_router_floor_suspends_instead_of_guessing(tmp_path):
    flow = _write(tmp_path, "semantic.md", SEMANTIC)
    graph = parse_file(flow)
    router = StubRouter("stage", score=0.30, sims={"stage": 0.30, "ignore": 0.28})
    res = run(graph, lambda n, i, s: {"text": "ambiguous alert"}, router=router, human_floor=0.5)
    assert res.stopped == "needs_human"
    assert res.pending["node"] == "triage" and res.pending["would_pick"] == "stage"
    scores = {c["target"]: c["score"] for c in res.pending["candidates"]}
    assert scores == {"stage": 0.30, "ignore": 0.28}       # candidate edges + scores captured
    # above the floor, it routes normally (no suspension)
    router2 = StubRouter("stage", score=0.80, sims={"stage": 0.80, "ignore": 0.20})
    res2 = run(graph, lambda n, i, s: {"text": "clearly malicious"}, router=router2, human_floor=0.5)
    assert res2.stopped == "terminal" and res2.path == ["triage", "stage", "done"]


def test_checkpoint_is_valid_json_each_step(tmp_path):
    flow = _write(tmp_path, "linear.md", LINEAR)
    ckpt = str(tmp_path / "ck.json")
    checkpoint.run_durable(flow, lambda n, i, s: {"text": n, "always": True}, ckpt)
    doc = json.load(open(ckpt))
    assert doc["version"] == checkpoint.CHECKPOINT_VERSION
    assert doc["stopped"] == "terminal"
    assert doc["flow_path"].endswith("linear.md")


def test_non_serializable_state_disables_checkpoint_but_run_completes(tmp_path, capsys):
    flow = _write(tmp_path, "linear.md", LINEAR)
    ckpt = str(tmp_path / "ck.json")

    def agent(node, instruction, state):
        state["junk"] = {1, 2, 3}          # a set is not JSON-serializable
        return {"text": node, "always": True}

    res = checkpoint.run_durable(flow, agent, ckpt)
    assert res.stopped == "terminal"        # the run still finishes — checkpointing is off the critical path
    assert "checkpoint" in capsys.readouterr().out.lower()


def test_resume_finished_run_errors(tmp_path):
    flow = _write(tmp_path, "linear.md", LINEAR)
    ckpt = str(tmp_path / "ck.json")
    checkpoint.run_durable(flow, lambda n, i, s: {"text": n, "always": True}, ckpt)
    with pytest.raises(checkpoint.CheckpointError):
        checkpoint.resume(ckpt, lambda n, i, s: {"text": n, "always": True})   # already terminal
