# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The operator's short lived change expires by construction: a run held at the overlay node returns
to the baseline posture on the operator's stand down event or on the timer, through the ordinary
suspend and resume machinery, with nothing added to the pack."""
from pathlib import Path

from prismpath import checkpoint

FLOW = Path(__file__).resolve().parent.parent / "examples" / "operator_overlay" / "overlay.md"


def _worker(fields):
    def agent(node, instruction, state):
        if node == "gate":
            return dict(fields)
        if node == "heightened":
            return {"text": "held for review", "wait": True, "timeout_s": 3600}
        return {"text": node}
    return agent


def _held(tmp_path):
    ckpt = tmp_path / "run.ckpt.json"
    res = checkpoint.run_durable(str(FLOW), _worker({"severity": 2, "source_internal": False, "incident_active": True}), str(ckpt))
    assert res.stopped == "waiting"
    assert set(res.pending["awaiting"]) == {"stand_down", "__timeout__"}
    assert res.path[-1] == "heightened"
    return ckpt


def test_stand_down_returns_to_baseline(tmp_path):
    ckpt = _held(tmp_path)
    after = _worker({"severity": 2, "source_internal": False, "incident_active": False})
    res = checkpoint.resume(str(ckpt), after, event="stand_down")
    assert res.path[:2] == ["heightened", "gate"] or "gate" in res.path
    assert res.path[-1] == "observe"


def test_timer_returns_to_baseline(tmp_path):
    ckpt = _held(tmp_path)
    after = _worker({"severity": 2, "source_internal": False, "incident_active": False})
    res = checkpoint.resume(str(ckpt), after, event="__timeout__")
    assert "gate" in res.path
    assert res.path[-1] == "observe"


def test_baseline_is_unchanged_without_an_incident(tmp_path):
    ckpt = tmp_path / "run.ckpt.json"
    res = checkpoint.run_durable(str(FLOW), _worker({"severity": 2, "source_internal": False, "incident_active": False}), str(ckpt))
    assert res.stopped == "terminal"
    assert res.path == ["gate", "observe"]
