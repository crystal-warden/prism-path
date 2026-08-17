# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Reference-scheduler tests (critic #7) — `on timeout` edges only fire because something delivers
`__timeout__`; this is that something."""
import os

from prismpath import checkpoint, scheduler

FLOW = """---
name: order
start: place
---
## place
Place the order, then wait.
-> await_payment: when always
## await_payment
Wait for payment confirmation (or a timeout).
-> fulfilled: on event payment_confirmed
-> cancelled: on timeout
## fulfilled
-> done: when always
## cancelled
-> done: when always
## done
"""


def _agent(node, instr, state):
    if node == "await_payment":
        return {"text": "waiting", "wait": True, "timeout_s": 3600}
    return {"text": node, "always": True}


def _suspend(tmp_path):
    qdir = tmp_path / "queue"
    qdir.mkdir()
    flow = tmp_path / "order.md"
    flow.write_text(FLOW)
    ckpt = str(qdir / "run1.json")
    res = checkpoint.run_durable(str(flow), _agent, ckpt)
    assert res.stopped == "waiting"
    return str(qdir), ckpt


def test_not_due_before_timeout_elapses(tmp_path):
    qdir, ckpt = _suspend(tmp_path)
    cp = checkpoint.load_checkpoint(ckpt)
    assert scheduler.seconds_until_due(cp, now=cp["saved_at"] + 10) > 0   # 10s << 3600s
    fired = scheduler.fire_due_timeouts(_agent, qdir=qdir, now=cp["saved_at"] + 10)
    assert fired == []                                    # nothing fired; still waiting
    assert checkpoint.load_checkpoint(ckpt)["stopped"] == "waiting"


def test_fires_timeout_after_elapsed_and_takes_the_edge(tmp_path):
    qdir, ckpt = _suspend(tmp_path)
    cp = checkpoint.load_checkpoint(ckpt)
    assert scheduler.is_due(cp, now=cp["saved_at"] + 3601)
    fired = scheduler.fire_due_timeouts(_agent, qdir=qdir, now=cp["saved_at"] + 3601)
    assert len(fired) == 1
    res = fired[0]["result"]
    assert res.path[-2:] == ["cancelled", "done"]         # took the `on timeout` edge
    assert res.stopped == "terminal"


def test_ignores_non_checkpoint_files(tmp_path):
    qdir, ckpt = _suspend(tmp_path)
    with open(os.path.join(qdir, "note.txt"), "w") as f:
        f.write("not a checkpoint")
    # far-future now so the real run is due; the junk file is skipped, not raised on
    cp = checkpoint.load_checkpoint(ckpt)
    fired = scheduler.fire_due_timeouts(_agent, qdir=qdir, now=cp["saved_at"] + 10_000)
    assert len(fired) == 1
