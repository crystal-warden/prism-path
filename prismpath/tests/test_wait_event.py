# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Wait-for-event tests (critic #7) — suspend on `{"wait": …}`, resume by delivering a signal/timer."""
import pytest

from prismpath import checkpoint, predicates
from prismpath.engine import run
from prismpath.parser import parse

FLOW = """---
name: order
start: place
---
## place
Place the order, then wait for the payment webhook.
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


def test_event_predicate_tier():
    assert predicates.is_event("on event payment_confirmed")
    assert predicates.is_event("on timeout")
    assert not predicates.is_event("the payment cleared")
    assert not predicates.is_semantic("on event x")          # event edges aren't semantic
    assert predicates.event_name("on event payment_confirmed") == "payment_confirmed"
    assert predicates.event_name("on timeout") == "__timeout__"


def _agent(node, instr, state):
    if node == "await_payment":
        return {"text": "waiting for the payment webhook", "wait": True, "timeout_s": 3600}
    return {"text": node, "always": True}


def test_run_suspends_waiting():
    res = run(parse(FLOW), _agent)
    assert res.stopped == "waiting"
    assert res.pending["node"] == "await_payment"
    assert set(res.pending["awaiting"]) == {"payment_confirmed", "__timeout__"}


def test_resume_delivers_event(tmp_path):
    flow = tmp_path / "order.md"
    flow.write_text(FLOW)
    ckpt = str(tmp_path / "ck.json")
    res = checkpoint.run_durable(str(flow), _agent, ckpt)
    assert res.stopped == "waiting"
    cont = checkpoint.resume(ckpt, _agent, event="payment_confirmed")
    assert cont.path == ["place", "await_payment", "fulfilled", "done"]
    assert cont.stopped == "terminal"


def test_resume_timeout_path(tmp_path):
    flow = tmp_path / "order.md"
    flow.write_text(FLOW)
    ckpt = str(tmp_path / "ck.json")
    checkpoint.run_durable(str(flow), _agent, ckpt)
    cont = checkpoint.resume(ckpt, _agent, event="__timeout__")
    assert cont.path[-2:] == ["cancelled", "done"]


def test_resume_waiting_requires_event(tmp_path):
    flow = tmp_path / "order.md"
    flow.write_text(FLOW)
    ckpt = str(tmp_path / "ck.json")
    checkpoint.run_durable(str(flow), _agent, ckpt)
    with pytest.raises(checkpoint.CheckpointError):
        checkpoint.resume(ckpt, _agent)                       # no event -> error
    with pytest.raises(checkpoint.CheckpointError):
        checkpoint.resume(ckpt, _agent, event="unknown_signal")
