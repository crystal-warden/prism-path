"""@state_bound — the sliding-window bound on persisted state (the papers' open critique (2)).

Pins the load-bearing guarantees: the transcript windows to the declared N with deterministic drop
accounting; the RE-SEEDED history (path/steps) is bounded across resumes, so the checkpoint payload
of a long-lived run stays flat; routing is bit-identical with and without the bound (predicates read
fields + visits/error counters, never the windowed lists); a malformed bound fails loudly; and the
default remains unbounded (backward compatible).
"""
import json

import pytest

from prismpath.engine import run
from prismpath.parser import parse
from prismpath.checkpoint import run_durable, resume, load_checkpoint

LOOP = """---
name: loop
start: work
---

## work
Do one iteration.
{anno}
-> work: when n < 8
-> done: when n >= 8

## done
Finished.
"""

WAITER = """---
name: waiter
start: work
---

## work
Wait for the outside world, repeatedly.
@state_bound(transcript=4)
-> work: on event again
-> done: on event finish

## done
Finished.
"""


def loop_agent(node, instruction, state):
    return {"text": f"iteration {state['visits'][node]}", "n": state["visits"][node]}


def _parse_loop(anno=""):
    return parse(LOOP.format(anno=anno))


def test_default_is_unbounded():
    res = run(_parse_loop(), loop_agent)
    assert res.stopped == "terminal"
    assert len(res.state["transcript"]) == 8            # every hop retained
    assert "_state_dropped" not in res.state


def test_annotation_windows_transcript_and_counts_drops():
    res = run(_parse_loop("@state_bound(transcript=3)"), loop_agent)
    assert res.stopped == "terminal"
    assert len(res.state["transcript"]) == 3
    assert res.state["_state_dropped"]["transcript"] == 5          # 8 appended - 3 kept
    # the window keeps the TAIL: the last entry is the final work iteration
    assert res.state["transcript"][-1]["outcome"] == "iteration 8"


def test_routing_identical_with_and_without_bound():
    free = run(_parse_loop(), loop_agent)
    bounded = run(_parse_loop("@state_bound(transcript=1)"), loop_agent)
    assert bounded.path == free.path                    # the window never changes a decision
    assert bounded.state["visits"] == free.state["visits"]


def test_kwarg_overrides_annotation():
    res = run(_parse_loop("@state_bound(transcript=3)"), loop_agent, max_transcript=5)
    assert len(res.state["transcript"]) == 5
    assert res.state["_state_dropped"]["transcript"] == 3


def test_malformed_bound_raises():
    with pytest.raises(ValueError, match="positive integer"):
        run(_parse_loop("@state_bound(transcript=lots)"), loop_agent)
    with pytest.raises(ValueError, match=">= 1"):
        run(_parse_loop("@state_bound(transcript=0)"), loop_agent)


def test_checkpoint_payload_stays_flat_across_resumes(tmp_path):
    flow = tmp_path / "waiter.md"
    flow.write_text(WAITER)

    def agent(node, instruction, state):
        return {"text": f"waiting (visit {state['visits'][node]})", "wait": True}

    cp = str(tmp_path / "run.json")
    res = run_durable(str(flow), agent, checkpoint_path=cp)
    assert res.stopped == "waiting"

    sizes = []
    for _ in range(12):                                  # a long-lived run: many resume cycles
        res = resume(cp, agent, event="again", write_back=True)
        assert res.stopped == "waiting"
        doc = load_checkpoint(cp)
        sizes.append((len(doc["path"]), len(doc["steps"]), len(doc["state"]["transcript"])))

    # bounded: the persisted payload is FLAT, not linear in resume count
    path_lens = {p for p, _, _ in sizes[4:]}
    assert len(path_lens) == 1, f"path kept growing: {sizes}"
    assert all(t <= 4 for _, _, t in sizes)              # transcript window honored in the payload
    assert all(s <= 4 + 2 for _, s, _ in sizes)          # seed windowed + this segment's steps
    dropped = load_checkpoint(cp)["state"]["_state_dropped"]
    assert dropped["transcript"] > 0 and dropped["path"] > 0 and dropped["steps"] > 0

    res = resume(cp, agent, event="finish", write_back=True)
    assert res.stopped == "terminal"                     # the windowed run still finishes correctly
    assert res.path[-1] == "done"


def test_unbounded_checkpoint_grows_linearly_for_contrast(tmp_path):
    """The control arm: without @state_bound the payload DOES grow per resume — the behavior the
    bound exists to fix (and proof the bounded test above isn't vacuously passing)."""
    flow = tmp_path / "waiter.md"
    flow.write_text(WAITER.replace("@state_bound(transcript=4)\n", ""))

    def agent(node, instruction, state):
        return {"text": "waiting", "wait": True}

    cp = str(tmp_path / "run.json")
    run_durable(str(flow), agent, checkpoint_path=cp)
    lens = []
    for _ in range(6):
        resume(cp, agent, event="again", write_back=True)
        lens.append(len(load_checkpoint(cp)["path"]))
    assert lens == sorted(lens) and lens[-1] > lens[0]   # strictly growing
