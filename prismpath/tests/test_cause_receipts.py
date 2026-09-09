# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Engine cause adoption referee: every stop path carries its registry code on the RunResult,
clean outcomes carry 0, and the showcase distinction holds — the two paths that both surface
as stopped=='needs_human' carry DIFFERENT causes (worker-requested vs below the calibrated
floor), which is the whole reason the cause layer exists."""
from prismpath.kernel import causes
from prismpath.kernel.engine import run
from prismpath.kernel.parser import parse
from prismpath.routing.router import RouteDecision


class ScoredRouter:
    """Stub semantic router returning a fixed confidence score."""
    def __init__(self, score):
        self.score = score

    def route(self, outcome, edges, instruction=''):
        return RouteDecision(edges[0][0], {"used": "semantic", "score": self.score,
                                           "sims": {t: self.score for t, _ in edges}})


def test_terminal_is_clean():
    g = parse("""
## start
-> done: when go
## done
finished
""")
    res = run(g, lambda n, i, s: {"text": "x", "go": True})
    assert res.stopped == "terminal" and res.cause == causes.CAUSE_NONE


def test_stuck_carries_cause():
    g = parse("""
## start
-> done: when go
## done
finished
""")
    res = run(g, lambda n, i, s: {"text": "x", "go": False})
    assert res.stopped == "stuck"
    assert res.cause == causes.NAMES["route:stuck"]
    assert causes.cause_class(res.cause) == "routing"


def test_max_steps_carries_cause():
    g = parse("""
## a
-> b: when True
## b
-> a: when True
""")
    res = run(g, lambda n, i, s: {"text": "x"}, max_steps=5)
    assert res.stopped == "max_steps"
    assert res.cause == causes.NAMES["route:max-steps"]


def test_worker_requested_human_vs_below_floor_differ():
    # worker-requested: the worker returns needs_human
    g1 = parse("""
## start
-> done: when go
## done
finished
""")
    r1 = run(g1, lambda n, i, s: {"text": "x", "needs_human": True})
    assert r1.stopped == "needs_human"
    assert r1.cause == causes.NAMES["route:needs-human"]

    # below-floor: a semantic route whose confidence is under human_floor
    g2 = parse("""
## start
-> done: something only a model could weigh
## done
finished
""")
    r2 = run(g2, lambda n, i, s: {"text": "ambiguous"},
             router=ScoredRouter(0.10), human_floor=0.55)
    assert r2.stopped == "needs_human"
    assert r2.cause == causes.NAMES["route:below-human-floor"]

    # identical surface state, different structural cause — the registry's reason to exist
    assert r1.stopped == r2.stopped and r1.cause != r2.cause
