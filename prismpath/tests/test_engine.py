"""Engine tests — end-to-end run() with MOCK agents and a stub router (no real model).

ORIGIN: the swarm (Qwen2.5-Coder-7B, driven by flows/build_prismpath.md) authored the first
version of this module; it covered the right cases but mis-modeled the real API in a few
systematic ways (treated `result.steps` as an int instead of a list; used capitalized node
names that the parser lowercases; asserted on visits keys for never-entered nodes). This file
is the post-loop CORRECTION: same intent and case coverage, fixed to the real engine contract.
"""
from prismpath.engine import run, RunResult
from prismpath.parser import parse
from prismpath.router import RouteDecision


class FirstEdgeRouter:
    """A stub semantic router: always pick the first semantic edge. Keeps engine tests off
    the real embedding/LLM routers."""
    def route(self, outcome, edges, instruction=''):
        return RouteDecision(edges[0][0], {"used": "semantic"})


def test_deterministic_before_semantic():
    # the node has BOTH a matching `when` edge and a semantic edge; deterministic must win.
    text = """
## start
-> a: when go
-> b: a natural language condition that the stub router would otherwise pick
## a
done
## b
done
"""
    g = parse(text)
    agent = lambda n, i, s: {"text": "anything", "go": True}
    res = run(g, agent, router=FirstEdgeRouter())
    assert res.path == ["start", "a"]            # took the deterministic edge, not 'b'
    assert res.steps[0].info["used"] == "deterministic"
    assert res.stopped == "terminal"


def test_semantic_when_no_deterministic_matches():
    # no `when` edge matches -> the semantic edge is routed by the (stub) router.
    text = """
## start
-> a: when go
-> b: some semantic condition
## a
end
## b
end
"""
    g = parse(text)
    agent = lambda n, i, s: {"text": "x", "go": False}   # deterministic edge is False
    res = run(g, agent, router=FirstEdgeRouter())
    assert res.path == ["start", "b"]
    assert res.steps[0].info["used"] == "semantic"


def test_terminal_node():
    text = """
## start
-> end: always
## end
finish
"""
    g = parse(text)
    agent = lambda n, i, s: {"text": "ok"}
    res = run(g, agent, router=FirstEdgeRouter())
    assert res.stopped == "terminal"
    assert res.path == ["start", "end"]
    assert isinstance(res.steps, list) and len(res.steps) == 1
    assert res.state["visits"]["start"] == 1


def test_cycle_bounded_by_visits():
    # a self-loop that exits via the visits cap rather than looping forever.
    text = """
## loop
-> done: when visits > 2
-> loop: always
## done
finished
"""
    g = parse(text)
    agent = lambda n, i, s: {"text": "spin"}
    res = run(g, agent, router=FirstEdgeRouter(), max_steps=50)
    assert res.stopped == "terminal"
    assert res.path[-1] == "done"
    assert res.state["visits"]["loop"] == 3       # entered until visits>2 fired


def test_max_steps_enforced():
    # an unbounded self-loop hits the max_steps hard stop.
    text = """
## loop
-> loop: always
"""
    g = parse(text)
    agent = lambda n, i, s: {"text": "spin"}
    res = run(g, agent, router=FirstEdgeRouter(), max_steps=3)
    assert res.stopped == "max_steps"
    assert res.state["visits"]["loop"] == 3


def test_stuck_on_deterministic_only_no_match():
    # a deterministic-only node where nothing matches and there are no semantic edges.
    text = """
## start
-> end: when never_true
## end
finish
"""
    g = parse(text)
    agent = lambda n, i, s: {"text": "x"}          # 'never_true' is unknown -> None -> falsy
    res = run(g, agent, router=FirstEdgeRouter())
    assert res.stopped == "stuck"
    assert res.path == ["start"]


def test_agent_returns_dict_drives_predicate():
    # a dict outcome's fields feed `when` predicates.
    text = """
## start
-> done: when ok
-> retry: something semantic
## retry
r
## done
d
"""
    g = parse(text)
    agent = lambda n, i, s: {"text": "all good", "ok": True}
    res = run(g, agent, router=FirstEdgeRouter())
    assert res.path == ["start", "done"]
    assert res.steps[0].info["used"] == "deterministic"


def test_agent_returns_string_drives_semantic():
    # a plain string outcome has no fields, so a `when` predicate is falsy and the semantic
    # edge is taken via the router.
    text = """
## start
-> done: when ok
-> other: a semantic condition
## other
o
## done
d
"""
    g = parse(text)
    agent = lambda n, i, s: "just a string outcome"
    res = run(g, agent, router=FirstEdgeRouter())
    assert res.path == ["start", "other"]
    assert res.steps[0].info["used"] == "semantic"


def test_run_result_shape():
    text = """
## start
-> end: always
## end
e
"""
    g = parse(text)
    res = run(g, lambda n, i, s: {"text": "x"}, router=FirstEdgeRouter())
    assert isinstance(res, RunResult)
    assert isinstance(res.path, list)
    assert isinstance(res.steps, list)
    assert isinstance(res.state, dict)
