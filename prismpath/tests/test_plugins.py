"""The plugin ecosystem — discovery/audit, @worker binding, dispatch provenance, council plugin.

Pins the contract: bundled plugins are discovered with their manifests; `@worker(plugin.name)`
bindings resolve strictly and fail fast (at agent construction / in `prismpath plugins --check`, never
at hop 40); dispatched outcomes carry `_worker` provenance; the council plugin's workers are
deterministic (seeded roll, weighted tally); and the old seams (`load_gate`, `import dice`) still
work unchanged.
"""
import json

import pytest

from prismpath.parser import parse
from prismpath.engine import run
from prismpath.plugins import load_gate, registry

FLOW = """---
name: steered
start: steer
---

## steer
Roll the mandate.
@worker(council.roll)
-> tally: always

## tally
Weigh the votes.
@worker(council.tally)
-> done: when winner
-> steer: when not winner

## done
Finished.
"""


# --- discovery + audit -------------------------------------------------------------------

def test_discover_finds_bundled_plugins_with_manifests():
    infos = registry.discover()
    assert "council" in infos and "roblox" in infos
    council = infos["council"]
    assert council.source == "bundled"
    assert sorted(council.workers) == ["roll", "tally"]
    assert not council.is_gate
    assert infos["roblox"].is_gate                       # the original seam, visible in the audit

def test_audit_renders_both_formats():
    text = registry.audit()
    assert "council" in text and "workers: roll, tally" in text
    data = json.loads(registry.audit(as_json=True))
    assert data["council"]["workers"] == ["roll", "tally"]


# --- binding + resolution ----------------------------------------------------------------

def test_resolve_worker_strict():
    assert callable(registry.resolve_worker("council.roll"))
    with pytest.raises(KeyError, match="must be 'plugin.worker'"):
        registry.resolve_worker("roll")                  # bare names don't resolve — by design
    with pytest.raises(KeyError, match="not installed"):
        registry.resolve_worker("nope.roll")
    with pytest.raises(KeyError, match="no worker"):
        registry.resolve_worker("council.nope")

def test_check_flow_clean_and_broken():
    assert registry.check_flow(parse(FLOW)) == []
    broken = parse(FLOW.replace("council.tally", "council.absent"))
    problems = registry.check_flow(broken)
    assert len(problems) == 1 and "absent" in problems[0]

def test_worker_agent_fails_fast_on_unresolvable():
    with pytest.raises(KeyError, match="no worker"):
        registry.worker_agent(parse(FLOW.replace("council.roll", "council.gone")))


# --- dispatch + provenance ---------------------------------------------------------------

def test_worker_agent_dispatches_with_provenance_and_fallback():
    graph = parse(FLOW)
    seen = []

    def default(node, instruction, state):              # would only serve UNBOUND nodes
        seen.append(node)
        return {"text": "default"}

    agent = registry.worker_agent(graph, default=default)
    state = {"transcript": [], "visits": {}, "round_key": 7,
             "files": {"a.luau": "local x = 1"}, "votes": {"v1": "combat", "v2": "combat"}}
    res = run(graph, agent, state=state)
    assert res.stopped == "terminal"
    assert seen == []                                    # every node was bound; fallback untouched
    outs = res.state["_outcomes"]
    assert outs["steer"]["_worker"] == "council.roll"    # provenance in the audit trail
    assert outs["tally"]["_worker"] == "council.tally"
    assert outs["tally"]["winner"] == "combat"

def test_worker_agent_requires_default_for_unbound_nodes():
    graph = parse(FLOW.replace("@worker(council.roll)\n", ""))   # steer is now unbound
    agent = registry.worker_agent(graph)                          # no default
    with pytest.raises(KeyError, match="no default agent"):
        agent("steer", "x", {})


# --- the council plugin itself -----------------------------------------------------------

def test_council_roll_is_seeded_deterministic():
    from prismpath.plugins import council
    state = {"round_key": 3, "files": {"a.luau": "combat spawn wave"}}
    a = council.WORKERS["roll"]("steer", "", dict(state))
    b = council.WORKERS["roll"]("steer", "", dict(state))
    assert a == b                                        # same round + files -> same mandate, always
    c = council.WORKERS["roll"]("steer", "", {**state, "round_key": 4})
    assert c != a                                        # a new round is a new roll

def test_council_tally_weighted_and_tiebreak_deterministic():
    from prismpath.plugins import council
    out = council.WORKERS["tally"]("tally", "", {"votes": {"a": "combat", "b": "economy"}})
    assert out["winner"] in ("combat", "economy")
    again = council.WORKERS["tally"]("tally", "", {"votes": {"a": "combat", "b": "economy"}})
    assert out["winner"] == again["winner"]              # ties break deterministically
    assert set(out["weights"]) == {"combat", "economy"}


# --- the old seams stay unchanged --------------------------------------------------------

def test_load_gate_backcompat_alias():
    assert load_gate("luau").NAME == "roblox"

def test_dice_shim_still_imports():
    import prismpath.dice as dice_shim
    from prismpath.plugins.council import dice as real
    assert dice_shim.roll is real.roll and dice_shim.CATEGORIES == real.CATEGORIES
