# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The plugin ecosystem — discovery/audit, @worker binding, dispatch provenance.

Pins the contract: bundled plugins are discovered with their manifests; `@worker(plugin.name)`
bindings resolve strictly and fail fast (at agent construction / in `prismpath plugins --check`, never
at hop 40); dispatched outcomes carry `_worker` provenance; and the old seams (`load_gate`) still
work unchanged.
"""
import json
import sys
import types

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
@worker(dummy.roll)
-> tally: always

## tally
Weigh the votes.
@worker(dummy.tally)
-> done: when winner
-> steer: when not winner

## done
Finished.
"""


@pytest.fixture(autouse=True)
def mock_dummy_plugin(monkeypatch):
    dummy_mod = types.ModuleType("prismpath.plugins.dummy")
    dummy_mod.NAME = "dummy"
    dummy_mod.WORKERS = {
        "roll": lambda node, instruction, state: {"text": "rolled"},
        "tally": lambda node, instruction, state: {"text": "tallied", "winner": "combat"},
    }
    monkeypatch.setitem(sys.modules, "prismpath.plugins.dummy", dummy_mod)
    orig_discover = registry.discover

    def dummy_discover():
        res = orig_discover()
        res["dummy"] = registry.PluginInfo(
            name="dummy", module="prismpath.plugins.dummy", source="bundled",
            workers=["roll", "tally"], is_gate=False, has_cli=False
        )
        return res

    monkeypatch.setattr(registry, "discover", dummy_discover)


# --- discovery + audit -------------------------------------------------------------------

def test_discover_finds_bundled_plugins_with_manifests():
    infos = registry.discover()
    assert "pysprint" in infos
    pysprint = infos["pysprint"]
    assert pysprint.source == "bundled"
    assert pysprint.is_gate


def test_audit_renders_both_formats():
    text = registry.audit()
    assert "pysprint" in text and "gate" in text
    data = json.loads(registry.audit(as_json=True))
    assert data["pysprint"]["gate"] is True


# --- binding + resolution ----------------------------------------------------------------

def test_resolve_worker_strict():
    assert callable(registry.resolve_worker("dummy.roll"))
    with pytest.raises(KeyError, match="must be 'plugin.worker'"):
        registry.resolve_worker("roll")                  # bare names don't resolve — by design
    with pytest.raises(KeyError, match="not installed"):
        registry.resolve_worker("nope.roll")
    with pytest.raises(KeyError, match="no worker"):
        registry.resolve_worker("dummy.nope")


def test_check_flow_clean_and_broken():
    assert registry.check_flow(parse(FLOW)) == []
    broken = parse(FLOW.replace("dummy.tally", "dummy.absent"))
    problems = registry.check_flow(broken)
    assert len(problems) == 1 and "absent" in problems[0]


def test_worker_agent_fails_fast_on_unresolvable():
    with pytest.raises(KeyError, match="no worker"):
        registry.worker_agent(parse(FLOW.replace("dummy.roll", "dummy.gone")))


# --- dispatch + provenance ---------------------------------------------------------------

def test_worker_agent_dispatches_with_provenance_and_fallback():
    graph = parse(FLOW)
    seen = []

    def default(node, instruction, state):              # would only serve UNBOUND nodes
        seen.append(node)
        return {"text": "default"}

    agent = registry.worker_agent(graph, default=default)
    state = {"transcript": [], "visits": {}, "round_key": 7,
             "files": {"a.js": "let x = 1"}, "votes": {"v1": "combat", "v2": "combat"}}
    res = run(graph, agent, state=state)
    assert res.stopped == "terminal"
    assert seen == []                                    # every node was bound; fallback untouched
    outs = res.state["_outcomes"]
    assert outs["steer"]["_worker"] == "dummy.roll"      # provenance in the audit trail
    assert outs["tally"]["_worker"] == "dummy.tally"
    assert outs["tally"]["winner"] == "combat"


def test_worker_agent_requires_default_for_unbound_nodes():
    graph = parse(FLOW.replace("@worker(dummy.roll)\n", ""))   # steer is now unbound
    agent = registry.worker_agent(graph)                        # no default
    with pytest.raises(KeyError, match="no default agent"):
        agent("steer", "x", {})


# --- the old seams stay unchanged --------------------------------------------------------

def test_load_gate_unknown_raises_cleanly():
    with pytest.raises(ModuleNotFoundError):
        load_gate("nonexistent_gate")
