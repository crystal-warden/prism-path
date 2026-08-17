# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The fusion_triage flow: Level M proof + frozen structure + routing matrix.

The structure inventory is frozen on purpose: the spiral band order derives from the first
appearance of each target in `correlate`'s edge list, so reordering edges silently reorders
the tessellation. A change here is a spec review, not a refactor.
"""
from pathlib import Path

import pytest

from prismpath import predicates
from prismpath.model_check import flow_level_m
from prismpath.parser import parse

ADAPTER = Path(__file__).resolve().parent.parent
FLOW_PATH = ADAPTER / "flows" / "fusion_triage.md"
FLOW_TEXT = FLOW_PATH.read_text()
GRAPH = parse(FLOW_TEXT)

VERDICTS = [
    "coincident_critical", "physical_escalation", "cyber_containment",
    "tandem_watch", "cyber_watch", "physical_watch", "all_quiet",
]


def _route(graph, node, reading):
    """First matching deterministic edge — mirrors wire.route_node without the adapter import
    (the wire-level cross-check lives in test_fusion_spiral.py)."""
    for target, cond in graph.nodes[node].edges:
        if predicates.is_deterministic(cond) and predicates.eval_condition(cond, reading):
            return target
    return None


def _r(stability, dev_mg, rule_level, soc_action):
    return {"stability": stability, "dev_mg": dev_mg,
            "rule_level": rule_level, "soc_action": soc_action}


# ---------------------------------------------------------------- the proof

def test_flow_is_level_m():
    ok, bad = flow_level_m(GRAPH)
    assert ok, f"fusion_triage left the Level M fragment: {bad}"
    assert bad == []


def test_flow_validates_clean():
    assert GRAPH.validate() == []


def test_pure_level_m_flow_needs_no_lockfile():
    assert not (ADAPTER / "flows" / "fusion_triage.lock").exists(), \
        "a pure Level M flow must not grow a lockfile"


# ---------------------------------------------------- frozen structure inventory

def test_node_inventory_frozen():
    expected = {
        "intake", "physical_check", "tamper_path", "handling_path", "quiescent_path",
        "correlate", *VERDICTS, "record", "end",
    }
    assert set(GRAPH.nodes) == expected
    assert GRAPH.start == "intake"


def test_correlate_target_first_appearance_order_frozen():
    # Spiral band order = reversed first-appearance order: all_quiet center,
    # coincident_critical outermost. Reordering edges reorders the bloom.
    seen = []
    for target, _cond in GRAPH.nodes["correlate"].edges:
        if target not in seen:
            seen.append(target)
    assert seen == VERDICTS


def test_every_verdict_reaches_record():
    for v in VERDICTS:
        assert GRAPH.nodes[v].edges == [("record", "when always")]


# ---------------------------------------------------------------- routing matrix

@pytest.mark.parametrize("reading,expected", [
    # coincident_critical, one per edge
    (_r("shaken", 3000, 13, "contain"), "coincident_critical"),
    (_r("shaken", 0, 3, "contain"), "coincident_critical"),
    (_r("still", 3000, 3, "contain"), "coincident_critical"),
    (_r("still", 200, 12, "watch"), "coincident_critical"),   # deadband coincidence
    # precedence: containment-grade cyber with a physically quiet device is NOT coincident
    (_r("still", 0, 12, "contain"), "cyber_containment"),
    (_r("still", 149, 12, "contain"), "cyber_containment"),   # just under the deadband
    # physical without cyber
    (_r("shaken", 2600, 5, "ignore"), "physical_escalation"),
    (_r("still", 2500, 3, "ignore"), "physical_escalation"),
    # tandem
    (_r("moving", 600, 8, "watch"), "tandem_watch"),
    (_r("still", 600, 3, "watch"), "tandem_watch"),
    # single-axis watches
    (_r("still", 0, 8, "ignore"), "cyber_watch"),
    (_r("still", 0, 7, "watch"), "cyber_watch"),
    (_r("moving", 100, 3, "ignore"), "physical_watch"),
    (_r("still", 500, 3, "ignore"), "physical_watch"),
    # quiet (400 sits above the deadband but below every solo-escalation line)
    (_r("still", 400, 3, "ignore"), "all_quiet"),
    (_r("still", 0, 0, "ignore"), "all_quiet"),
])
def test_correlate_routing(reading, expected):
    assert _route(GRAPH, "correlate", reading) == expected


@pytest.mark.parametrize("reading,expected", [
    (_r("shaken", 0, 0, "ignore"), "tamper_path"),
    (_r("still", 2500, 0, "ignore"), "tamper_path"),
    (_r("moving", 0, 0, "ignore"), "handling_path"),
    (_r("still", 500, 0, "ignore"), "handling_path"),
    (_r("still", 499, 0, "ignore"), "quiescent_path"),
])
def test_physical_check_routing(reading, expected):
    assert _route(GRAPH, "physical_check", reading) == expected


def test_boundary_exactness():
    # Each cut routes differently at value and value-1 (the quantizer's bins depend on this).
    assert _route(GRAPH, "correlate", _r("still", 150, 12, "ignore")) == "coincident_critical"
    assert _route(GRAPH, "correlate", _r("still", 149, 12, "ignore")) == "cyber_containment"
    assert _route(GRAPH, "correlate", _r("still", 0, 7, "ignore")) == "cyber_watch"
    assert _route(GRAPH, "correlate", _r("still", 0, 6, "ignore")) == "all_quiet"
