# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Frozen-corpus conformance for the fusion_triage tessellation.

Referee pattern from adapters/telemetry: every probe must route identically three ways —
direct evaluation, quantize -> wire round-trip -> evaluation, and spiral index -> band
reconstruction. A mapping bug anywhere flips a frozen entry and this file goes RED.
"""
import hashlib
import json
import sys
from pathlib import Path

import pytest

ADAPTER = Path(__file__).resolve().parent.parent
REPO = ADAPTER.parent.parent
sys.path.insert(0, str(REPO / "adapters" / "telemetry"))

import quantizer as q  # noqa: E402
import spiral as sp    # noqa: E402
import wire as w       # noqa: E402
from prismpath.parser import parse  # noqa: E402

CORPUS = json.loads((ADAPTER / "conformance" / "spiral_fusion.json").read_text())
FLOW_PATH = ADAPTER / "flows" / "fusion_triage.md"
GRAPH = parse(FLOW_PATH.read_text())
LAYOUT = sp.SpiralLayout(GRAPH, CORPUS["node"])
PARTS = q.build_partitions(GRAPH)

SEVERITY_ORDER = [
    "all_quiet", "physical_watch", "cyber_watch", "tandem_watch",
    "cyber_containment", "physical_escalation", "coincident_critical",
]


# ------------------------------------------------------------- corpus integrity

def test_corpus_pins_the_shipped_flow():
    assert CORPUS["flow_sha256"] == hashlib.sha256(FLOW_PATH.read_bytes()).hexdigest(), \
        "flows/fusion_triage.md changed without regenerating the frozen corpus"


def test_layout_matches_frozen_corpus_exactly():
    assert LAYOUT.fields == CORPUS["fields"]
    assert LAYOUT.radices == CORPUS["radices"]
    assert LAYOUT.size == CORPUS["size"] == 108
    frozen_bands = [(b["route"], b["base"], b["width"]) for b in CORPUS["bands"]]
    live_bands = [(r, LAYOUT.band_base[i], LAYOUT.band_width[i])
                  for i, r in enumerate(LAYOUT.routes)]
    assert live_bands == frozen_bands
    for entry in CORPUS["cells"]:
        n = entry["n"]
        assert list(LAYOUT.cell_of[n]) == entry["cell"]
        assert LAYOUT.route_of(n) == entry["route"]
        assert LAYOUT.band_index[LAYOUT.route_of(n)] == entry["band"]


def test_band_order_is_severity_center_outward():
    assert [b["route"] for b in CORPUS["bands"]] == SEVERITY_ORDER


def test_every_cell_routes():
    assert all(e["route"] is not None for e in CORPUS["cells"]), \
        "the correlate node has an else edge; no cell may be unrouted"


# --------------------------------------------------- decisions preserved, three ways

@pytest.mark.parametrize("probe", CORPUS["probes"],
                         ids=lambda p: "/".join(str(p["reading"][f]) for f in
                                                ("stability", "dev_mg", "rule_level", "soc_action")))
def test_probe_decisions_preserved(probe):
    reading, frozen_route = probe["reading"], probe["route"]
    # 1. direct evaluation
    assert w.route_node(GRAPH, CORPUS["node"], reading) == frozen_route
    # 2. quantize -> wire -> decode -> evaluate
    bits = w.encode_reading(PARTS, reading)
    decoded = w.decode_reading(PARTS, bits)
    assert w.route_node(GRAPH, CORPUS["node"], decoded) == frozen_route
    # 3. spiral index -> band -> route
    assert LAYOUT.route_of(LAYOUT.index(reading)) == frozen_route
    assert LAYOUT.routes[LAYOUT.band_id(reading)] == frozen_route


# ------------------------------------------------------------------ guard rails

def test_missing_field_raises():
    with pytest.raises(KeyError):
        w.encode_reading(PARTS, {"stability": "still", "dev_mg": 0, "rule_level": 3})


def test_other_collapse_is_decision_preserving():
    # "still" and the drifted "On Table" are not flow constants; both land in the OTHER cell
    # and must quantize identically — the minimum-sufficient-statistic property, visible.
    s = PARTS["stability"]
    assert s.symbol("still") == s.symbol("On Table") == s.symbol("anything_else")
    a = PARTS["soc_action"]
    assert a.symbol("ignore") == a.symbol("none")
    assert a.symbol("contain") != a.symbol("ignore")
