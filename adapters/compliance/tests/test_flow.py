# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The generic family-agnostic assessment flow: it compiles, routes by method profile, is
escalation-default at every adjudicator, and the attestation binds the actual flow content."""
from adapters.compliance import compliance_adapter as ca
from prismpath.kernel import parser

ADJUDICATORS = ["adjudicate_technical", "adjudicate_procedural", "adjudicate_operational", "general_control"]


def _graph():
    return parser.parse_file(ca.GENERIC_FLOW)


def test_generic_flow_compiles_all_edges_resolve():
    graph = _graph()
    assert {"observe", "route", "report", "end"} <= set(graph.nodes)
    for name, node in graph.nodes.items():
        for target, _cond in node.edges:
            assert target in graph.nodes, (name, "->", target)


def test_route_covers_the_four_method_profiles():
    graph = _graph()
    targets = {target for target, _ in graph.nodes["route"].edges}
    assert set(ADJUDICATORS) <= targets


def test_every_adjudicator_is_escalation_default_to_poam():
    graph = _graph()
    for adj in ADJUDICATORS:
        tgts = [target for target, _ in graph.nodes[adj].edges]
        assert "record_met" in tgts and "record_poam" in tgts
        assert tgts[-1] == "record_poam"                       # the `when always` fallback sinks to POA&M


def test_discovery_loop_is_bounded():
    """The in-graph discovery loop (folded from agy's map) requests evidence, loops back, and is bounded."""
    graph = _graph()
    ce = [target for target, _ in graph.nodes["check_evidence"].edges]
    re = graph.nodes["request_evidence"].edges
    assert "request_evidence" in ce and "route" in ce
    # loops back to check_evidence, and has a visits-bound deterministic exit to record_poam
    assert any(target == "check_evidence" for target, _ in re)
    assert any(target == "record_poam" and "visits" in condition for target, condition in re)


def test_report_checkpoints_then_ends():
    graph = _graph()
    assert [target for target, _ in graph.nodes["report"].edges] == ["end"]
    assert graph.nodes["end"].terminal


def test_attest_binds_active_flow_hash():
    control = ca.get_control("3.1.5")
    manifest = ca.attest(control, {"control_id": "3.1.5", "boundary": "x", "evidence": []},
                         {"status": "not-met", "unmet_objective_ids": [], "gap_summary": "g"})
    assert manifest["policy_hash"] == ca.active_flow_hash()
    assert manifest["gate_id"] == "nist_800171_generic@v1"
