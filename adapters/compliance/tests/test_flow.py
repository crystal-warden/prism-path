"""The generic family-agnostic assessment flow: it compiles, routes by method profile, is
escalation-default at every adjudicator, and the attestation binds the actual flow content."""
import compliance_adapter as ca
from prismpath import parser

ADJUDICATORS = ["adjudicate_technical", "adjudicate_procedural", "adjudicate_operational", "general_control"]


def _graph():
    return parser.parse_file(ca.GENERIC_FLOW)


def test_generic_flow_compiles_all_edges_resolve():
    g = _graph()
    assert {"observe", "route", "report", "end"} <= set(g.nodes)
    for name, n in g.nodes.items():
        for target, _cond in n.edges:
            assert target in g.nodes, (name, "->", target)


def test_route_covers_the_four_method_profiles():
    g = _graph()
    targets = {t for t, _ in g.nodes["route"].edges}
    assert set(ADJUDICATORS) <= targets


def test_every_adjudicator_is_escalation_default_to_poam():
    g = _graph()
    for adj in ADJUDICATORS:
        tgts = [t for t, _ in g.nodes[adj].edges]
        assert "record_met" in tgts and "record_poam" in tgts
        assert tgts[-1] == "record_poam"                       # the `when always` fallback sinks to POA&M


def test_discovery_loop_is_bounded():
    """The in-graph discovery loop (folded from agy's map) requests evidence, loops back, and is bounded."""
    g = _graph()
    ce = [t for t, _ in g.nodes["check_evidence"].edges]
    re = g.nodes["request_evidence"].edges
    assert "request_evidence" in ce and "route" in ce
    # loops back to check_evidence, and has a visits-bound deterministic exit to record_poam
    assert any(t == "check_evidence" for t, _ in re)
    assert any(t == "record_poam" and "visits" in c for t, c in re)


def test_report_checkpoints_then_ends():
    g = _graph()
    assert [t for t, _ in g.nodes["report"].edges] == ["end"]
    assert g.nodes["end"].terminal


def test_attest_binds_active_flow_hash():
    c = ca.get_control("3.1.5")
    m = ca.attest(c, {"control_id": "3.1.5", "boundary": "x", "evidence": []},
                  {"status": "not-met", "unmet_objective_ids": [], "gap_summary": "g"})
    assert m["policy_hash"] == ca.active_flow_hash()
    assert m["gate_id"] == "nist_800171_generic@v1"
