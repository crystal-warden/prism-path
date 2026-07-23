"""SOC decomposed-triage map: compiles, routes by MITRE tactic, escalation-default (watch, never benign
by default), prefilter cheap-gate present; plus the adapter module exposes its port surface. Offline —
live-SIEM adjudication is opt-in."""
import os
from prismpath import parser

HERE = os.path.dirname(os.path.abspath(__file__))
FLOWS = os.path.join(os.path.dirname(HERE), "flows")
ATTACK_TACTICS = ["adjudicate_credential_access", "adjudicate_lateral_movement", "adjudicate_execution",
                  "adjudicate_persistence", "adjudicate_privilege_escalation", "adjudicate_defense_evasion",
                  "adjudicate_discovery", "adjudicate_c2_exfil"]
TACTICS = ATTACK_TACTICS + ["general_adjudicate"]   # general = the explicit no-technique catch-all


def _g():
    return parser.parse_file(os.path.join(FLOWS, "wazuh_triage_decomposed.md"))


def test_flow_compiles_all_edges_resolve():
    g = _g()
    assert {"observe", "vector_prefilter", "route"} <= set(g.nodes)
    for name, n in g.nodes.items():
        for target, _c in n.edges:
            assert target in g.nodes, (name, "->", target)


def test_route_covers_mitre_tactics():
    g = _g()
    targets = {t for t, _ in g.nodes["route"].edges}
    assert set(TACTICS) <= targets


def test_attack_adjudicators_escalation_default_to_watch():
    g = _g()
    for adj in ATTACK_TACTICS:
        tgts = [t for t, _ in g.nodes[adj].edges]
        assert "stage_containment" in tgts and "watchlist" in tgts and "benign" in tgts
        assert tgts[-1] == "watchlist"          # a matched attack tactic is never dismissed benign by default


def test_general_adjudicator_defaults_benign():
    # the ONLY node whose default is benign — the explicit "no attack technique / routine noise" catch-all
    g = _g()
    tgts = [t for t, _ in g.nodes["general_adjudicate"].edges]
    assert "benign" in tgts and tgts[-1] == "benign"


def test_prefilter_gate_present():
    g = _g()
    tgts = [t for t, _ in g.nodes["vector_prefilter"].edges]
    assert "stage_containment" in tgts and "watchlist" in tgts and "benign" in tgts
    assert "signature_gate" in tgts            # a miss falls through to the signature gate / router


def test_adapter_module_exposes_port_surface():
    import wazuh_triage_agent as a
    for fn in ("alert_document", "alert_key"):      # Ingestion normalizers (pure, top-level)
        assert hasattr(a, fn) and callable(getattr(a, fn)), fn
    assert a.FLOW.endswith("wazuh_triage.md") and a.POLICY_HASH        # flow bound as policy_hash
