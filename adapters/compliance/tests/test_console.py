# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The console runs the whole platform end to end and surfaces every capability from real calls: the
unified assessment, the decision view (verdict, who-decides, what-breaks), SPRS, FAIR risk, tasks, SOPs,
signed receipts, OSCAL export. No section is a stub."""
import compliance_adapter as ca
import console as cons


def test_console_runs_end_to_end_and_populates_every_section():
    m = cons.demo()
    assert m["standard"] == "nist_800171_r2"
    assert set(m["standards_available"]) >= {"nist_800171_r2", "ai_safety_testing"}
    # every control assessed, tally is complete
    assert m["summary"]["n_controls"] == 110
    assert sum(m["summary"]["tally"].values()) == 110
    # real mechanisms actually decided objectives (config from the scan, operational from task records)
    assert m["summary"]["by_mechanism"]["config"] > 0
    assert m["summary"]["by_mechanism"]["operational"] > 0
    # rollups are real
    assert m["sprs"]["n_assessed"] == 110
    assert m["risk"]["aggregate_ale"]["likely"] > 0
    assert len(m["risk"]["top"]) >= 1
    assert len(m["sops"]) >= 5
    assert m["receipts"]["n_signed"] == 110               # a key was supplied -> every determination signed
    assert m["oscal_export"]["available"] is True


def test_decision_view_ties_controls_to_owner_and_what_breaks():
    m = cons.demo()
    by = {c["control_id"]: c for c in m["controls"]}
    # 3.1.1 mitigates the credential-exfil scenario; unmet here, so it must show as exposed
    c = by["3.1.1"]
    assert c["verdict"] in ("insufficient", "not-met", "partially-met")
    assert "escalate" in c["who_decides"] or "remediation" in c["who_decides"]
    assert any("exfiltration" in wb["scenario"].lower() and wb["exposed"] for wb in c["what_breaks"])
    # a met control shows no exposure
    met = next(c for c in m["controls"] if c["verdict"] == "met" and c["what_breaks"])
    assert all(wb["exposed"] is False and wb["ale_likely"] == 0 for wb in met["what_breaks"])


def test_llm_path_is_wired_through_the_console(monkeypatch):
    # with the LLM enabled, prose objectives that were undetermined get decided by the adjudicator
    monkeypatch.setattr(ca, "adjudicate",
                        lambda control, req: {"status": "met", "unmet_objective_ids": [], "gap_summary": "llm"})
    off = cons.demo(use_llm=False)
    on = cons.demo(use_llm=True)
    assert off["summary"]["by_mechanism"]["llm"] == 0
    assert on["summary"]["by_mechanism"]["llm"] > 0
    assert on["summary"]["tally"]["insufficient"] < off["summary"]["tally"]["insufficient"]


def test_render_text_produces_output():
    txt = cons.render_text(cons.demo())
    assert "PrismPath GRC console" in txt and "decision view" in txt
    ca.use_standard("nist_800171_r2")


def test_render_html_is_self_contained_and_data_driven():
    m = cons.demo()
    html = cons.render_html(m)
    # fonts are the one allowed external host; no other network dependency
    assert "fonts.googleapis.com" in html
    assert "http://" not in html.replace("https://fonts.g", "")   # no non-font external resources
    # all three theme states are defined at token level (light :root, system dark, explicit dark)
    assert html.count("prefers-color-scheme") == 1 and '[data-theme="dark"]' in html
    # the decision table renders one styled verdict pill per control, colored by verdict
    assert html.count('class="pill') == m["summary"]["n_controls"]
    for cls in ("pill met", "pill notmet", "pill insuff"):
        assert cls in html
    # the summary numbers are actually rendered, not placeholders
    assert cons._money(m["risk"]["aggregate_ale"]["likely"]) in html
    assert str(m["sprs"]["ceiling_if_unassessed_all_met"]) in html
    assert "Decision view" in html and "What breaks" in html
