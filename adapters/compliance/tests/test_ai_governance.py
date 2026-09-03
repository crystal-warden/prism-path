# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The AI-governance pillar: an AI-GOV catalog (the organizational AI-governance questions, structured on
the NIST AI RMF functions) assessed through the same unified determination. Inventory objectives decide
deterministically from the AI-use register; policy/operating objectives fail closed to insufficient
without adopted SOPs and records. A missing inventory reads as not-met, never assumed met."""
import compliance_adapter as ca
import ai_register as reg
import ai_governance as aig


def test_ai_governance_is_registered_and_covers_the_questions():
    assert "ai_governance" in ca.list_standards()
    ca.use_standard("ai_governance")
    cat = ca._catalog()
    assert cat["_meta"]["controls"] == 11
    ids = set(cat["controls"])
    # every AI RMF function is represented, and the inventory + governance controls exist
    assert {"MP-1", "MP-2", "MP-3", "MP-4", "MP-5", "GV-1", "GV-2", "GV-3", "MG-1", "MG-2", "MS-1"} == ids
    ca.use_standard("nist_800171_r2")


def test_register_is_fail_closed():
    empty = reg.facts_from_register({})
    assert set(empty) == set(reg.FACT_KEYS)
    assert all(v is False for v in empty.values())          # nothing shown -> nothing credited
    sample = reg.facts_from_register(reg._SAMPLE)
    assert sample["ai_user_inventory_exists"] is True
    assert sample["ai_prohibited_data_controls_enforced"] is False   # the modeled gap
    assert sample["ai_high_risk_uses_tiered"] is False               # partial inventory -> not complete


def test_assessment_decides_inventory_from_the_register_fail_closed():
    r = aig.demo()
    assert r["standard"] == "ai_governance" and r["n_controls"] == 11
    # the register actually decided objectives deterministically (no model)
    assert r["by_mechanism"]["config"] >= 8
    by = {c["control_id"]: c["verdict"] for c in r["controls"]}
    # approved-tools: both objectives are register facts and both true -> met with no model
    assert by["MP-2"] == "met"
    # decision-impact recorded but tiering incomplete -> one objective met, one refuted -> partially-met
    assert by["MP-5"] == "partially-met"
    # a control with policy/operating objectives and no adopted evidence fails closed
    assert by["GV-1"] == "insufficient"


def test_render_runs():
    txt = aig.render_text(aig.demo())
    assert "AI governance assessment" in txt and "MP-2" in txt
    ca.use_standard("nist_800171_r2")
