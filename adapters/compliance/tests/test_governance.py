# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The Governance & Direction layer runs the assurance chain strategy-down: an organizational objective ->
the risk scenarios that threaten it -> the controls -> the live verdicts -> the dollar exposure -> whether
it sits inside the risk appetite the organization set. Improving controls moves an objective back inside
appetite; unmet controls are the named drivers."""
import fair_risk as fr
import governance as gov


def test_all_met_keeps_objectives_within_appetite():
    verdicts = {c: "met" for s in fr.load_scenarios() for c in s["controls"]}   # everything met
    r = gov.assess_governance(verdicts)
    assert r["within_appetite"] == r["n_objectives"]                            # residual-only exposure
    assert all(p["current_exposure"] < p["appetite_ale"] for p in r["objectives"])


def test_unmet_pushes_objectives_over_appetite():
    r = gov.assess_governance({})                                              # nothing met -> full exposure
    assert r["over_appetite"] >= 1
    over = next(p for p in r["objectives"] if not p["within_appetite"])
    assert over["over_by"] > 0 and over["driving_controls"]                    # named controls drive it


def test_objective_posture_links_strategy_to_controls():
    p = gov.objective_posture(gov.ORG_OBJECTIVES[0], {}, gov._scenarios_by_id())
    assert p["objective"] == "OBJ-1" and p["owner"] and p["category"] == "strategic"
    assert p["scenarios"] and p["driving_controls"]                            # risk -> controls linkage
    assert p["current_exposure"] > 0


def test_demo_and_render():
    txt = gov.render_text(gov.demo())
    assert txt.startswith("Governance & Direction") and "OBJ-1" in txt
