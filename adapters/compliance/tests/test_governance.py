# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The Governance & Direction layer runs the assurance chain strategy-down: an organizational objective ->
the risk scenarios that threaten it -> the controls -> the live verdicts -> the dollar exposure -> whether
it sits inside the risk appetite the organization set. Improving controls moves an objective back inside
appetite; unmet controls are the named drivers."""
from adapters.compliance import fair_risk as fr
from adapters.compliance import governance as gov


def test_all_met_keeps_objectives_within_appetite():
    verdicts = {control_id: "met" for scenario in fr.load_scenarios() for control_id in scenario["controls"]}   # everything met
    assessment = gov.assess_governance(verdicts)
    assert assessment["within_appetite"] == assessment["n_objectives"]                            # residual-only exposure
    assert all(posture["current_exposure"] < posture["appetite_ale"] for posture in assessment["objectives"])


def test_unmet_pushes_objectives_over_appetite():
    assessment = gov.assess_governance({})                                              # nothing met -> full exposure
    assert assessment["over_appetite"] >= 1
    over = next(posture for posture in assessment["objectives"] if not posture["within_appetite"])
    assert over["over_by"] > 0 and over["driving_controls"]                    # named controls drive it


def test_objective_posture_links_strategy_to_controls():
    posture = gov.objective_posture(gov.ORG_OBJECTIVES[0], {}, gov._scenarios_by_id())
    assert posture["objective"] == "OBJ-1" and posture["owner"] and posture["category"] == "strategic"
    assert posture["scenarios"] and posture["driving_controls"]                            # risk -> controls linkage
    assert posture["current_exposure"] > 0


def test_demo_and_render():
    txt = gov.render_text(gov.demo())
    assert txt.startswith("Governance & Direction") and "OBJ-1" in txt
