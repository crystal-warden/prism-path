# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The remediation planner turns an assessment into a prioritized plan: each gap ranked by a transparent
blend of SPRS points, FAIR dollar reduction, obligations unblocked, and objectives helped, with the fix
path attached, and emitted as an OSCAL POA&M in priority order. Assess -> prioritize -> remediate."""
import compliance_adapter as ca
import remediation as rem


def test_plan_ranks_gaps_and_rolls_up():
    plan = rem.demo(top=None)
    assert plan["n_gaps"] > 0
    assert [it["rank"] for it in plan["items"]] == list(range(1, len(plan["items"]) + 1))  # contiguous ranks
    for it in plan["items"]:
        assert it["remediation"] and all("mechanism" in p for p in it["remediation"])      # a fix path each
        assert "priority_score" in it
    r = plan["rollup"]
    assert r["sprs_recoverable"] > 0 and r["ale_reducible_likely"] > 0


def test_priority_is_ordered_and_favors_value():
    plan = rem.demo(top=None)
    scores = [it["priority_score"] for it in plan["items"]]
    assert scores == sorted(scores, reverse=True)                       # ranked by priority, descending
    top = plan["items"][0]
    assert top["sprs_points"] >= 3 or top["ale_reduction_likely"] > 0   # #1 is a high-value gap


def test_all_met_has_no_gaps():
    ca.use_standard("nist_800171_r2")
    allmet = {c: "met" for c in ca._catalog()["controls"]}
    plan = rem.remediation_plan(allmet)
    assert plan["n_gaps"] == 0 and plan["rollup"]["sprs_recoverable"] == 0


def test_poam_emits_prioritized_open_items():
    plan = rem.demo(top=5)
    poam = rem.to_poam(plan)["plan-of-action-and-milestones"]
    items = poam["poam-items"]
    assert len(items) == 5                                              # 5 gaps -> 5 POA&M items
    assert "Priority 1." in items[0]["description"]                     # priority order carried into the POA&M


def test_render_runs():
    txt = rem.render_text(rem.demo())
    assert "Remediation plan" in txt
    ca.use_standard("nist_800171_r2")
