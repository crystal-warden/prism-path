# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The obligations layer links external drivers (regulations, contracts, policies) to the controls they
require, so 'are we meeting DFARS 252.204-7012, and which controls are the breach' is one query against
the live determinations. Required evidence can arrive through a crosswalk, so one assessment satisfies
obligations across frameworks."""
from adapters.compliance import compliance_adapter as ca
from adapters.compliance import obligations as ob


def test_obligation_resolves_required_controls():
    fw, ctrls = ob._required_controls({"framework": "nist_800171_r2", "scope": "all"})
    assert fw == "nist_800171_r2" and len(ctrls) == 110
    _, l1 = ob._required_controls({"framework": "nist_800171_r2", "scope": "cmmc_l1"})
    assert len(l1) == 17                                              # FAR basic safeguarding = CMMC L1
    ca.use_standard("nist_800171_r2")


def test_all_met_satisfies_800171_obligations():
    ca.use_standard("nist_800171_r2")
    allmet = {control_id: "met" for control_id in ca._catalog()["controls"]}
    assessment = ob.assess_obligations({"nist_800171_r2": allmet})
    by = {obligation["obligation"]: obligation for obligation in assessment["obligations"]}
    assert by["DFARS-7012"]["status"] == "met" and by["FAR-52.204-21"]["status"] == "met"
    assert by["CONTRACT-SOC2"]["status"] == "not-met"                # no SOC 2 evidence supplied here
    ca.use_standard("nist_800171_r2")


def test_breach_names_controls_and_reverse_view():
    assessment = ob.assess_obligations({"nist_800171_r2": {}})               # nothing met
    dfars = next(obligation for obligation in assessment["obligations"] if obligation["obligation"] == "DFARS-7012")
    assert dfars["status"] == "not-met" and len(dfars["breaching_controls"]) == 110
    obs = {breach["obligation"] for breach in ob.breaches_for_control("3.1.1")}
    assert {"DFARS-7012", "FAR-52.204-21"} <= obs                    # a failing 3.1.1 breaches both
    ca.use_standard("nist_800171_r2")


def test_demo_reaches_across_frameworks_via_crosswalk():
    assessment = ob.demo()                                                    # 800-171 + SOC2 (crosswalk) + AI-gov
    frameworks = {obligation["framework"] for obligation in assessment["obligations"]}
    assert {"nist_800171_r2", "soc2_tsc", "ai_governance"} <= frameworks
    soc2 = next(obligation for obligation in assessment["obligations"] if obligation["framework"] == "soc2_tsc")
    assert soc2["evidence_present"] is True                          # SOC 2 answered from the 800-171 assessment
    assert ob.render_text(assessment).startswith("Obligations")
    ca.use_standard("nist_800171_r2")
