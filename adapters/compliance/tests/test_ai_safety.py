# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The AI-safety-testing catalog assessed by the same engine, and the model-version binding that makes
'retested after every change' provable."""
import compliance_adapter as ca
import deterministic_checks as dc
import ai_safety as ais

CAPS = {
    "test_suite_defined": True, "model_versions_hashed": True,
    "tests_fingerprinted": True, "stale_tests_refused": True,
    "discrimination_margin_measured": True, "collapsed_margin_abstains": True,
    "determinations_signed": True, "receipts_anchored": True,
    "point_in_time_replayable": True, "continuous_evaluation": True,
    "io_baseline_comparison": True, "drift_abstains_or_escalates": True,
}


def _good_state():
    return {
        "boundary": "the routing model behind PrismPath",
        "versions": [{"version_hash": "v3", "deployed": True, "current": True},
                     {"version_hash": "v2", "deployed": True}],
        "determinations": [{"version_hash": "v3"}, {"version_hash": "v2"}],
        "capabilities": dict(CAPS),
    }


def test_catalog_registered_and_selectable():
    assert "ai_safety_testing" in ca.list_standards()
    ca.use_standard("ai_safety_testing")
    assert set(ca._catalog()["controls"]) == {"AST-1", "AST-2", "AST-3", "AST-4"}
    ca.use_standard("nist_800171_r2")


def test_all_ast_controls_are_machine_checkable():
    ca.use_standard("ai_safety_testing")
    for cid in ("AST-1", "AST-2", "AST-3", "AST-4"):
        assert dc.machine_checkable(ca.get_control(cid)) is True
    ca.use_standard("nist_800171_r2")


def test_version_binding_all_retested():
    vb = ais.version_binding(_good_state()["versions"], _good_state()["determinations"])
    assert vb["all_deployed_retested"] is True
    assert vb["unretested_deployed"] == []
    assert vb["current_has_determination"] is True


def test_version_binding_flags_unretested_deploy():
    versions = [{"version_hash": "v3", "deployed": True, "current": True},
                {"version_hash": "v2", "deployed": True},
                {"version_hash": "v2.5", "deployed": True}]     # pushed but never retested
    determinations = [{"version_hash": "v3"}, {"version_hash": "v2"}]
    vb = ais.version_binding(versions, determinations)
    assert vb["all_deployed_retested"] is False
    assert vb["unretested_deployed"] == ["v2.5"]


def test_assess_good_pipeline_all_met():
    res = ais.assess(_good_state())
    assert res["assessed"] == 4
    assert res["deferred"] == []
    assert res["tally"] == {"met": 4, "partially-met": 0, "not-met": 0}
    assert res["version_binding"]["all_deployed_retested"] is True


def test_assess_unretested_version_fails_retest_control():
    state = _good_state()
    state["versions"].append({"version_hash": "v2.5", "deployed": True})   # no determination for it
    res = ais.assess(state)
    by_id = {r["control_id"]: r for r in res["results"]}
    assert by_id["AST-1"]["status"] == "partially-met"
    assert by_id["AST-1"]["unmet_objective_ids"] == ["AST-1[d]"]
    assert res["version_binding"]["unretested_deployed"] == ["v2.5"]


def test_assess_missing_capability_defers_not_assumes():
    state = _good_state()
    del state["capabilities"]["tests_fingerprinted"]   # AST-2[a] fact absent
    res = ais.assess(state)
    assert "AST-2" in res["deferred"]                   # fail-closed, not assumed met
    assert "AST-1" in {r["control_id"] for r in res["results"]}


def test_assess_restores_previous_standard():
    ca.use_standard("nist_800171_r2")
    ais.assess(_good_state())
    assert ca.active_standard() == "nist_800171_r2"
