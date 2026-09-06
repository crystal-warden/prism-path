# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The AST catalog's three-mechanism treatment: a documented AI Safety Testing Plan (SOP), a recurring
retest task whose completion evidences continuous evaluation (operational), alongside the config
comparator and measured receipts."""
import compliance_adapter as ca
import control_tasks as ct
import sop_generator as sg
import ai_safety as ais

_CAPS_NO_CONTINUOUS = {
    "test_suite_defined": True, "model_versions_hashed": True,
    "tests_fingerprinted": True, "stale_tests_refused": True,
    "discrimination_margin_measured": True, "collapsed_margin_abstains": True,
    "determinations_signed": True, "receipts_anchored": True, "point_in_time_replayable": True,
    "io_baseline_comparison": True, "drift_abstains_or_escalates": True,
}


def _state(caps=None, completions=None):
    return {"boundary": "the model",
            "versions": [{"version_hash": "v3", "deployed": True, "current": True}],
            "determinations": [{"control_id": "AST-1", "status": "met",
                                "version_hash": "v3", "tested_at": "2026-09-01"}],
            "capabilities": caps or {}, "retest_completions": completions or []}


def test_ast_sop_is_objective_complete():
    ca.use_standard("ai_safety_testing")
    cov = sg.verify_coverage(sg.load_spec("ai_safety_testing_plan"))
    assert cov["complete"] is True and cov["n_objectives"] == 14
    ca.use_standard("nist_800171_r2")


def test_ast_retest_task_registered():
    tasks = ct.tasks_for("AST-3")
    assert tasks and tasks[0]["id"] == "safety-suite-run"
    assert tasks[0]["objectives"] == ["AST-3[d]"]


def test_operational_facts_current_overdue_and_none():
    done = [ct.record_completion("safety-suite-run", "AST-3", "2026-09-01", "ci", "run.json")]
    assert ais.operational_facts({"retest_completions": done}, "2026-09-03")["continuous_evaluation"] is True
    assert ais.operational_facts({"retest_completions": done}, "2026-10-01")["continuous_evaluation"] is False
    assert ais.operational_facts({"retest_completions": []}, "2026-09-03")["continuous_evaluation"] is False


def test_continuous_evaluation_measured_from_task_record():
    # declared everything except continuous_evaluation, no as_of -> AST-3 defers
    r0 = ais.assess(_state(dict(_CAPS_NO_CONTINUOUS)))
    assert "AST-3" in r0["deferred"]
    # a current retest completion + as_of -> continuous_evaluation is measured -> AST-3 decides met
    done = [ct.record_completion("safety-suite-run", "AST-3", "2026-09-01", "ci", "run.json")]
    r1 = ais.assess(_state(dict(_CAPS_NO_CONTINUOUS), done), as_of="2026-09-03")
    by = {x["control_id"]: x for x in r1["results"]}
    assert by["AST-3"]["status"] == "met"
    assert "continuous_evaluation" in r1["measured"]
    # an overdue retest -> continuous_evaluation measured False -> AST-3 not met
    r2 = ais.assess(_state(dict(_CAPS_NO_CONTINUOUS), done), as_of="2026-10-01")
    by2 = {x["control_id"]: x for x in r2["results"]}
    assert by2["AST-3"]["status"] in ("partially-met", "not-met")
    assert "AST-3[d]" in by2["AST-3"]["unmet_objective_ids"]
    assert ca.active_standard() == "nist_800171_r2"
