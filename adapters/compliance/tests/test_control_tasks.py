# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Operational / evidence layer: recurring tasks, due/overdue status from cadence, and completion
records that evidence the 'performed' objectives. Fail-closed and clock-free (dates passed in)."""
import pytest
import compliance_adapter as ca
import control_tasks as ct


def _control(cid):
    ca.use_standard("nist_800171_r2")
    return ca.get_control(cid)


def _ir_task():
    return ct.tasks_for("3.6.3")[0]


def test_specs_load_and_map_to_operational_objectives():
    assert "3.6.3" in ct.list_operational_controls()
    t = _ir_task()
    assert t["id"] == "ir-capability-test"
    assert t["objectives"] == ["3.6.3[a]"]
    assert t["cadence_days"] == 365


def test_record_completion_validates_date():
    rec = ct.record_completion("ir-capability-test", "3.6.3", "2026-01-15", "tester", "aar.pdf")
    assert rec["record_type"] == "operational_evidence"
    assert rec["completed_on"] == "2026-01-15"
    with pytest.raises(ValueError):
        ct.record_completion("ir-capability-test", "3.6.3", "not-a-date", "tester", "aar.pdf")


def test_task_status_current_overdue_and_never_done():
    task = _ir_task()
    done = [ct.record_completion("ir-capability-test", "3.6.3", "2026-01-15", "t", "aar.pdf")]
    within = ct.task_status(task, done, "2026-06-01")
    assert within["status"] == "current" and within["overdue"] is False
    assert within["due_by"] == "2027-01-15"
    past = ct.task_status(task, done, "2027-06-01")
    assert past["status"] == "overdue" and past["overdue"] is True
    never = ct.task_status(task, [], "2026-06-01")
    assert never["status"] == "never-done" and never["overdue"] is True


def test_operational_evidence_tracks_current_completions():
    done = [ct.record_completion("ir-capability-test", "3.6.3", "2026-01-15", "t", "aar.pdf")]
    ev_current = ct.operational_evidence("3.6.3", done, "2026-06-01")
    assert ev_current["3.6.3[a]"]["evidenced"] is True
    assert ev_current["3.6.3[a]"]["last_completed"] == "2026-01-15"
    ev_overdue = ct.operational_evidence("3.6.3", done, "2027-06-01")
    assert ev_overdue["3.6.3[a]"]["evidenced"] is False


def test_assess_operational_met_notmet_and_none():
    control = _control("3.6.3")
    done = [ct.record_completion("ir-capability-test", "3.6.3", "2026-01-15", "t", "aar.pdf")]
    met = ct.assess_operational(control, done, "2026-06-01")
    assert met["status"] == "met"
    assert met["method"] == "operational-record"
    assert met["covered_objectives"] == ["3.6.3[a]"]
    notmet = ct.assess_operational(control, done, "2027-06-01")
    assert notmet["status"] == "not-met"
    assert notmet["unmet_objective_ids"] == ["3.6.3[a]"]
    # a control with no operational tasks defers here (None)
    assert ct.assess_operational(_control("3.1.1"), done, "2026-06-01") is None


def test_multi_objective_task_covers_both():
    control = _control("3.3.3")   # audit-log-review covers 3.3.3[b] and 3.3.3[c]
    done = [ct.record_completion("audit-log-review", "3.3.3", "2026-05-01", "t", "logreview.md")]
    res = ct.assess_operational(control, done, "2026-06-01")
    assert res["status"] == "met"
    assert set(res["covered_objectives"]) == {"3.3.3[b]", "3.3.3[c]"}


def test_due_tasks_lists_everything_when_nothing_done():
    due = ct.due_tasks([], "2026-06-01")
    controls_with_due = {d["control_id"] for d in due}
    assert controls_with_due == set(ct.list_operational_controls())
    assert all(d["overdue"] for d in due)
