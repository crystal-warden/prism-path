#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Operational / evidence layer — recurring control tasks and the completion records that EVIDENCE
the objectives a config scan cannot.

The honest-boundary problem: many 800-171A objectives are not "is it configured" (which the comparator
adjudicator decides from facts) and not "is it documented" (which the SOP generator produces). They are
"is the process performed": the incident response capability is tested (3.6.3[a]), controls are assessed
with the defined frequency (3.12.1[b]), vulnerability scans are performed (3.11.2[b,c]), personnel are
trained (3.2.2[c]). Those are satisfied only by a record that the process ran, on cadence.

This layer holds the recurring tasks (task_specs.json), records their completions, computes due/overdue
status from a cadence and the last completion, and turns current completions into operational evidence
for the objectives they cover. It is the third mechanism in the honest hybrid, alongside the config
comparator (deterministic_checks) and the document generator (sop_generator), and like them it is
fail-closed: an objective with no current completion is NOT evidenced, never assumed.

Dates are passed in (`as_of`, `completed_on` as ISO-8601 date strings); nothing here reads the clock, so
every status is a reproducible function of the records and the date supplied.
"""
import os
import json
import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC_PATH = os.path.join(HERE, "task_specs.json")


def _date(s):
    return datetime.date.fromisoformat(s)


def _load():
    return {k: v for k, v in json.load(open(SPEC_PATH)).items() if not k.startswith("_")}


def all_tasks():
    """control_id -> list of recurring task specs."""
    return _load()


def list_operational_controls():
    return sorted(_load().keys())


def tasks_for(control_id):
    return _load().get(control_id, [])


def record_completion(task_id, control_id, completed_on, actor, evidence_ref, notes=""):
    """Build a completion record for a task that was performed. Structured for the caller to persist
    and to bind into the ledger as operational evidence. completed_on is an ISO-8601 date."""
    _date(completed_on)   # validate the date up front
    return {"task_id": task_id, "control_id": control_id, "completed_on": completed_on,
            "actor": actor, "evidence_ref": evidence_ref, "notes": notes,
            "record_type": "operational_evidence"}


def task_status(task, completions, as_of):
    """Due/overdue status for one task, from its cadence and the most recent matching completion.
    completions: records (each with task_id and completed_on). as_of: ISO-8601 date string."""
    as_of_d = _date(as_of)
    dates = [_date(c["completed_on"]) for c in completions if c.get("task_id") == task["id"]]
    if not dates:
        return {"task_id": task["id"], "last_completed": None, "due_by": None,
                "overdue": True, "days_until_due": None, "status": "never-done"}
    last = max(dates)
    due_by = last + datetime.timedelta(days=int(task["cadence_days"]))
    overdue = as_of_d > due_by
    return {"task_id": task["id"], "last_completed": last.isoformat(), "due_by": due_by.isoformat(),
            "overdue": overdue, "days_until_due": (due_by - as_of_d).days,
            "status": "overdue" if overdue else "current"}


def due_tasks(completions, as_of):
    """Every task across all specs that is overdue or never done, for the operations dashboard."""
    out = []
    for cid, tasks in _load().items():
        for task in tasks:
            st = task_status(task, completions, as_of)
            if st["overdue"]:
                out.append({"control_id": cid, **st, "title": task["title"]})
    return out


def operational_evidence(control_id, completions, as_of):
    """For each objective covered by this control's tasks, whether a CURRENT (non-overdue) completion
    evidences it. The operational analog of the config-facts check: a live record that the process
    ran, not a document saying it should."""
    obj_tasks = {}
    for task in tasks_for(control_id):
        st = task_status(task, completions, as_of)
        for oid in task.get("objectives", []):
            obj_tasks.setdefault(oid, []).append(st)
    out = {}
    for oid, statuses in obj_tasks.items():
        current = [s for s in statuses if not s["overdue"]]
        lasts = [s["last_completed"] for s in statuses if s["last_completed"]]
        out[oid] = {"evidenced": bool(current),
                    "tasks": [s["task_id"] for s in statuses],
                    "current_tasks": [s["task_id"] for s in current],
                    "last_completed": max(lasts) if lasts else None}
    return out


def assess_operational(control, completions, as_of):
    """Determination over the objectives this control's operational tasks cover, from live completion
    records. Objectives with a current completion are met; overdue or never-done are unmet. Returns
    None (fail-closed) when the control has no operational tasks, leaving it to the other mechanisms.
    Covers a SUBSET of the control's objectives; combine with the config and document determinations
    for the whole control."""
    ev = operational_evidence(control["id"], completions, as_of)
    covered = [o["id"] for o in control["objectives"] if o["id"] in ev]
    if not covered:
        return None
    unmet = sorted(oid for oid in covered if not ev[oid]["evidenced"])
    if not unmet:
        status = "met"
        gap = "all %d operationally-evidenced objectives are current" % len(covered)
    elif len(unmet) < len(covered):
        status = "partially-met"
        gap = "operational tasks overdue or never done for: " + ", ".join(unmet)
    else:
        status = "not-met"
        gap = "no current operational evidence for: " + ", ".join(unmet)
    return {"status": status, "unmet_objective_ids": unmet, "gap_summary": gap,
            "method": "operational-record", "covered_objectives": covered}
