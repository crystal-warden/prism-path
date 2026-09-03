#!/usr/bin/env python3
"""Unified adjudicator — merge the three honest-hybrid mechanisms into one per-control determination.

For a single control, objectives are decided by whichever mechanism covers them:
  - config       : the comparator adjudicator, from the request's `facts` (deterministic_checks)
  - operational  : current task completion records, for the 'performed' objectives (control_tasks)
  - undetermined : objectives no mechanism here covers (documented/prose) — left for the SOP-adoption
                   record or the LLM adjudicator, and reported honestly rather than assumed

Per objective the result records which mechanism decided it and whether it is met. Overall status is
met only when every objective is met, partially-met / not-met when some or all are refuted, and
INSUFFICIENT (fail-closed) whenever any objective is still undetermined. Nothing is assumed satisfied.
Given the same facts, completions, and date, the result is reproducible.
"""
import deterministic_checks as _dc
import control_tasks as _ct


def full_determination(control, req=None, completions=None, as_of=None):
    facts = (req or {}).get("facts") or {}
    per = {}   # objective_id -> {"met": bool, "by": mechanism}

    for oid, ok in _dc.check_objectives(control, facts).items():
        per[oid] = {"met": ok, "by": "config"}

    if completions is not None and as_of is not None:
        for oid, ev in _ct.operational_evidence(control["id"], completions, as_of).items():
            per.setdefault(oid, {"met": bool(ev["evidenced"]), "by": "operational"})

    objectives = [o["id"] for o in control.get("objectives", [])]
    undetermined = sorted(oid for oid in objectives if oid not in per)
    unmet = sorted(oid for oid, r in per.items() if not r["met"])

    if undetermined:
        status = "insufficient"
    elif not unmet:
        status = "met"
    elif len(unmet) < len(objectives):
        status = "partially-met"
    else:
        status = "not-met"

    coverage = {
        "config": sorted(o for o, r in per.items() if r["by"] == "config"),
        "operational": sorted(o for o, r in per.items() if r["by"] == "operational"),
        "undetermined": undetermined,
    }
    return {"control_id": control["id"], "status": status,
            "unmet_objective_ids": unmet, "undetermined_objective_ids": undetermined,
            "objectives_total": len(objectives), "objectives_decided": len(per),
            "by_objective": per, "coverage": coverage, "method": "unified"}
