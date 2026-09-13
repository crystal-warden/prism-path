#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Unified adjudicator — merge the three honest-hybrid mechanisms into one per-control determination.

For a single control, objectives are decided by whichever mechanism covers them:
  - config       : the comparator adjudicator, from the request's `facts` (deterministic_checks)
  - operational  : current task completion records, for the 'performed' objectives (control_tasks)
  - undetermined : objectives no mechanism here covers (documented/prose) — left for the SOP-adoption
                   record or the LLM adjudicator, and reported honestly rather than assumed

Per objective the result records which mechanism decided it and whether it is met. The control's
determination is met only when every objective is met, partially-met / not-met when some or all are
refuted, and INSUFFICIENT (fail-closed) whenever any objective is still undetermined. Nothing is
assumed satisfied.
Given the same facts, completions, and date, the result is reproducible.
"""
from adapters.compliance import deterministic_checks as _dc
from adapters.compliance import control_tasks as _ct


def full_determination(control, req=None, completions=None, as_of=None, use_llm=False):
    """Merge config (facts) and operational (task completions), and, when use_llm is set, the
    escalation-default LLM adjudicator for the objectives no other mechanism covers. Config and
    operational determinations are measured and always win; the LLM only fills the remaining prose
    objectives. If the LLM is unreachable or errors, those objectives stay undetermined and the
    control is INSUFFICIENT (fail-closed), never assumed. Same inputs, same result."""
    facts = (req or {}).get("facts") or {}
    per = {}   # objective_id -> {"met": bool, "by": mechanism}

    for oid, ok in _dc.check_objectives(control, facts).items():
        per[oid] = {"met": ok, "by": "config"}

    if completions is not None and as_of is not None:
        for oid, ev in _ct.operational_evidence(control["id"], completions, as_of).items():
            per.setdefault(oid, {"met": bool(ev["evidenced"]), "by": "operational"})

    objectives = [objective["id"] for objective in control.get("objectives", [])]
    undetermined = [oid for oid in objectives if oid not in per]

    if undetermined and use_llm:
        from adapters.compliance import compliance_adapter as _ca
        try:
            det = _ca.adjudicate(control, req or {"control_id": control["id"]})
        except Exception:
            det = None
        if det is not None:
            unmet_llm = set(det.get("unmet_objective_ids", []))
            for oid in undetermined:
                per[oid] = {"met": oid not in unmet_llm, "by": "llm"}
            undetermined = [oid for oid in objectives if oid not in per]

    undetermined = sorted(undetermined)
    unmet = sorted(oid for oid, resolution in per.items() if not resolution["met"])

    if undetermined:
        determination = "insufficient"
    elif not unmet:
        determination = "met"
    elif len(unmet) < len(objectives):
        determination = "partially-met"
    else:
        determination = "not-met"

    coverage = {
        "config": sorted(objective_id for objective_id, resolution in per.items() if resolution["by"] == "config"),
        "operational": sorted(objective_id for objective_id, resolution in per.items() if resolution["by"] == "operational"),
        "llm": sorted(objective_id for objective_id, resolution in per.items() if resolution["by"] == "llm"),
        "undetermined": undetermined,
    }
    return {"control_id": control["id"], "status": determination,
            "unmet_objective_ids": unmet, "undetermined_objective_ids": undetermined,
            "objectives_total": len(objectives), "objectives_decided": len(per),
            "by_objective": per, "coverage": coverage, "method": "unified"}
