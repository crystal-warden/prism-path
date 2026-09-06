#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Remediation planner — turn an assessment into a prioritized plan of action.

Assessment answers "where do I stand." This answers "what do I fix first, why, and how" — the
operationalization a buyer actually pays for. For every gap (a control that is not met) it computes the
value of closing it from signals the platform already holds:

  * SPRS points recovered (the DoD Assessment Methodology weight — the number that gates the contract)
  * FAIR dollars of exposure removed (the marginal drop in annualized loss if the control becomes met)
  * obligations unblocked (which DFARS / FAR / contract breach it closes)
  * objectives moved back inside risk appetite (the governance layer)

then ranks the gaps by a transparent blend of those (components exposed on every item, nothing hidden),
attaches the remediation PATH (fix the configuration, adopt the policy, perform the task, or supply
evidence), and emits an OSCAL POA&M in priority order. This closes the loop: assess -> prioritize ->
remediate -> prove -> re-assess.
"""
import compliance_adapter as _ca
import fair_risk as _fr
import obligations as _ob
import governance as _gov
import control_tasks as _ct
import deterministic_checks as _dc
import sop_generator as _sg
import emit as _emit


def _sop_index():
    """control_id -> a SOP doc_id whose controls include it (the 800-171 documentation SOPs)."""
    idx = {}
    for doc in _sg.list_documents():
        try:
            spec = _sg.load_spec(doc)
        except Exception:
            continue
        if spec.get("standard", "nist_800171_r2") != "nist_800171_r2":
            continue
        for cid in spec.get("controls", []):
            idx.setdefault(cid, doc)
    return idx


def _ale_reduction_if_met(cid, verdicts, scenarios):
    """The marginal drop in likely annualized loss if this one control flips to met."""
    total = 0
    for s in scenarios:
        if cid in s.get("controls", []):
            total += _fr.ale(s, verdicts)["likely"] - _fr.ale(s, dict(verdicts, **{cid: "met"}))["likely"]
    return total


def _remediation_path(cid, control, sop_idx):
    """How to close the gap: configuration (a scanner fact), a policy (a SOP), an operational task, or
    evidence for a prose objective. Multiple may apply for a mixed control."""
    paths = []
    facts = sorted({_dc.FACT_KEYS[o["id"]] for o in control.get("objectives", []) if o["id"] in _dc.FACT_KEYS})
    if facts:
        paths.append({"mechanism": "config", "action": "Set the configuration the scanner reads", "detail": facts})
    if cid in sop_idx:
        paths.append({"mechanism": "documented", "action": "Generate and adopt the policy", "detail": sop_idx[cid]})
    tasks = [t["id"] for t in _ct.tasks_for(cid)]
    if tasks:
        paths.append({"mechanism": "operational", "action": "Perform the task and retain the record", "detail": tasks})
    if not paths:
        paths.append({"mechanism": "evidence", "action": "Supply evidence for the prose objective", "detail": []})
    return paths


def remediation_plan(verdicts, boundary="(unspecified)", top=None):
    """Prioritized remediation for the gaps in `verdicts`. Ranks by a transparent blend of SPRS points,
    FAIR dollar reduction, obligations unblocked, and objectives helped, with the components exposed."""
    _ca.use_standard("nist_800171_r2")
    weights = _ca.catalog_weights()
    scenarios = _fr.load_scenarios()
    sop_idx = _sop_index()
    obj_of_control = {}
    for p in _gov.assess_governance(verdicts)["objectives"]:
        for c in p["driving_controls"]:
            obj_of_control.setdefault(c, []).append(p["objective"])

    items = []
    for cid, status in verdicts.items():
        if status == "met":
            continue
        control = _ca.get_control(cid)
        items.append({
            "control_id": cid, "title": control["title"], "status": status,
            "sprs_points": weights.get(cid, 0),
            "ale_reduction_likely": _ale_reduction_if_met(cid, verdicts, scenarios),
            "obligations_unblocked": [b["obligation"] for b in _ob.breaches_for_control(cid)],
            "objectives_helped": obj_of_control.get(cid, []),
            "remediation": _remediation_path(cid, control, sop_idx),
        })

    max_sprs = max([it["sprs_points"] for it in items] + [1])
    max_ale = max([it["ale_reduction_likely"] for it in items] + [1])
    for it in items:
        sn, an = it["sprs_points"] / max_sprs, it["ale_reduction_likely"] / max_ale
        on = min(1.0, len(it["obligations_unblocked"]) / 3.0)
        jn = min(1.0, len(it["objectives_helped"]) / 2.0)
        it["priority_score"] = round(0.45 * sn + 0.35 * an + 0.12 * on + 0.08 * jn, 4)
    items.sort(key=lambda it: (-it["priority_score"], -it["sprs_points"], -it["ale_reduction_likely"]))
    for i, it in enumerate(items):
        it["rank"] = i + 1
    if top:
        items = items[:top]

    rollup = {"gaps": len(items),
              "sprs_recoverable": sum(it["sprs_points"] for it in items),
              "ale_reducible_likely": sum(it["ale_reduction_likely"] for it in items),
              "obligations_touched": sorted({o for it in items for o in it["obligations_unblocked"]}),
              "objectives_touched": sorted({o for it in items for o in it["objectives_helped"]})}
    return {"boundary": boundary, "n_gaps": len(items), "items": items, "rollup": rollup,
            "weighting": "priority = 0.45*SPRS + 0.35*FAIR$ + 0.12*obligations + 0.08*objectives, normalized"}


def to_poam(plan, now=None):
    """Emit the plan as an OSCAL Plan of Action & Milestones, in priority order."""
    results = [{"control_id": it["control_id"], "title": it["title"], "status": it["status"],
                "boundary": plan.get("boundary"),
                "gap_summary": "Priority %d. Fix via %s; recovers %d SPRS points, reduces $%s risk." % (
                    it["rank"], "/".join(p["mechanism"] for p in it["remediation"]),
                    it["sprs_points"], format(it["ale_reduction_likely"], ",")),
                "unmet_objective_ids": []}
               for it in plan["items"]]
    return _emit.emit_oscal_poam(results, now=now)


def demo(use_llm=False, top=8):
    import unified as _un
    import posture_connector as _pc
    _ca.use_standard("nist_800171_r2")
    posture = _pc.load_sample("example_host")
    req_base = {"facts": posture.get("facts", {}), "boundary": posture.get("boundary")}
    verdicts = {cid: _un.full_determination(_ca.get_control(cid), dict(req_base, control_id=cid))["status"]
                for cid in _ca._catalog()["controls"]}
    return remediation_plan(verdicts, boundary=posture.get("boundary", "(unspecified)"), top=top)


def render_text(plan):
    r = plan["rollup"]
    L = ["Remediation plan  |  %d gaps  |  fix all -> +%d SPRS, -$%s risk, closes %d obligations"
         % (plan["n_gaps"], r["sprs_recoverable"], format(r["ale_reducible_likely"], ","),
            len(r["obligations_touched"]))]
    for it in plan["items"]:
        L.append("  #%-2d %-8s %-40s +%d SPRS  -$%-9s  %s"
                 % (it["rank"], it["control_id"], it["title"][:40], it["sprs_points"],
                    format(it["ale_reduction_likely"], ","), "/".join(p["mechanism"] for p in it["remediation"])))
        if it["obligations_unblocked"]:
            L.append("        unblocks: %s" % ", ".join(it["obligations_unblocked"]))
    return "\n".join(L)


if __name__ == "__main__":
    print(render_text(demo()))
