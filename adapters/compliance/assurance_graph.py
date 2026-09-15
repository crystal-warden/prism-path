#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Assurance connectivity graph — the common backbone of the GRC Alignment Model.

The alignment model's core is connectivity: obligations, controls, evidence, risk, and ownership should
be linked, not siloed, so one control's assurance chain is visible end to end and a single assessment
serves everyone. We already hold all those pieces separately (catalogs, crosswalks, FAIR scenarios, the
method-profile owners); this module joins them into one queryable graph.

  nodes:  frameworks, controls, objectives, risk scenarios, assurance owners
  edges:  framework -contains-> control -has-> objective
          control -crosswalks_to-> control (another framework)
          control -mitigates-> risk scenario  (with dollar exposure)
          control -owned_by-> assurance owner

trace(control) walks that graph for one control and returns its full chain, so "what does this control
touch, what breaks if it fails, who owns it, and which frameworks does it satisfy" is one call. This is
the traceability the model asks for, built on the primitives we already ship — no new data, just the
connections made explicit.
"""
from adapters.compliance import compliance_adapter as _ca
from adapters.compliance import crosswalk as _cw
from adapters.compliance import fair_risk as _fr

_OWNER = {"technical": "System / Security Administrator", "procedural": "ISSM / Policy Owner",
          "operational": "Operations / Process Owner", "general": "ISSM"}


def _owner_of(control):
    return _OWNER.get(_ca._method_profile(control), "ISSM")


def trace(control_id, standard=None):
    """The full assurance chain for one control: its objectives, every framework/control it crosswalks
    to (both directions), the risk scenarios it mitigates (with dollar exposure), and its owner."""
    if standard:
        _ca.use_standard(standard)
    control = _ca.get_control(control_id)
    std = _ca.active_standard()
    reach = []
    for name in _cw.list_crosswalks():
        crosswalk = _cw.load_crosswalk(name)
        if std == crosswalk["a"]:
            tgts = sorted({target_control for edge in crosswalk["edges"] if edge["a"] == control_id for target_control in edge["b"]})
            if tgts:
                reach.append({"framework": crosswalk["b"], "controls": tgts, "crosswalk": name, "direction": "forward"})
        elif std == crosswalk["b"]:
            srcs = sorted({edge["a"] for edge in crosswalk["edges"] if control_id in edge["b"]})
            if srcs:
                reach.append({"framework": crosswalk["a"], "controls": srcs, "crosswalk": name, "direction": "reverse"})
    scen = [{"scenario": scenario["name"], "id": scenario["id"], "ale_likely": scenario["loss"]["likely"]}
            for scenario in _fr.load_scenarios() if control_id in scenario.get("controls", [])]
    return {"standard": std, "control_id": control_id, "title": control["title"],
            "owner": _owner_of(control), "objectives": [objective["id"] for objective in control.get("objectives", [])],
            "crosswalk_reach": reach, "mitigates_risk": scen,
            "frameworks_satisfied": sorted({reached["framework"] for reached in reach})}


def graph_summary(standard="nist_800171_r2"):
    """Node and edge counts of the connectivity graph anchored on one standard."""
    _ca.use_standard(standard)
    controls = _ca._catalog()["controls"]
    n_obj = sum(len(control.get("objectives", [])) for control in controls.values())
    xw_edges, frameworks = 0, set()
    for name in _cw.list_crosswalks():
        crosswalk = _cw.load_crosswalk(name)
        if standard in (crosswalk["a"], crosswalk["b"]):
            frameworks.add(crosswalk["b"] if standard == crosswalk["a"] else crosswalk["a"])
            xw_edges += sum(len(edge["b"]) for edge in crosswalk["edges"])
    scenarios = _fr.load_scenarios()
    risk_links = sum(len(scenario.get("controls", [])) for scenario in scenarios)
    owners = sorted({_owner_of({"family_name": control.get("family_name")}) for control in controls.values()})
    return {"standard": standard,
            "nodes": {"controls": len(controls), "objectives": n_obj,
                      "frameworks_linked": sorted(frameworks), "risk_scenarios": len(scenarios)},
            "edges": {"crosswalk_links": xw_edges, "risk_links": risk_links},
            "owners": owners}


def demo():
    return {"summary": graph_summary("nist_800171_r2"), "example_trace": trace("3.1.1", "nist_800171_r2")}


def render_text(graph):
    summary, example_trace = graph["summary"], graph["example_trace"]
    lines = ["Assurance connectivity graph (anchored on %s):" % summary["standard"]]
    lines.append("  nodes: %d controls, %d objectives, %d risk scenarios; frameworks linked: %s"
                 % (summary["nodes"]["controls"], summary["nodes"]["objectives"], summary["nodes"]["risk_scenarios"],
                    ", ".join(summary["nodes"]["frameworks_linked"])))
    lines.append("  edges: %d crosswalk links, %d control->risk links; owners: %s"
                 % (summary["edges"]["crosswalk_links"], summary["edges"]["risk_links"], ", ".join(summary["owners"])))
    lines.append("")
    lines.append("  trace %s (%s):" % (example_trace["control_id"], example_trace["title"]))
    lines.append("    owner: %s   objectives: %d" % (example_trace["owner"], len(example_trace["objectives"])))
    lines.append("    satisfies frameworks: %s" % ", ".join(example_trace["frameworks_satisfied"]))
    for reached in example_trace["crosswalk_reach"]:
        lines.append("      -> %-16s %s" % (reached["framework"], ", ".join(reached["controls"][:6])))
    if example_trace["mitigates_risk"]:
        lines.append("    mitigates: " + "; ".join("%s ($%s)" % (mitigation["scenario"], format(mitigation["ale_likely"], ","))
                                                for mitigation in example_trace["mitigates_risk"][:4]))
    return "\n".join(lines)


if __name__ == "__main__":
    print(render_text(demo()))
