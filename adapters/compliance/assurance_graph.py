#!/usr/bin/env python3
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
import compliance_adapter as _ca
import crosswalk as _cw
import fair_risk as _fr

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
        x = _cw.load_crosswalk(name)
        if std == x["a"]:
            tgts = sorted({b for e in x["edges"] if e["a"] == control_id for b in e["b"]})
            if tgts:
                reach.append({"framework": x["b"], "controls": tgts, "crosswalk": name, "direction": "forward"})
        elif std == x["b"]:
            srcs = sorted({e["a"] for e in x["edges"] if control_id in e["b"]})
            if srcs:
                reach.append({"framework": x["a"], "controls": srcs, "crosswalk": name, "direction": "reverse"})
    scen = [{"scenario": s["name"], "id": s["id"], "ale_likely": s["loss"]["likely"]}
            for s in _fr.load_scenarios() if control_id in s.get("controls", [])]
    return {"standard": std, "control_id": control_id, "title": control["title"],
            "owner": _owner_of(control), "objectives": [o["id"] for o in control.get("objectives", [])],
            "crosswalk_reach": reach, "mitigates_risk": scen,
            "frameworks_satisfied": sorted({r["framework"] for r in reach})}


def graph_summary(standard="nist_800171_r2"):
    """Node and edge counts of the connectivity graph anchored on one standard."""
    _ca.use_standard(standard)
    controls = _ca._catalog()["controls"]
    n_obj = sum(len(c.get("objectives", [])) for c in controls.values())
    xw_edges, frameworks = 0, set()
    for name in _cw.list_crosswalks():
        x = _cw.load_crosswalk(name)
        if standard in (x["a"], x["b"]):
            frameworks.add(x["b"] if standard == x["a"] else x["a"])
            xw_edges += sum(len(e["b"]) for e in x["edges"])
    scenarios = _fr.load_scenarios()
    risk_links = sum(len(s.get("controls", [])) for s in scenarios)
    owners = sorted({_owner_of({"family_name": c.get("family_name")}) for c in controls.values()})
    return {"standard": standard,
            "nodes": {"controls": len(controls), "objectives": n_obj,
                      "frameworks_linked": sorted(frameworks), "risk_scenarios": len(scenarios)},
            "edges": {"crosswalk_links": xw_edges, "risk_links": risk_links},
            "owners": owners}


def demo():
    return {"summary": graph_summary("nist_800171_r2"), "example_trace": trace("3.1.1", "nist_800171_r2")}


def render_text(d):
    s, t = d["summary"], d["example_trace"]
    L = ["Assurance connectivity graph (anchored on %s):" % s["standard"]]
    L.append("  nodes: %d controls, %d objectives, %d risk scenarios; frameworks linked: %s"
             % (s["nodes"]["controls"], s["nodes"]["objectives"], s["nodes"]["risk_scenarios"],
                ", ".join(s["nodes"]["frameworks_linked"])))
    L.append("  edges: %d crosswalk links, %d control->risk links; owners: %s"
             % (s["edges"]["crosswalk_links"], s["edges"]["risk_links"], ", ".join(s["owners"])))
    L.append("")
    L.append("  trace %s (%s):" % (t["control_id"], t["title"]))
    L.append("    owner: %s   objectives: %d" % (t["owner"], len(t["objectives"])))
    L.append("    satisfies frameworks: %s" % ", ".join(t["frameworks_satisfied"]))
    for r in t["crosswalk_reach"]:
        L.append("      -> %-16s %s" % (r["framework"], ", ".join(r["controls"][:6])))
    if t["mitigates_risk"]:
        L.append("    mitigates: " + "; ".join("%s ($%s)" % (m["scenario"], format(m["ale_likely"], ","))
                                                for m in t["mitigates_risk"][:4]))
    return "\n".join(L)


if __name__ == "__main__":
    print(render_text(demo()))
