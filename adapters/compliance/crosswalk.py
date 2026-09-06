#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Crosswalk engine — assess once, report to many frameworks.

A crosswalk is authoritative mapping data (crosswalks/*.json) between two control frameworks: which
requirements of framework A correspond to which requirements of framework B. Given verdicts on one
framework, the engine PROPAGATES them to the other, FAIL CLOSED:

  a target requirement is met only when EVERY source requirement mapped to it is met; a single not-met
  makes it not-met; anything missing or unproven makes it insufficient.

So a propagated verdict is only ever as strong as the mapping and the source evidence, and the engine
says which source controls each result rests on. Mappings are DATA with a stated authority, never
model-generated; the engine trusts the mapping file and does no adjudication of its own. A crosswalk
may be partial (not every target requirement is mapped); propagation reports only the mapped targets,
so partial coverage is visible rather than silently assumed complete.
"""
import os
import json
import glob

HERE = os.path.dirname(os.path.abspath(__file__))
CROSSWALK_DIR = os.path.join(HERE, "crosswalks")


def list_crosswalks():
    return sorted(os.path.basename(p)[:-5] for p in glob.glob(os.path.join(CROSSWALK_DIR, "*.json")))


def load_crosswalk(name):
    cw = json.load(open(os.path.join(CROSSWALK_DIR, name + ".json")))
    for k in ("a", "b", "edges"):
        if k not in cw:
            raise ValueError("crosswalk %s missing required key %r" % (name, k))
    return cw


def frameworks(cw):
    return (cw["a"], cw["b"])


def _combine(statuses):
    """Fail-closed combine of the source verdicts feeding one target requirement. A missing verdict
    (None) counts as unproven, i.e. insufficient, never met."""
    if not statuses:
        return "insufficient"
    if any(s == "not-met" for s in statuses):
        return "not-met"
    if any(s in (None, "insufficient", "partially-met") for s in statuses):
        return "insufficient"
    return "met"


def propagate(cw, from_fw, verdicts):
    """Propagate verdicts on `from_fw` to the other framework in the crosswalk. Returns per mapped
    target {verdict, from: [source controls]} plus a tally, fail closed. Unmapped targets are omitted."""
    a, b = cw["a"], cw["b"]
    if from_fw == a:
        target_fw, groups = b, {}
        for e in cw["edges"]:
            for bc in e["b"]:
                groups.setdefault(bc, set()).add(e["a"])
    elif from_fw == b:
        target_fw = a
        groups = {e["a"]: set(e["b"]) for e in cw["edges"]}
    else:
        raise ValueError("framework %r not in crosswalk %s (%s <-> %s)" % (from_fw, cw.get("id"), a, b))
    controls, tally = {}, {}
    for tgt, srcs in groups.items():
        v = _combine([verdicts.get(s) for s in sorted(srcs)])
        controls[tgt] = {"verdict": v, "from": sorted(srcs)}
        tally[v] = tally.get(v, 0) + 1
    return {"crosswalk": cw.get("id"), "authority": cw.get("authority"),
            "source_framework": from_fw, "target_framework": target_fw,
            "n_targets": len(controls), "tally": tally, "controls": controls}


def coverage(cw):
    """How much of each side the crosswalk touches, and whether it is complete against a known size."""
    a_ctrls = {e["a"] for e in cw["edges"]}
    b_ctrls = {b for e in cw["edges"] for b in e["b"]}
    return {"crosswalk": cw.get("id"), "authority": cw.get("authority"), "complete": cw.get("complete", False),
            "a": cw["a"], "a_controls_mapped": len(a_ctrls),
            "b": cw["b"], "b_controls_mapped": len(b_ctrls), "edges": len(cw["edges"])}


def demo():
    """Assess 800-171 once, then report the result against every crosswalk that starts from it."""
    import compliance_adapter as _ca
    import unified as _un
    import posture_connector as _pc
    _ca.use_standard("nist_800171_r2")
    posture = _pc.load_sample("example_host")
    req_base = {"facts": posture.get("facts", {}), "boundary": posture.get("boundary")}
    verdicts = {}
    for cid in _ca._catalog()["controls"]:
        det = _un.full_determination(_ca.get_control(cid), dict(req_base, control_id=cid))
        verdicts[cid] = det["status"]
    out = {"source": "nist_800171_r2", "assessed": len(verdicts), "reports": []}
    for name in list_crosswalks():
        cw = load_crosswalk(name)
        if "nist_800171_r2" in (cw["a"], cw["b"]):
            rep = propagate(cw, "nist_800171_r2", verdicts)
            out["reports"].append({"to": rep["target_framework"], "crosswalk": name,
                                   "n_targets": rep["n_targets"], "tally": rep["tally"],
                                   "coverage": coverage(cw)})
    return out


def render_text(d):
    L = ["Crosswalk propagation from %s (%d controls assessed):" % (d["source"], d["assessed"])]
    for r in d["reports"]:
        cov = r["coverage"]
        L.append("  -> %-18s %d targets  %s  [%s%s]"
                 % (r["to"], r["n_targets"], r["tally"],
                    "complete" if cov["complete"] else "partial",
                    "" if cov["complete"] else " %d/%d mapped" % (cov["a_controls_mapped"], cov["b_controls_mapped"])))
    return "\n".join(L)


if __name__ == "__main__":
    print(render_text(demo()))
