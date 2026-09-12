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
    return sorted(os.path.basename(path)[:-5] for path in glob.glob(os.path.join(CROSSWALK_DIR, "*.json")))


def load_crosswalk(name):
    cw = json.load(open(os.path.join(CROSSWALK_DIR, name + ".json")))
    for required_key in ("a", "b", "edges"):
        if required_key not in cw:
            raise ValueError("crosswalk %s missing required key %r" % (name, required_key))
    return cw


def frameworks(cw):
    return (cw["a"], cw["b"])


def _combine(statuses):
    """Fail-closed combine of the source verdicts feeding one target requirement. A missing verdict
    (None) counts as unproven, i.e. insufficient, never met."""
    if not statuses:
        return "insufficient"
    if any(status == "not-met" for status in statuses):
        return "not-met"
    if any(status in (None, "insufficient", "partially-met") for status in statuses):
        return "insufficient"
    return "met"


def propagate(cw, from_fw, verdicts):
    """Propagate verdicts on `from_fw` to the other framework in the crosswalk. Returns per mapped
    target {verdict, from: [source controls]} plus a tally, fail closed. Unmapped targets are omitted."""
    framework_a, framework_b = cw["a"], cw["b"]
    if from_fw == framework_a:
        target_fw, groups = framework_b, {}
        for edge in cw["edges"]:
            for bc in edge["b"]:
                groups.setdefault(bc, set()).add(edge["a"])
    elif from_fw == framework_b:
        target_fw = framework_a
        groups = {edge["a"]: set(edge["b"]) for edge in cw["edges"]}
    else:
        raise ValueError("framework %r not in crosswalk %s (%s <-> %s)" % (from_fw, cw.get("id"), framework_a, framework_b))
    controls, tally = {}, {}
    for tgt, srcs in groups.items():
        verdict = _combine([verdicts.get(source_control) for source_control in sorted(srcs)])
        controls[tgt] = {"verdict": verdict, "from": sorted(srcs)}
        tally[verdict] = tally.get(verdict, 0) + 1
    return {"crosswalk": cw.get("id"), "authority": cw.get("authority"),
            "source_framework": from_fw, "target_framework": target_fw,
            "n_targets": len(controls), "tally": tally, "controls": controls}


def coverage(cw):
    """How much of each side the crosswalk touches, and whether it is complete against a known size."""
    a_ctrls = {edge["a"] for edge in cw["edges"]}
    b_ctrls = {target_control for edge in cw["edges"] for target_control in edge["b"]}
    return {"crosswalk": cw.get("id"), "authority": cw.get("authority"), "complete": cw.get("complete", False),
            "a": cw["a"], "a_controls_mapped": len(a_ctrls),
            "b": cw["b"], "b_controls_mapped": len(b_ctrls), "edges": len(cw["edges"])}


def demo():
    """Assess 800-171 once, then report the result against every crosswalk that starts from it."""
    from adapters.compliance import compliance_adapter as _ca
    from adapters.compliance import unified as _un
    from adapters.compliance import posture_connector as _pc
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


def render_text(report):
    lines = ["Crosswalk propagation from %s (%d controls assessed):" % (report["source"], report["assessed"])]
    for framework_report in report["reports"]:
        cov = framework_report["coverage"]
        lines.append("  -> %-18s %d targets  %s  [%s%s]"
                     % (framework_report["to"], framework_report["n_targets"], framework_report["tally"],
                        "complete" if cov["complete"] else "partial",
                        "" if cov["complete"] else " %d/%d mapped" % (cov["a_controls_mapped"], cov["b_controls_mapped"])))
    return "\n".join(lines)


if __name__ == "__main__":
    print(render_text(demo()))
