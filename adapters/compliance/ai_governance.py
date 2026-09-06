#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""AI governance assessment — run the AI-GOV catalog over an AI-use register.

The AI-GOV catalog (catalog/ai_governance.json) encodes the organizational AI-governance questions
(who uses AI, which tools/processes/vendors, what data, decision impact, human review, high-risk
controls, exceptions, incidents, evidence retention, leadership visibility), structured on the NIST AI
RMF functions. This module assesses them through the same unified determination as every other
framework: the inventory objectives are decided deterministically from the AI-use register (config),
the policy and operating objectives resolve through SOPs, task records, and the LLM, and everything
unproven fails closed to insufficient. Governing the USE of AI with signed, decidable evidence; not
inspecting the model.
"""
import compliance_adapter as _ca
import unified as _un
import ai_register as _reg


def assess(posture, completions=None, as_of=None, use_llm=False):
    """Assess the AI-GOV catalog over an AI-use register posture."""
    _ca.use_standard("ai_governance")
    facts = (posture or {}).get("facts") or {}
    boundary = (posture or {}).get("boundary", "(unspecified)")
    req_base = {"facts": facts, "boundary": boundary}

    controls, tally = [], {}
    by_mech = {"config": 0, "operational": 0, "llm": 0, "undetermined": 0}
    for cid in sorted(_ca._catalog()["controls"]):
        control = _ca.get_control(cid)
        det = _un.full_determination(control, dict(req_base, control_id=cid),
                                     completions=completions, as_of=as_of, use_llm=use_llm)
        tally[det["status"]] = tally.get(det["status"], 0) + 1
        for m, objs in det["coverage"].items():
            if m in by_mech:
                by_mech[m] += len(objs)
        controls.append({"control_id": cid, "title": control["title"], "verdict": det["status"],
                         "coverage": det["coverage"]})
    return {"standard": "ai_governance", "boundary": boundary, "n_controls": len(controls),
            "tally": tally, "by_mechanism": by_mech, "controls": controls,
            "note": "AI governance covers the USE of AI (inventory, approval, human review, exceptions, "
                    "incidents, evidence, oversight), proven with signed, decidable evidence. The "
                    "inventory objectives decide from the AI-use register; policy and operating "
                    "objectives need adopted SOPs and records, and fail closed to insufficient without "
                    "them. Crosswalk to NIST AI RMF / ISO 42001 pending an authoritative source table."}


def demo(use_llm=False):
    return assess(_reg.load_sample("example_org"), as_of="2026-09-03", use_llm=use_llm)


def render_text(r):
    L = ["AI governance assessment  |  boundary: %s" % r["boundary"]]
    L.append("  controls: %d   verdicts: %s" % (r["n_controls"], r["tally"]))
    L.append("  objectives decided by: %s" % r["by_mechanism"])
    for c in r["controls"]:
        cov = ", ".join("%s:%d" % (m, len(o)) for m, o in c["coverage"].items() if o and m != "undetermined")
        L.append("  %-5s %-13s %-34s [%s]" % (c["control_id"], c["verdict"], c["title"][:34], cov or "no config/op evidence"))
    return "\n".join(L)


if __name__ == "__main__":
    print(render_text(demo()))
