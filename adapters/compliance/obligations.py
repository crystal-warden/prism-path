#!/usr/bin/env python3
"""Obligations layer — the external drivers at the top of the Compliance & Control layer.

The alignment model maps laws, regulations, contracts, standards, and policies DOWN into controls. This
module models those obligations explicitly and links each to the controls it requires (through a
framework and a scope), so the chain runs obligation -> required controls -> live verdicts -> whether the
obligation is satisfied, and a failing control names every obligation it breaches. Obligations are the
'why' above the controls: not "is 3.1.1 met" but "are we meeting DFARS 252.204-7012, and if not, which
controls are the breach." Because the required evidence can arrive through the crosswalks, an obligation
against SOC 2 can be answered from the 800-171 assessment — assess once, satisfy many obligations.

Obligations are organization-specific (the tenant's contracts and policies); a realistic DIB set drives
the demo and tests.
"""
import compliance_adapter as _ca
import cmmc as _cmmc

# each obligation: what imposes it, the citation, and what it REQUIRES (a framework + a scope).
# scope: "all" (every control of the framework) | "cmmc_l1" | "cmmc_l2" | an explicit list of control ids.
OBLIGATIONS = [
    {"id": "DFARS-7012", "name": "Safeguarding Covered Defense Information", "type": "regulation",
     "citation": "DFARS 252.204-7012", "imposed_by": "DoD contract",
     "requires": {"framework": "nist_800171_r2", "scope": "all"}},
    {"id": "DFARS-7019", "name": "NIST SP 800-171 DoD Assessment Requirements", "type": "regulation",
     "citation": "DFARS 252.204-7019", "imposed_by": "DoD contract",
     "requires": {"framework": "nist_800171_r2", "scope": "all"}},
    {"id": "DFARS-7021", "name": "CMMC Level 2 Requirement", "type": "regulation",
     "citation": "DFARS 252.204-7021 / 32 CFR 170", "imposed_by": "DoD contract",
     "requires": {"framework": "nist_800171_r2", "scope": "cmmc_l2"}},
    {"id": "FAR-52.204-21", "name": "Basic Safeguarding of Covered Contractor Information Systems",
     "type": "regulation", "citation": "FAR 52.204-21", "imposed_by": "Federal contract",
     "requires": {"framework": "nist_800171_r2", "scope": "cmmc_l1"}},
    {"id": "CONTRACT-SOC2", "name": "Prime contractor SOC 2 flow-down", "type": "contract",
     "citation": "Prime subcontract, Exhibit C", "imposed_by": "Prime contractor",
     "requires": {"framework": "soc2_tsc", "scope": "all"}},
    {"id": "POLICY-AI-AUP", "name": "Internal AI Acceptable Use and Governance Policy", "type": "policy",
     "citation": "CW-POL-AI-001", "imposed_by": "Crystal Warden management",
     "requires": {"framework": "ai_governance", "scope": "all"}},
]


def _required_controls(req):
    """Resolve an obligation's 'requires' spec into (framework, [control ids])."""
    fw, scope = req["framework"], req["scope"]
    prev = _ca.active_standard()
    _ca.use_standard(fw)
    if scope == "cmmc_l1":
        ctrls = list(_cmmc.L1_CONTROLS)
    elif scope in ("all", "cmmc_l2"):                 # L2 == the full Rev 2 set
        ctrls = sorted(_ca._catalog()["controls"])
    elif isinstance(scope, list):
        ctrls = list(scope)
    else:
        ctrls = []
    _ca.use_standard(prev)
    return fw, ctrls


def obligation_status(obligation, verdicts_by_framework):
    """Resolve the obligation's required controls and report whether it is satisfied by the live verdicts,
    naming the controls that breach it. verdicts_by_framework: {framework: {control_id: status}}."""
    fw, ctrls = _required_controls(obligation["requires"])
    verdicts = verdicts_by_framework.get(fw, {})
    breaching = sorted(c for c in ctrls if verdicts.get(c) != "met")
    return {"obligation": obligation["id"], "name": obligation["name"], "type": obligation["type"],
            "citation": obligation["citation"], "imposed_by": obligation["imposed_by"],
            "framework": fw, "required_controls": len(ctrls), "met": len(ctrls) - len(breaching),
            "status": "met" if not breaching else "not-met",
            "breaching_controls": breaching,
            "evidence_present": bool(verdicts)}


def assess_obligations(verdicts_by_framework, obligations=None):
    """Every obligation's status plus a rollup. One assessment's verdicts (and their crosswalk
    propagations) can satisfy obligations across several frameworks."""
    obligations = obligations if obligations is not None else OBLIGATIONS
    rows = [obligation_status(o, verdicts_by_framework) for o in obligations]
    met = sum(1 for r in rows if r["status"] == "met")
    return {"n_obligations": len(rows), "met": met, "breached": len(rows) - met, "obligations": rows,
            "note": "An obligation is met only when every control it requires is met. Required evidence "
                    "may arrive directly or through a crosswalk (e.g. a SOC 2 obligation answered from the "
                    "800-171 assessment), so one assessment can satisfy obligations across frameworks."}


def breaches_for_control(control_id, obligations=None):
    """Reverse view: which obligations does this single 800-171 control participate in (so a failing
    control shows the obligations at risk)."""
    obligations = obligations if obligations is not None else OBLIGATIONS
    out = []
    for o in obligations:
        fw, ctrls = _required_controls(o["requires"])
        if fw == "nist_800171_r2" and control_id in ctrls:
            out.append({"obligation": o["id"], "citation": o["citation"]})
    return out


def demo(use_llm=False):
    """Build one integrated picture: assess 800-171, propagate to SOC 2 via the crosswalk, assess AI
    governance from its register, then check every obligation against that connected evidence."""
    import unified as _un
    import posture_connector as _pc
    import crosswalk as _cw
    import ai_governance as _aig
    import ai_register as _reg
    _ca.use_standard("nist_800171_r2")
    posture = _pc.load_sample("example_host")
    req_base = {"facts": posture.get("facts", {}), "boundary": posture.get("boundary")}
    v171 = {cid: _un.full_determination(_ca.get_control(cid), dict(req_base, control_id=cid))["status"]
            for cid in _ca._catalog()["controls"]}
    soc2 = _cw.propagate(_cw.load_crosswalk("nist_800171_r2__soc2_tsc"), "nist_800171_r2", v171)
    vsoc2 = {c: v["verdict"] for c, v in soc2["controls"].items()}
    aig = _aig.assess(_reg.load_sample("example_org"))
    vaig = {c["control_id"]: c["verdict"] for c in aig["controls"]}
    _ca.use_standard("nist_800171_r2")
    return assess_obligations({"nist_800171_r2": v171, "soc2_tsc": vsoc2, "ai_governance": vaig})


def render_text(r):
    L = ["Obligations  |  met: %d/%d" % (r["met"], r["n_obligations"])]
    for o in r["obligations"]:
        flag = "MET" if o["status"] == "met" else "BREACHED (%d of %d controls open)" % (
            o["required_controls"] - o["met"], o["required_controls"])
        L.append("  %-14s %-8s %-30s %s" % (o["citation"], o["type"], o["name"][:30], flag))
    return "\n".join(L)


if __name__ == "__main__":
    print(render_text(demo()))
