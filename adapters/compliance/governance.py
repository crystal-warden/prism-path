#!/usr/bin/env python3
"""Governance & Direction layer — the top of the GRC Alignment Model.

The model's top layer links organizational objectives, risk appetite, and oversight to the controls
below, so the assurance chain runs strategy-down: an objective -> the risk scenarios that threaten it ->
the controls that mitigate them -> the live verdicts -> the resulting dollar exposure -> whether that
exposure sits inside the risk appetite the organization set. This closes the loop the rest of the
platform leaves open: control verdicts stop being a compliance score and become "is this business
objective within the risk we agreed to accept, and what is driving it if not."

Objectives and appetite are organization-specific (the tenant supplies them, and the board owns the
appetite); a realistic sample drives the demo and tests. Exposure is computed from the FAIR scenarios
and the live control verdicts, so improving the controls measurably moves an objective back inside
appetite.
"""
import fair_risk as _fr

# Each objective: what the organization is trying to achieve, who owns it, the risk scenarios that
# threaten it, and the risk appetite = the maximum annual loss expectancy (likely) the board will accept.
ORG_OBJECTIVES = [
    {"id": "OBJ-1", "statement": "Protect CUI and retain DoD contract eligibility", "category": "strategic",
     "owner": "CEO / ISSM", "appetite_ale": 250000,
     "threatened_by": ["cui-credential-exfil", "cui-at-rest-disclosure", "unauthorized-network-access",
                       "insider-misuse", "privileged-account-misuse"]},
    {"id": "OBJ-2", "statement": "Maintain operational resilience and system availability", "category": "operational",
     "owner": "COO / Operations", "appetite_ale": 500000,
     "threatened_by": ["ransomware", "backup-recovery-failure", "unpatched-vulnerability-exploitation"]},
    {"id": "OBJ-3", "statement": "Secure the supply chain and third-party dependencies", "category": "strategic",
     "owner": "CISO / Procurement", "appetite_ale": 200000,
     "threatened_by": ["supply-chain-compromise", "cloud-misconfiguration-exposure", "maintenance-tool-data-leakage"]},
    {"id": "OBJ-4", "statement": "Protect the network perimeter and remote access", "category": "operational",
     "owner": "CISO / Network Engineering", "appetite_ale": 300000,
     "threatened_by": ["remote-access-compromise", "rogue-wireless-access-point", "phishing-bec-compromise",
                       "physical-intrusion-enclave"]},
]


def _scenarios_by_id():
    return {s["id"]: s for s in _fr.load_scenarios()}


def objective_posture(objective, verdicts, scen_index=None):
    """One objective's risk posture: the threatening scenarios and their current ALE (driven by the live
    verdicts), the total exposure, whether it is within the appetite the organization set, and the unmet
    controls driving it. Strategy-down: objective -> risk -> control."""
    scen_index = scen_index if scen_index is not None else _scenarios_by_id()
    rows = []
    for sid in objective["threatened_by"]:
        s = scen_index.get(sid)
        if not s:
            continue
        rows.append({"scenario": sid, "name": s["name"], "ale_likely": _fr.ale(s, verdicts)["likely"],
                     "unmet_controls": sorted(c for c in s.get("controls", []) if verdicts.get(c) != "met")})
    exposure = sum(r["ale_likely"] for r in rows)
    appetite = objective["appetite_ale"]
    return {"objective": objective["id"], "statement": objective["statement"],
            "category": objective["category"], "owner": objective["owner"],
            "appetite_ale": appetite, "current_exposure": exposure,
            "within_appetite": exposure <= appetite, "over_by": max(0, exposure - appetite),
            "scenarios": sorted(rows, key=lambda r: -r["ale_likely"]),
            "driving_controls": sorted({c for r in rows for c in r["unmet_controls"]})}


def assess_governance(verdicts, objectives=None):
    """Every objective's posture plus a portfolio rollup, grounded in the live control verdicts."""
    objectives = objectives if objectives is not None else ORG_OBJECTIVES
    idx = _scenarios_by_id()
    postures = [objective_posture(o, verdicts, idx) for o in objectives]
    within = sum(1 for p in postures if p["within_appetite"])
    return {"n_objectives": len(postures), "within_appetite": within,
            "over_appetite": len(postures) - within, "objectives": postures,
            "note": "Exposure is the summed likely ALE of the scenarios threatening each objective, driven "
                    "by the live control verdicts; an objective is over appetite when its exposure exceeds "
                    "the tolerance the organization set. Scenarios can threaten more than one objective, so "
                    "per-objective exposures are not additive across the portfolio."}


def demo(use_llm=False):
    import compliance_adapter as _ca
    import unified as _un
    import posture_connector as _pc
    _ca.use_standard("nist_800171_r2")
    posture = _pc.load_sample("example_host")
    req_base = {"facts": posture.get("facts", {}), "boundary": posture.get("boundary")}
    verdicts = {cid: _un.full_determination(_ca.get_control(cid), dict(req_base, control_id=cid))["status"]
                for cid in _ca._catalog()["controls"]}
    return assess_governance(verdicts)


def render_text(r):
    L = ["Governance & Direction  |  objectives within appetite: %d/%d"
         % (r["within_appetite"], r["n_objectives"])]
    for p in r["objectives"]:
        flag = "WITHIN" if p["within_appetite"] else "OVER by $%s" % format(p["over_by"], ",")
        L.append("  %s %-52s %s" % (p["objective"], p["statement"][:52], p["category"]))
        L.append("      owner: %-26s exposure $%-10s appetite $%-9s  -> %s"
                 % (p["owner"], format(p["current_exposure"], ","), format(p["appetite_ale"], ","), flag))
        if not p["within_appetite"]:
            top = p["scenarios"][0]
            L.append("      top driver: %s ($%s)  unmet controls: %s"
                     % (top["name"], format(top["ale_likely"], ","), ", ".join(p["driving_controls"][:8])))
    return "\n".join(L)


if __name__ == "__main__":
    print(render_text(demo()))
