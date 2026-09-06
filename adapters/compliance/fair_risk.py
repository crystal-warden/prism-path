#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""FAIR risk pillar — the R in GRC, driven by the deterministic compliance verdicts.

Risk is estimative, not deterministic, and this module does not pretend otherwise: the threat event
frequency and the loss magnitude are calibrated estimates (ranges). What PrismPath makes provable is
the PROCESS. Each scenario's mitigating controls are explicit, the vulnerability factor is COMPUTED
from the deterministic compliance verdicts (the more mitigating controls are unmet, the more exposed
the scenario), the risk is a reproducible function of those inputs, and a risk-acceptance decision
carries a signed receipt with an owner, a rationale, and a date.

FAIR: Annualized Loss Expectancy = Loss Event Frequency x Loss Magnitude, where
LEF = Threat Event Frequency x Vulnerability. Vulnerability here is a function of the control posture,
so improving compliance measurably reduces risk, and a control gap shows up as exposure in dollars.
"""
import os
import json
import ai_safety_receipts as _sig   # reuse the engine's Ed25519 receipt signing (generic over any record)

HERE = os.path.dirname(os.path.abspath(__file__))
SCEN_PATH = os.path.join(HERE, "risk_scenarios.json")
RESIDUAL_VULN = 0.05   # residual exposure remains even when every mitigating control is met


def load_scenarios():
    return json.load(open(SCEN_PATH))["scenarios"]


def verdicts_from_results(results):
    """Convenience: build {control_id: status} from a posture_connector / assessment result list."""
    return {r["control_id"]: r["status"] for r in results}


def vulnerability(scenario, verdicts):
    """Vulnerability (0..1) driven by the compliance posture of the scenario's mitigating controls. A
    control mitigates only when its verdict is exactly 'met'; anything else (not-met, partially-met,
    insufficient, or absent) leaves the scenario exposed. A residual floor applies even at full
    compliance."""
    controls = scenario.get("controls", [])
    if not controls:
        return 1.0
    unmet = sum(1 for c in controls if verdicts.get(c) != "met")
    return max(RESIDUAL_VULN, round(unmet / len(controls), 4))


def ale(scenario, verdicts):
    """Annualized Loss Expectancy range (min/likely/max) = TEF x Vulnerability x Loss Magnitude."""
    v = vulnerability(scenario, verdicts)
    tef, loss = scenario["tef"], scenario["loss"]
    return {k: round(tef[k] * v * loss[k]) for k in ("min", "likely", "max")}


def risk_register(verdicts, scenarios=None):
    """Per-scenario ALE plus the aggregate, and the mitigating controls that are unmet (the drivers).
    verdicts: {control_id: status}. Reproducible given the same verdicts."""
    scenarios = scenarios if scenarios is not None else load_scenarios()
    rows = []
    for s in scenarios:
        rows.append({"id": s["id"], "name": s["name"],
                     "vulnerability": vulnerability(s, verdicts), "ale": ale(s, verdicts),
                     "unmet_controls": sorted(c for c in s.get("controls", []) if verdicts.get(c) != "met")})
    agg = {k: sum(r["ale"][k] for r in rows) for k in ("min", "likely", "max")}
    return {"scenarios": rows, "aggregate_ale": agg,
            "note": "ALE is an estimate; TEF and loss magnitude require calibration. Vulnerability is "
                    "computed from the deterministic compliance verdicts, so the ranking is defensible "
                    "even though the dollar figures are estimates."}


def accept_risk(scenario_id, accepted_ale, actor, rationale, key, accepted_on):
    """A signed risk-acceptance decision: who accepted which residual risk, why, and when, bound under
    Ed25519 so the acceptance is a non-repudiable record rather than a spreadsheet cell."""
    record = {"kind": "risk-acceptance", "scenario_id": scenario_id, "accepted_ale": accepted_ale,
              "actor": actor, "rationale": rationale, "accepted_on": accepted_on}
    return {"record": record, "receipt": _sig.sign_receipt(record, key, accepted_on)}


def verify_acceptance(acceptance, pub_path):
    """Verify a risk-acceptance signature and that the record was not altered after acceptance."""
    return _sig.verify_receipt(acceptance["receipt"], acceptance["record"], pub_path)
