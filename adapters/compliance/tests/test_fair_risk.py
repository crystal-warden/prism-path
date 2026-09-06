# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The FAIR risk pillar: vulnerability is driven by the deterministic compliance verdicts, so improving
compliance measurably lowers the annualized loss expectancy, and risk-acceptance is a signed record."""
import json
import os
import pytest
import fair_risk as fr
from prismpath import policy_pack as pp

HERE = os.path.dirname(os.path.abspath(__file__))


def _all_scenario_controls():
    return sorted(list(set(c for s in fr.load_scenarios() for c in s["controls"])))


def _all(status):
    return {c: status for c in _all_scenario_controls()}


@pytest.fixture
def key(tmp_path):
    return pp.keygen(str(tmp_path), "risk")


def test_scenarios_load():
    s = fr.load_scenarios()
    assert len(s) == 15
    assert all(x["controls"] and x["tef"] and x["loss"] for x in s)


def test_all_referenced_controls_exist_in_catalog():
    adapter_dir = os.path.dirname(HERE)
    cat = json.load(open(os.path.join(adapter_dir, "catalog", "nist_800171_r2.json")))["controls"]
    scenarios = fr.load_scenarios()
    for s in scenarios:
        for cid in s["controls"]:
            assert cid in cat, f"Control {cid} in scenario {s['id']} not in NIST 800-171 Rev 2 catalog"

    task_specs = json.load(open(os.path.join(adapter_dir, "task_specs.json")))
    for cid in task_specs:
        if cid.startswith("_") or cid == "AST-3":
            continue
        assert cid in cat, f"Control {cid} in task_specs.json not in NIST 800-171 Rev 2 catalog"



def test_vulnerability_driven_by_verdicts():
    scen = fr.load_scenarios()[0]                                # 5 mitigating controls
    assert fr.vulnerability(scen, _all("met")) == fr.RESIDUAL_VULN     # fully mitigated -> residual
    assert fr.vulnerability(scen, {}) == 1.0                            # nothing met -> full exposure
    partial = {c: "met" for c in scen["controls"][:3]}                 # 3 of 5 met
    assert fr.vulnerability(scen, partial) == round(2 / 5, 4)


def test_partially_met_does_not_mitigate():
    # only 'met' mitigates; partially-met leaves exposure, consistent with the fail-closed system
    scen = fr.load_scenarios()[0]
    assert fr.vulnerability(scen, {c: "partially-met" for c in scen["controls"]}) == 1.0


def test_compliance_reduces_ale():
    scen = fr.load_scenarios()[0]
    hi = fr.ale(scen, {})["likely"]
    lo = fr.ale(scen, _all("met"))["likely"]
    assert lo < hi
    assert lo == round(scen["tef"]["likely"] * fr.RESIDUAL_VULN * scen["loss"]["likely"])


def test_register_aggregate_and_drivers():
    good = fr.risk_register(_all("met"))
    bad = fr.risk_register(_all("not-met"))
    assert bad["aggregate_ale"]["likely"] > good["aggregate_ale"]["likely"]
    assert all(r["unmet_controls"] == [] for r in good["scenarios"])   # nothing driving risk when compliant
    assert all(r["unmet_controls"] for r in bad["scenarios"])          # every scenario driven when not


def test_signed_risk_acceptance(key):
    row = fr.risk_register(_all("not-met"))["scenarios"][0]
    acc = fr.accept_risk(row["id"], row["ale"], "the ISSM", "compensating controls in place",
                         key, "2026-09-03")
    assert fr.verify_acceptance(acc, key["public"]) is True
    tampered = {"record": dict(acc["record"], accepted_ale={"likely": 1}), "receipt": acc["receipt"]}
    assert fr.verify_acceptance(tampered, key["public"]) is False
