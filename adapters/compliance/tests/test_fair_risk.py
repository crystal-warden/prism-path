# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The FAIR risk pillar: vulnerability is driven by the deterministic compliance verdicts, so improving
compliance measurably lowers the annualized loss expectancy, and risk-acceptance is a signed record."""
import pytest
import fair_risk as fr
from prismpath import policy_pack as pp

ALL_CONTROLS = ["3.5.3", "3.1.8", "3.5.7", "3.5.8", "3.1.1", "3.14.4", "3.14.5", "3.13.16", "3.6.1",
                "3.13.6", "3.13.1", "3.1.5", "3.1.19", "3.8.7", "3.9.1", "3.3.3"]


@pytest.fixture
def key(tmp_path):
    return pp.keygen(str(tmp_path), "risk")


def _all(status):
    return {c: status for c in ALL_CONTROLS}


def test_scenarios_load():
    s = fr.load_scenarios()
    assert len(s) >= 4
    assert all(x["controls"] and x["tef"] and x["loss"] for x in s)


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
