# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The LLM path in the unified adjudicator: prose objectives no other mechanism covers are resolved by
the escalation-default LLM adjudicator, config and operational verdicts still win, and an unreachable
model fails closed rather than crashing or being assumed."""
import pytest
import compliance_adapter as ca
import unified as un


def _c(cid):
    ca.use_standard("nist_800171_r2")
    return ca.get_control(cid)


def test_llm_resolves_undetermined_prose_objectives(monkeypatch):
    monkeypatch.setattr(ca, "adjudicate",
                        lambda control, req: {"status": "met", "unmet_objective_ids": [], "gap_summary": "llm"})
    control = _c("3.1.3")   # control the flow of CUI: prose, not machine-checkable
    det = un.full_determination(control, {"evidence": []}, use_llm=True)
    assert det["status"] == "met"
    assert det["undetermined_objective_ids"] == []
    assert det["coverage"]["llm"] == [o["id"] for o in control["objectives"]]
    assert all(v["by"] == "llm" for v in det["by_objective"].values())


def test_llm_partial_verdict(monkeypatch):
    objs = [o["id"] for o in _c("3.1.3")["objectives"]]
    monkeypatch.setattr(ca, "adjudicate",
                        lambda control, req: {"status": "partially-met", "unmet_objective_ids": [objs[0]], "gap_summary": "x"})
    det = un.full_determination(_c("3.1.3"), {"evidence": []}, use_llm=True)
    assert det["status"] == "partially-met"
    assert det["unmet_objective_ids"] == [objs[0]]


def test_llm_unreachable_fails_closed(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("model endpoint down")
    monkeypatch.setattr(ca, "adjudicate", boom)
    det = un.full_determination(_c("3.1.3"), {"evidence": []}, use_llm=True)
    assert det["status"] == "insufficient"                  # not crashed, not assumed
    assert det["coverage"]["llm"] == []


def test_config_wins_llm_not_consulted(monkeypatch):
    calls = {"n": 0}
    def spy(*a, **k):
        calls["n"] += 1
        return {"status": "not-met", "unmet_objective_ids": ["3.1.8[a]", "3.1.8[b]"], "gap_summary": "x"}
    monkeypatch.setattr(ca, "adjudicate", spy)
    facts = {"account_lockout_threshold": 5, "account_lockout_enforced": True}
    det = un.full_determination(_c("3.1.8"), {"facts": facts}, use_llm=True)
    assert det["status"] == "met"       # decided by config
    assert calls["n"] == 0              # no undetermined objectives, so the LLM is never called


@pytest.mark.gemma
def test_llm_live_resolves_a_prose_control():
    """Runs against a live gemma at PRISMPATH_LLM_ENDPOINT (pytest -m gemma)."""
    control = _c("3.1.3")
    req = {"control_id": "3.1.3", "boundary": "the CUI enclave", "evidence": [
        {"type": "policy", "text": "An information flow control policy defines approved sources and "
         "destinations for CUI between networks and enforces those paths at the firewall, which is "
         "configured to deny by default."}]}
    det = un.full_determination(control, req, use_llm=True)
    assert det["undetermined_objective_ids"] == []          # the LLM decided every remaining objective
    assert det["status"] in ("met", "partially-met", "not-met")
    assert det["coverage"]["llm"]
