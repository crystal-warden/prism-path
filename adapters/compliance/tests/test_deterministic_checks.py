# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The honest-hybrid comparator adjudicator: machine-checkable controls resolve from configuration
facts with no model in the loop, and fail closed to the LLM otherwise."""
import deterministic_checks as dc
import compliance_adapter as ca


def _control(cid):
    ca.use_standard("nist_800171_r2")
    return ca.get_control(cid)


def test_fully_met_is_deterministic():
    facts = {"account_lockout_threshold": 5, "account_lockout_enforced": True}
    det = dc.adjudicate_deterministic(_control("3.1.8"), {"facts": facts})
    assert det is not None
    assert det["status"] == "met"
    assert det["unmet_objective_ids"] == []
    assert det["method"] == "deterministic"


def test_partially_met():
    facts = {"account_lockout_threshold": 5, "account_lockout_enforced": False}
    det = dc.adjudicate_deterministic(_control("3.1.8"), {"facts": facts})
    assert det["status"] == "partially-met"
    assert det["unmet_objective_ids"] == ["3.1.8[b]"]


def test_not_met():
    facts = {"account_lockout_threshold": 0, "account_lockout_enforced": False}
    det = dc.adjudicate_deterministic(_control("3.1.8"), {"facts": facts})
    assert det["status"] == "not-met"
    assert set(det["unmet_objective_ids"]) == {"3.1.8[a]", "3.1.8[b]"}


def test_missing_fact_fails_closed():
    # only objective [a]'s fact present; [b] unknown -> abstain (defer), never assume satisfied
    det = dc.adjudicate_deterministic(_control("3.1.8"), {"facts": {"account_lockout_threshold": 5}})
    assert det is None


def test_control_without_checks_defers():
    # 3.1.3 (control the flow of CUI) is prose-judgment, not in the registry
    det = dc.adjudicate_deterministic(_control("3.1.3"), {"facts": {"anything": True}})
    assert det is None


def test_no_facts_defers():
    assert dc.adjudicate_deterministic(_control("3.1.8"), {}) is None
    assert dc.adjudicate_deterministic(_control("3.1.8"), None) is None


def test_mfa_full_control_met():
    facts = {"privileged_accounts_identified": True, "mfa_local_privileged": True,
             "mfa_network_privileged": True, "mfa_network_nonprivileged": True}
    det = dc.adjudicate_deterministic(_control("3.5.3"), {"facts": facts})
    assert det["status"] == "met"
    assert det["method"] == "deterministic"


def test_machine_checkable_predicate():
    assert dc.machine_checkable(_control("3.13.11")) is True   # single objective, registered
    assert dc.machine_checkable(_control("3.1.3")) is False    # prose objectives, not registered


def test_adjudicate_uses_deterministic_without_calling_model(monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("the LLM must not be called when facts fully decide the control")
    monkeypatch.setattr(ca, "_gemma", _boom)
    det = ca.adjudicate(_control("3.13.11"),
                        {"control_id": "3.13.11", "facts": {"fips_validated_cryptography": True}})
    assert det["status"] == "met"
    assert det["method"] == "deterministic"


def test_adjudicate_falls_back_to_model_when_not_checkable(monkeypatch):
    sentinel = {"status": "not-met", "unmet_objective_ids": [], "gap_summary": "from llm"}
    monkeypatch.setattr(ca, "_gemma", lambda *a, **k: sentinel)
    det = ca.adjudicate(_control("3.1.3"), {"control_id": "3.1.3", "evidence": []})
    assert det is sentinel
