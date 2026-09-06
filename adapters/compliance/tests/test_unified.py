# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The unified adjudicator merges config, operational, and undetermined evidence into one per-control
determination, with per-objective provenance and honest INSUFFICIENT."""
import compliance_adapter as ca
import control_tasks as ct
import unified as un


def _c(cid):
    ca.use_standard("nist_800171_r2")
    return ca.get_control(cid)


def test_all_config_control_is_met_from_facts():
    facts = {"account_lockout_threshold": 5, "account_lockout_enforced": True}
    det = un.full_determination(_c("3.1.8"), {"facts": facts})
    assert det["status"] == "met"
    assert det["coverage"]["config"] == ["3.1.8[a]", "3.1.8[b]"]
    assert det["undetermined_objective_ids"] == []
    assert det["by_objective"]["3.1.8[a]"]["by"] == "config"


def test_config_refutation_is_partially_met():
    facts = {"account_lockout_threshold": 5, "account_lockout_enforced": False}
    det = un.full_determination(_c("3.1.8"), {"facts": facts})
    assert det["status"] == "partially-met"
    assert det["unmet_objective_ids"] == ["3.1.8[b]"]


def test_operational_only_control_met_from_completion():
    done = [ct.record_completion("ir-capability-test", "3.6.3", "2026-08-01", "ISSM", "aar.pdf")]
    det = un.full_determination(_c("3.6.3"), {}, completions=done, as_of="2026-09-02")
    assert det["status"] == "met"
    assert det["coverage"]["operational"] == ["3.6.3[a]"]
    assert det["by_objective"]["3.6.3[a]"]["by"] == "operational"


def test_operational_overdue_is_not_met():
    done = [ct.record_completion("ir-capability-test", "3.6.3", "2024-01-01", "ISSM", "aar.pdf")]
    det = un.full_determination(_c("3.6.3"), {}, completions=done, as_of="2026-09-02")
    assert det["status"] == "not-met"
    assert det["unmet_objective_ids"] == ["3.6.3[a]"]


def test_no_covering_evidence_is_insufficient_not_assumed():
    det = un.full_determination(_c("3.6.3"), {})     # no facts, no completions
    assert det["status"] == "insufficient"
    assert det["undetermined_objective_ids"] == ["3.6.3[a]"]
    assert det["unmet_objective_ids"] == []           # undetermined is NOT counted as met


def test_mixed_control_reports_partial_coverage_and_stays_insufficient():
    # 3.11.2: operational task covers [b],[c]; [a] (freq defined) and [d],[e] (scan-on-new) are prose
    done = [ct.record_completion("vulnerability-scan", "3.11.2", "2026-08-20", "eng", "scan.html")]
    det = un.full_determination(_c("3.11.2"), {}, completions=done, as_of="2026-09-02")
    assert det["coverage"]["operational"] == ["3.11.2[b]", "3.11.2[c]"]
    assert set(det["undetermined_objective_ids"]) == {"3.11.2[a]", "3.11.2[d]", "3.11.2[e]"}
    assert det["status"] == "insufficient"            # covered objectives met, but prose ones remain
    assert det["objectives_decided"] == 2
    assert det["objectives_total"] == 5
