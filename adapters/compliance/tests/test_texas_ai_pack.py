# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Texas AI Governance Pack (TRAIGA + SB 1964): catalog, applicability scoping, the config-enforced
objectives, crosswalk integrity, and policy-template coverage."""
import json, glob, os
import compliance_adapter as ca
import deterministic_checks as dc

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _std():
    ca.use_standard("texas_ai")


def test_catalog_registers_and_loads():
    _std()
    assert ca.active_standard() == "texas_ai"
    meta = ca.list_standards()["texas_ai"]
    assert meta["controls"] == 21 and meta["families"] == 9


def test_applicability_scoping_matches_statutory_reach():
    _std()
    counts = {a: ca.applicability_determination(a)["counts"]["applicable"]
              for a in ("commercial", "healthcare", "government", "gov_vendor")}
    # SB 1964 is government-heavy; TRAIGA's private-sector reach is narrow
    assert counts == {"commercial": 8, "healthcare": 6, "government": 20, "gov_vendor": 15}
    # every N/A carries a written justification
    na = ca.applicability_determination("commercial")["not_applicable"]
    assert na and all(x["status"] == "not-applicable" and x["reason"] for x in na)


def test_unknown_actor_is_rejected():
    _std()
    try:
        ca.applicable_controls("not-an-actor")
        assert False, "expected KeyError"
    except KeyError:
        pass


def test_seven_config_objectives_are_machine_checkable_and_scanned():
    _std()
    cfg = ["TX-PROHIB-1[b]", "TX-PROHIB-3[b]", "TX-DISC-1[b]", "TX-DISC-2[b]",
           "TX-OVS-1[b]", "TX-CHG-2[a]", "TX-CHG-2[b]"]
    for oid in cfg:
        assert oid in dc.CHECKS, f"{oid} not machine-checkable"
        assert dc.evidence_class(oid) == "scanned", f"{oid} should be tool-verifiable"
    # TX-CHG-2 (both objectives config) resolves deterministically to met
    facts = {dc.FACT_KEYS[o]: True for o in cfg}
    res = dc.adjudicate_deterministic(ca.get_control("TX-CHG-2"), {"facts": facts})
    assert res["status"] == "met" and res["evidence"]["class"] == "scanned"


def test_crosswalk_references_are_valid_both_sides():
    tx = json.load(open(os.path.join(HERE, "catalog", "texas_ai.json")))["controls"]
    aig = json.load(open(os.path.join(HERE, "catalog", "ai_governance.json")))["controls"]
    cw = json.load(open(os.path.join(HERE, "crosswalks", "texas_ai__ai_governance.json")))
    covered = set()
    for e in cw["edges"]:
        assert e["a"] in tx, f"bad source {e['a']}"
        covered.add(e["a"])
        for b in e["b"]:
            assert b in aig, f"bad target {b}"
    assert covered == set(tx), "every Texas control should map to the safe-harbor path"


def test_policy_specs_reference_real_objectives():
    tx = json.load(open(os.path.join(HERE, "catalog", "texas_ai.json")))["controls"]
    allobj = {o["id"] for c in tx.values() for o in c["objectives"]}
    specs = glob.glob(os.path.join(HERE, "sop_specs", "texas_*.json"))
    assert specs, "expected Texas SOP specs"
    for f in specs:
        s = json.load(open(f))
        assert s["standard"] == "texas_ai"
        for c in s["controls"]:
            assert c in tx, f"{s['doc_id']} references unknown control {c}"
        for sec in s["sections"]:
            for oid in sec.get("objectives", []):
                assert oid in allobj, f"{s['doc_id']} references unknown objective {oid}"


def test_runtime_connector_derives_config_facts_from_real_engine_runs():
    import texas_ai_connector as tx
    facts, receipts = tx.derive_facts()
    # three representative outcomes actually came out of the real engine
    stops = {r["stopped"] for r in receipts}
    assert {"terminal", "needs_human", "stuck"} <= stops
    # and they derive the four decision-control config facts (not hand-typed)
    assert facts["human_oversight_escalation_enforced"] is True   # a needs_human receipt exists
    assert facts["prohibited_use_refusal_enforced"] is True       # a stuck (default-deny) receipt exists
    assert facts["decision_version_attribution"] is True
    assert facts["governing_version_authorized"] is True


def test_standard_notice_marks_unvalidated():
    ca.use_standard("texas_ai")
    n = ca.standard_notice()
    assert n["validated"] is False and "REVIEW ASSISTANCE" in n["notice"]


def test_documented_plane_is_complete():
    """Every documented objective in the catalog has a policy template covering it (the pack ships a
    template for all of its documentation duties, not a subset)."""
    tx = json.load(open(os.path.join(HERE, "catalog", "texas_ai.json")))["controls"]
    docobj = {o["id"] for c in tx.values() for o in c["objectives"] if o["mechanism"] == "documented"}
    covered = set()
    for f in glob.glob(os.path.join(HERE, "sop_specs", "texas_*.json")):
        for sec in json.load(open(f))["sections"]:
            covered |= set(sec.get("objectives", []))
    assert docobj <= covered, f"documented objectives without a template: {sorted(docobj - covered)}"
