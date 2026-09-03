#!/usr/bin/env python3
"""AI-safety-testing support — the model-version binding and safety-posture assembly.

The AI-safety catalog (catalog/ai_safety_testing.json) is assessed by the SAME engine as 800-171: its
objectives are graded by the deterministic comparator from a safety-testing posture. Most facts are
declared pipeline capabilities (fingerprinting, signing, anchoring, continuous evaluation). Two facts
are COMPUTED here from the version-determination ledger, because the standout evidence question is Q1:
was the model retested after every change?

version_binding answers that provably: given the model versions and the safety-test determinations
bound to a version hash, it reports which deployed versions have no determination (the gap). Nothing is
assumed. A deployed version with no bound determination is a gap, full stop.
"""
import compliance_adapter as _ca
import posture_connector as _pc
import ai_safety_receipts as _r
import control_tasks as _ct

STANDARD = "ai_safety_testing"


def version_binding(versions, determinations):
    """versions: [{version_hash, deployed?, current?}]. determinations: [{version_hash, ...}] (safety
    results bound to a model version). Returns the retest-coverage picture."""
    bound = {d.get("version_hash") for d in determinations}
    deployed = [v for v in versions if v.get("deployed")]
    unretested = [v["version_hash"] for v in deployed if v.get("version_hash") not in bound]
    current = next((v for v in versions if v.get("current")), None)
    current_hash = current.get("version_hash") if current else None
    return {"deployed": len(deployed), "unretested_deployed": unretested,
            "all_deployed_retested": not unretested,
            "current_version": current_hash,
            "current_has_determination": bool(current_hash and current_hash in bound)}


def measure(state, key, signed_at):
    """Turn the AST-2 and AST-3 facts from declared into MEASURED by actually signing, verifying, and
    anchoring a receipt for every safety-test determination, and checking each carries a model-version
    fingerprint. `key` is a policy_pack.keygen() result; signed_at is an ISO-8601 string (passed in, so
    the result is reproducible). Returns the measured facts plus the receipts produced."""
    dets = state.get("determinations", [])
    receipts = []
    signed_ok = anchored_ok = fingerprinted = bool(dets)
    for d in dets:
        if "version_hash" not in d:
            fingerprinted = False
        rec = _r.sign_receipt(d, key, signed_at)
        receipts.append(rec)
        if not _r.verify_receipt(rec, d, key["public"]):
            signed_ok = False
        if not _r.verify_anchor(_r.anchor_receipt(rec)):
            anchored_ok = False
    return {"measured_facts": {
                "determinations_signed": signed_ok,
                "receipts_anchored": anchored_ok,
                "point_in_time_replayable": signed_ok,   # verify re-derives the root from the recorded determination
                "tests_fingerprinted": fingerprinted,
                "stale_tests_refused": fingerprinted,     # a fingerprint is what lets the binding refuse a stale test
            },
            "receipts": receipts}


def operational_facts(state, as_of):
    """Measure the 'performed' AST fact continuous_evaluation from an operational retest-task
    completion record: it is True when the recurring safety-suite-run task (control_tasks, control
    AST-3) is current, not overdue, as of `as_of`. The completions live in state['retest_completions'].
    This is the operational mechanism, alongside the config comparator and the AI Safety Testing Plan
    SOP, that gives the AST catalog the same three-way treatment as 800-171."""
    completions = state.get("retest_completions", [])
    tasks = _ct.tasks_for("AST-3")
    if not tasks:
        return {}
    st = _ct.task_status(tasks[0], completions, as_of)
    return {"continuous_evaluation": not st["overdue"]}


def safety_posture(state, measured=None):
    """Assemble the AI-safety facts from a pipeline state:
        {boundary, versions: [...], determinations: [...], capabilities: {fact_key: bool}, provenance: {}}
    The declared capabilities pass through, the two version-binding facts are computed, and if `measured`
    is supplied (from measure()) its facts OVERRIDE the declared ones and are tagged in provenance, so an
    auditor can see which facts were measured versus asserted."""
    vb = version_binding(state.get("versions", []), state.get("determinations", []))
    facts = dict(state.get("capabilities", {}))
    facts["safety_determination_for_current_version"] = vb["current_has_determination"]
    facts["no_unretested_deployed_versions"] = vb["all_deployed_retested"]
    measured_keys = []
    if measured:
        for k, v in measured["measured_facts"].items():
            facts[k] = v
            measured_keys.append(k)
    prov = {"source": "ai-safety-pipeline", "measured_facts": sorted(measured_keys)}
    prov.update(state.get("provenance", {}))
    return {"boundary": state.get("boundary", "the AI system"), "facts": facts,
            "provenance": prov, "version_binding": vb}


def assess(state, out_dir=None, key=None, signed_at=None, as_of=None):
    """Grade the AI-safety-testing controls from a pipeline state, restoring the previously active
    standard afterward. When `key` and `signed_at` are supplied, the AST-2 and AST-3 receipt and
    fingerprint facts are MEASURED from real signed, anchored receipts. When `as_of` is supplied,
    continuous_evaluation (AST-3[d]) is MEASURED from a current retest-task completion record. Anything
    not measured falls back to the declared capabilities and defers if absent (fail-closed)."""
    prev = _ca.active_standard()
    _ca.use_standard(STANDARD)
    try:
        measured_facts, receipts = {}, []
        if key is not None and signed_at is not None:
            m = measure(state, key, signed_at)
            measured_facts.update(m["measured_facts"])
            receipts = m["receipts"]
        if as_of is not None:
            measured_facts.update(operational_facts(state, as_of))
        measured = {"measured_facts": measured_facts} if measured_facts else None
        posture = safety_posture(state, measured=measured)
        result = _pc.assess(posture, out_dir=out_dir)
        result["version_binding"] = posture["version_binding"]
        result["measured"] = posture["provenance"]["measured_facts"]
        if receipts:
            result["receipts"] = receipts
        return result
    finally:
        _ca.use_standard(prev)
