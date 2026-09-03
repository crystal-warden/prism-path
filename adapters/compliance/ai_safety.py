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


def safety_posture(state):
    """Assemble the AI-safety facts from a pipeline state:
        {boundary, versions: [...], determinations: [...], capabilities: {fact_key: bool}, provenance: {}}
    The declared capabilities pass through; the two version-binding facts are computed from the ledger."""
    vb = version_binding(state.get("versions", []), state.get("determinations", []))
    facts = dict(state.get("capabilities", {}))
    facts["safety_determination_for_current_version"] = vb["current_has_determination"]
    facts["no_unretested_deployed_versions"] = vb["all_deployed_retested"]
    prov = {"source": "ai-safety-pipeline"}
    prov.update(state.get("provenance", {}))
    return {"boundary": state.get("boundary", "the AI system"), "facts": facts,
            "provenance": prov, "version_binding": vb}


def assess(state, out_dir=None):
    """Grade the AI-safety-testing controls from a pipeline state. Selects the AI-safety catalog,
    assembles the posture, and runs it through the deterministic posture connector, then restores the
    previously active standard."""
    prev = _ca.active_standard()
    _ca.use_standard(STANDARD)
    try:
        posture = safety_posture(state)
        result = _pc.assess(posture, out_dir=out_dir)
        result["version_binding"] = posture["version_binding"]
        return result
    finally:
        _ca.use_standard(prev)
