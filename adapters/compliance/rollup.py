#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""System-level rollup Sink (#66) — aggregate per-control determinations into a system artifact.

Three outputs, all bound to the per-control attestations that fed them:
  * a PARTIAL SPRS score (DoD Assessment Methodology weights 5/3/1, base 110) — honestly labeled
    partial because only a subset of the 110 controls is assessed; never presented as submittable.
  * an assessment SCOPE (boundary, sampled assets, sampling method, assessor, date).
  * a system-level rollup ATTESTATION whose inputs (ingestion_hashes) are the per-control manifest
    hashes — a superstructure over the individual Flow-Ledger commits, so the whole system report is
    provably derived from exactly those attested control determinations.

Pure aggregation + attestation reuse. No LLM, no domain adjudication.
"""
import os, json, hashlib
from prismpath.ledgers import ledger_airgap# CORE attestation (adapter -> core is allowed)

HERE = os.path.dirname(os.path.abspath(__file__))
WEIGHTS_PATH = os.path.join(HERE, "catalog", "sprs_weights.json")

def _weights():
    return json.load(open(WEIGHTS_PATH))

def weights_hash():
    weights_table = _weights()
    return "sha256:" + hashlib.sha256(json.dumps(weights_table["weights"], sort_keys=True).encode()).hexdigest()[:16]

def _canon(obj):
    return json.dumps(obj, sort_keys=True).encode()

# ---------- partial SPRS score ----------
def sprs_partial(records, weights=None):
    weights_table = _weights()
    base = weights_table["base"]
    wt = weights if weights is not None else weights_table["weights"]       # weights from the active catalog (Rev 2)
    assessed = sorted({record["control_id"] for record in records})
    deductions = []
    for record in records:
        if record["status"] == "met":
            continue
        cid = record["control_id"]; weight = wt.get(cid)
        deductions.append({"control": cid, "status": record["status"], "weight": weight,
                           "counted": weight if weight is not None else 0,
                           "note": None if weight is not None else "no weight in table — counted 0, VERIFY"})
    deducted = sum(deduction["counted"] for deduction in deductions)
    assessed_max = sum(wt.get(control_id, 0) for control_id in assessed)
    return {
        "base": base, "n_total_controls": weights_table.get("n_total_controls", 110),
        "assessed_controls": assessed, "n_assessed": len(assessed),
        "deductions": deductions, "deducted_points": deducted,
        "ceiling_if_unassessed_all_met": base - deducted,
        "assessed_subset_max_points": assessed_max,
        "assessed_subset_earned_points": assessed_max - deducted,
        "scoring_note": weights_table["_scoring_note"], "weights_source": weights_table["_source"],
        "weights_verification": weights_table["_verification"],
        "caveat": ("PARTIAL SCORE — only %d of %d controls assessed. 'ceiling_if_unassessed_all_met' assumes "
                   "every unassessed control is MET and is an OPTIMISTIC UPPER BOUND, not a submittable SPRS "
                   "score (which requires assessing all 110). Weights are provisional; verify against the "
                   "official DoD Assessment Methodology." % (len(assessed), weights_table.get("n_total_controls", 110))),
    }

# ---------- assessment scope / sampling ----------
_SCOPE_FIELDS = ("system_name", "boundary", "assets_sampled", "sampling_method", "assessor", "assessment_date")
def build_scope(meta):
    return {field: meta.get(field) for field in _SCOPE_FIELDS}

def scope_hash(scope):
    return "sha256:" + hashlib.sha256(_canon(scope)).hexdigest()[:16]

# ---------- system-level rollup attestation ----------
def system_attestation(records, sprs, scope, catalog_hash, flow_hash="sha256:nist_ac_flow_v0"):
    """The rollup's inputs ARE the per-control attestations: ingestion_hashes = their manifest hashes."""
    summary = {
        "kind": "system-rollup", "gate": "nist_800171_access_control",
        "sprs": sprs, "scope": scope,
        "controls": [{"id": record["control_id"], "status": record["status"],
                      "manifest": record["manifest"]["manifest_hash"]} for record in records],
    }
    root = hashlib.sha256(_canon(summary)).hexdigest()
    kb = "sha256:" + hashlib.sha256((catalog_hash + weights_hash() + scope_hash(scope)).encode()).hexdigest()[:16]
    manifest = ledger_airgap.provenance_manifest(
        root_hex=root, label="system-rollup:nist-800171-ac",
        policy_hash=flow_hash, gate_id="nist_800171_system_rollup@v0",
        ingestion_hashes=[record["manifest"]["manifest_hash"] for record in records],
        knowledge_base_hash=kb)
    return manifest, summary

def write_summary(sprs, scope, manifest, summary, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    doc = {"assessment_scope": scope, "sprs_partial": sprs,
           "rollup_attestation": {"manifest_hash": manifest["manifest_hash"], "root": manifest["root"],
                                  "bound_control_manifests": manifest["ingestion_hashes"],
                                  "created": manifest["created"]},
           "controls": summary["controls"]}
    path = os.path.join(out_dir, "system_rollup_summary.json")
    json.dump(doc, open(path, "w"), indent=1)
    return path
