#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""#66 proof: adjudicate the live bundles, attest each, then produce the SYSTEM rollup —
partial SPRS score + assessment scope + a rollup attestation bound to the per-control manifests —
and emit it into a schema-valid OSCAL AR + standalone summary."""
import os, json
HERE = os.path.dirname(os.path.abspath(__file__))
from adapters.compliance import compliance_adapter as ca

# ============================================================================
# CONFIGURE -- set SCOPE to your assessment scope; point the dirs at your data.
# ============================================================================
SCOPE = {   # SAMPLE assessment scope (replace with your own)
    "system_name": "Acme Defense Widgets — CUI Enclave",
    "boundary": "CUI enclave (VLAN 40, 3 workstations + 1 file server)",
    "assets_sampled": ["ws-01", "ws-02", "fs-01"],
    "sampling_method": "judgmental — all enclave assets (small population, 100% sample)",
    "assessor": "PrismPath automated pre-assessment + human auditor review",
    "assessment_date": "2026-07-22",
}
REQUESTS_DIR = os.path.join(HERE, "requests")   # your evidence-request bundles
OUT_DIR = os.path.join(HERE, "reports_live")    # where rollup reports are written
# ============================================================================

recs = []
for filename in sorted(os.listdir(REQUESTS_DIR)):
    req = ca.load_request(os.path.join(REQUESTS_DIR, filename))
    control = ca.get_control(req["control_id"])
    det = ca.adjudicate(control, req)
    if det is None:
        print("adjudication failed:", filename); continue
    manifest = ca.attest(control, req, det)
    recs.append(ca.result_record(control, req, det, manifest))

out = ca.rollup_report(recs, SCOPE, out_dir=OUT_DIR, fmt="both")

# confirm the rollup attestation binds every per-control manifest
per_control = {record["control_id"]: record["manifest"]["manifest_hash"] for record in recs}
bound = set(out["bound_control_manifests"])
all_bound = all(manifest_hash in bound for manifest_hash in per_control.values())

print(json.dumps({
    "sprs_partial": {field: out["sprs"][field] for field in
                     ("n_assessed", "deducted_points", "ceiling_if_unassessed_all_met",
                      "assessed_subset_max_points", "assessed_subset_earned_points")},
    "deductions": out["sprs"]["deductions"],
    "caveat": out["sprs"]["caveat"],
    "scope_boundary": out["scope"]["boundary"],
    "rollup_manifest": out["rollup_manifest"][:16],
    "rollup_binds_all_control_manifests": all_bound,
    "n_bound": len(bound),
    "summary_path": out["summary_path"],
    "emitted": out["emitted"],
}, indent=1))
