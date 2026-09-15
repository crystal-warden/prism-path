#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""End-to-end #65 proof: adjudicate the live request bundles through gemma, attest each determination,
then emit BOTH standards (OSCAL AR+POA&M and CycloneDX 1.6), schema-validated, and confirm every
Flow-Ledger provenance hash is actually embedded in the reports it belongs in."""
import os, json
HERE = os.path.dirname(os.path.abspath(__file__))
from adapters.compliance import compliance_adapter as ca

# ============================================================================
# CONFIGURE -- point these at your own evidence-request bundles and output dir.
# ============================================================================
REQUESTS_DIR = os.path.join(HERE, "requests")   # your evidence-request bundles (SAMPLE default)
OUT_DIR = os.path.join(HERE, "reports_live")    # where OSCAL + CycloneDX reports are written
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

out = ca.emit_reports(recs, fmt="both", out_dir=OUT_DIR)

def embedded_in(doc, hashes):
    serialized = json.dumps(doc)
    return {provenance_hash[:16]: (provenance_hash in serialized) for provenance_hash in hashes}

all_h = [record["manifest"]["manifest_hash"] for record in recs]
open_h = [record["manifest"]["manifest_hash"] for record in recs if record["status"] != "met"]
summary = {"determinations": [{"control": record["control_id"], "status": record["status"],
                               "manifest": record["manifest"]["manifest_hash"][:16]} for record in recs]}
for format_name, emission in out.items():
    want = open_h if format_name == "oscal_poam" else all_h
    emb = embedded_in(emission["doc"], want)
    summary[format_name] = {"valid": emission["valid"], "n_errors": len(emission["errors"]), "errors": emission["errors"][:4],
                            "path": emission["path"], "provenance_hashes_embedded": emb,
                            "all_embedded": all(emb.values())}
print(json.dumps(summary, indent=1))
