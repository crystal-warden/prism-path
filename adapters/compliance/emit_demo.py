#!/usr/bin/env python3
"""End-to-end #65 proof: adjudicate the live request bundles through gemma, attest each determination,
then emit BOTH standards (OSCAL AR+POA&M and CycloneDX 1.6), schema-validated, and confirm every
Flow-Ledger provenance hash is actually embedded in the reports it belongs in."""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import compliance_adapter as ca

recs = []
for f in sorted(os.listdir(os.path.join(HERE, "requests"))):
    req = ca.load_request(os.path.join(HERE, "requests", f))
    control = ca.get_control(req["control_id"])
    det = ca.adjudicate(control, req)
    if det is None:
        print("adjudication failed:", f); continue
    manifest = ca.attest(control, req, det)
    recs.append(ca.result_record(control, req, det, manifest))

out = ca.emit_reports(recs, fmt="both", out_dir=os.path.join(HERE, "reports_live"))

def embedded_in(doc, hashes):
    t = json.dumps(doc)
    return {h[:16]: (h in t) for h in hashes}

all_h = [r["manifest"]["manifest_hash"] for r in recs]
open_h = [r["manifest"]["manifest_hash"] for r in recs if r["status"] != "met"]
summary = {"determinations": [{"control": r["control_id"], "status": r["status"],
                               "manifest": r["manifest"]["manifest_hash"][:16]} for r in recs]}
for k, v in out.items():
    want = open_h if k == "oscal_poam" else all_h
    emb = embedded_in(v["doc"], want)
    summary[k] = {"valid": v["valid"], "n_errors": len(v["errors"]), "errors": v["errors"][:4],
                  "path": v["path"], "provenance_hashes_embedded": emb,
                  "all_embedded": all(emb.values())}
print(json.dumps(summary, indent=1))
