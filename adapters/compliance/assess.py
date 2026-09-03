#!/usr/bin/env python3
"""Compliance adapter runtime — the five ports wired end-to-end:
   Ingestion → Retrieval → Adjudicator → Action/Sink → Attestation.
Analogous to wazuh_triage_agent.py for the SOC adapter; the interesting logic is in the flow + this
thin port-wiring, not re-implemented engine machinery."""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import compliance_adapter as ca


def assess_one(req, out_dir):
    control = ca.get_control(req["control_id"])                 # Retrieval port
    det = ca.adjudicate(control, req)                           # Adjudicator port
    if det is None:
        return {"control": req["control_id"], "error": "adjudication failed"}
    path, rt = ca.write_result(control, req, det, out_dir)      # Action/Sink port
    prov = ca.attest(control, req, det)                         # Attestation port (reuses core ledger)
    return {"control": req["control_id"], "status": det["status"], "record": rt,
            "record_path": os.path.relpath(path, HERE),
            "n_objectives": len(control["objectives"]),
            "n_unmet": len(det.get("unmet_objective_ids", [])),
            "provenance": {"catalog_hash": prov["knowledge_base_hash"],
                           "evidence_hash": prov["ingestion_hashes"][0],
                           "manifest_hash": prov["manifest_hash"][:20]}}


if __name__ == "__main__":
    req_dir = os.path.join(HERE, "requests"); out_dir = os.path.join(HERE, "out")
    results = [assess_one(r, out_dir) for r in ca.iter_requests(req_dir)]
    print(json.dumps(results, indent=1))
    print("\ncatalog fingerprint:", ca.catalog_hash())
