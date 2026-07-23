#!/usr/bin/env python3
"""#67 proof (deterministic — no gemma): the discovery loop now generates catalog-driven,
objective-specific evidence requests from the Translation layer.
  (1) empty bundle for 3.1.7 -> a request per objective, built from the catalog.
  (2) partial case: only the unmet objectives of 3.1.12 -> a targeted subset."""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import compliance_adapter as ca

out = {}

# (1) empty bundle -> whole-control catalog-driven request
c7 = ca.get_control("3.1.7")
empty = {"control_id": "3.1.7", "boundary": "CUI enclave", "evidence": []}
pend = ca.defer_for_evidence(c7, empty)                 # no `missing` -> generated from catalog
req = pend["request"]
out["empty_bundle_3.1.7"] = {
    "status": pend["status"],
    "evidence_types": req["evidence_types"],
    "n_requests": len(req["requests"]),
    "requests": [{"objective_id": r["objective_id"], "ask": r["ask"]} for r in req["requests"]],
}

# (2) partial: only the unmet objectives get asked
c12 = ca.get_control("3.1.12")
part = {"control_id": "3.1.12", "boundary": "CUI enclave", "evidence": [{"type": "config", "text": "VPN config"}]}
pend2 = ca.defer_for_evidence(c12, part, unmet_ids=["3.1.12[b]", "3.1.12[d]"])
req2 = pend2["request"]
out["partial_3.1.12_unmet_only"] = {
    "targeted_objectives": [r["objective_id"] for r in req2["requests"]],
    "asks": [r["ask"] for r in req2["requests"]],
}

print(json.dumps(out, indent=1))
