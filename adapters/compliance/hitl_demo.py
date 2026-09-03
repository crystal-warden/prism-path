#!/usr/bin/env python3
"""Demo — the Deferral/Review port + override attestation, both loops:
   (1) HITL override: AI says not-met, a senior auditor accepts a compensating control and overrides
       to met; the AI output is attested first (immutable), the override supersedes it (provable chain).
   (2) Missing-evidence discovery: empty bundle → an evidence request is routed (deferred, not failed);
       the client uploads → resume → re-adjudicate."""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import compliance_adapter as ca

out = {}

# --- Loop 1: HITL override (compensating control) ---
req = json.load(open(os.path.join(HERE, "requests", "req_3.1.5_notmet.json")))
control = ca.get_control("3.1.5")
det = ca.adjudicate(control, req)                                  # AI adjudication (expected: not-met)
deferred = ca.defer_for_review(control, req, det, reason="MFA+PAM compensating control claimed by client")
resolved = ca.resolve_review(
    deferred["unit_id"], new_status="met", unmet_objective_ids=[], actor="auditor:j.smith",
    rationale="Compensating control accepted: enforced MFA + PAM just-in-time elevation mitigate the least-privilege gap on this boundary.",
    out_dir=os.path.join(HERE, "out"))
out["loop1_hitl_override"] = {"ai_said": resolved["ai_status"], "human_final": resolved["final_status"],
                              "overrider": resolved["overrider"], "override_supersedes_ai": resolved["supersedes_ai"],
                              "ai_manifest": resolved["ai_manifest"], "override_manifest": resolved["override_manifest"],
                              "record": resolved["record"]}

# --- Loop 2: missing-evidence discovery ---
empty_req = {"control_id": "3.1.7", "boundary": "CUI enclave", "evidence": []}
control7 = ca.get_control("3.1.7")
if not ca.sufficient_evidence(empty_req):
    pend = ca.defer_for_evidence(control7, empty_req,
                                 missing="audit logs of privileged-function execution + the non-privileged-user definition")
    out["loop2_evidence_request"] = {"status": pend["status"], "request": pend["request"]}
    new_ev = [{"type": "config", "text": "Audit policy captures privileged-function execution to the SIEM; AD groups define privileged vs non-privileged users; screenshots show non-privileged users blocked from privileged functions on the enclave, and the executions appear in the audit log."}]
    resolved_ev = ca.resolve_evidence(pend["unit_id"], new_ev, out_dir=os.path.join(HERE, "out"))
    out["loop2_after_evidence"] = resolved_ev

print(json.dumps(out, indent=1))
