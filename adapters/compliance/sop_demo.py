#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Runnable demonstration of the SOP generator: fill the Incident Response Plan template from a
structured intake and print the objective-complete draft. Deterministic, no model in the loop.

    PYTHONSAFEPATH=1 PYTHONPATH=<core>:<adapter> python -m sop_demo
"""
import compliance_adapter as ca
import sop_generator as sg

SAMPLE_ANSWERS = {
    "org_name": "Example Defense Supplier LLC",
    "system_name": "the CUI processing enclave",
    "boundary": "the isolated network segment that stores and processes CUI",
    "cui_description": "controlled technical data delivered under a DoD contract",
    "ir_lead_role": "the Information System Security Manager",
    "internal_officials": "the ISSM and the company owner",
    "external_authorities": "DoD DIBNet, and the FBI for suspected criminal activity",
    "preparation": "annual responder training, an on-call rotation, and maintained runbooks",
    "detection": "endpoint detection, network monitoring, and a user reporting channel",
    "analysis": "a documented triage and severity-scoring procedure",
    "containment": "isolating affected hosts and revoking compromised credentials",
    "recovery": "restoring affected systems from verified backups and confirming integrity",
    "user_response": "notifying and directing affected users through the ISSM",
    "tracking_system": "the incident register in the IT ticketing system",
    "documentation_practice": "a timeline, actions taken, evidence collected, and final disposition",
    "reporting_timeline": "72 hours of confirming a reportable incident",
    "reporting_method": "the DIBNet portal, with direct notification to internal officials",
    "test_frequency": "at least annually",
    "test_method": "a tabletop exercise with a written after-action report",
}


def main():
    ca.use_standard("nist_800171_r2")
    spec = sg.load_spec("incident_response")
    cov = sg.verify_coverage(spec)
    print("# Coverage: %d/%d objectives mapped across %s; complete=%s\n"
          % (cov["mapped"], cov["n_objectives"], ", ".join(cov["controls"]), cov["complete"]))
    res = sg.generate(spec, SAMPLE_ANSWERS)
    print(res["markdown"])
    print("\n# unanswered:", res["unanswered"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
