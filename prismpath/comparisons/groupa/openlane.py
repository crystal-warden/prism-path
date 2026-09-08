# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Openlane, graded from its documentation and API surface only (PREREGISTRATION.md section 3: a
reference layer, the governance system of record, never benchmarked as a decision engine).

Sources read (September 2026): the core repository README (github.com/theopenlane/core), which
describes the product as "a system of record for your compliance program including the people,
systems, and vendors in scope; the policies and controls that govern them; and the evidence that
proves it", built on PostgreSQL, ent, gqlgen, and OpenFGA; the platform documentation at
docs.theopenlane.io (compliance management: policies, controls, evidence, programs with approvals and
full history; frameworks; registry; exposure; automation workflows; trust center). There is no policy
evaluation language, no per request decision API for application requests, no signed policy
artifact for an enforcement point, no compact wire, no timing bound. Authorization inside the
product is OpenFGA.

Every Group A cell is therefore NOT for Openlane, with the documentation as evidence. Its Group B
rows (governance, evidence records, ecosystem) are written in Phase 4.

Usage: python -m prismpath.comparisons.groupa.openlane
"""
from __future__ import annotations

import sys

from prismpath.comparisons.groupa.common import evidence_dir, write_result

SOURCES = ("https://github.com/theopenlane/core (README, features)",
           "https://docs.theopenlane.io/docs/platform/compliance-management/overview",
           "https://docs.theopenlane.io/docs/developers/security/overview (authorization model: OpenFGA)",
           "https://docs.theopenlane.io/docs/api")

NOTES = {
    "A1": "no policy evaluation language or decision API: nothing to return abstain from; objects have approval states, not decisions on requests",
    "A2": "approvals and task assignment with escalation exist as workflow features on compliance objects, not as a routed outcome of a request decision",
    "A3": "a cloud service and Go server stack (PostgreSQL, Redis, S3); nothing runs on a kernel, MCU, or FPGA",
    "A4": "full history on every object and evidence records are audit features of the system of record; there is no per decision receipt because there is no decision engine, and no signing or Merkle anchoring is documented",
    "A5": "GraphQL and REST over HTTPS; no compact wire",
    "A6": "policies here are governance documents with approvals and history, not enforcement artifacts loaded by a point; no signature or version floor at an enforcement point",
    "A7": "no decision evaluation, so no decision time to bound",
    "A8": "an LLM proposed action cannot be gated by Openlane; it records controls and evidence about the program that would govern such gating",
}


def main() -> int:
    ev = evidence_dir("openlane", "docs")
    (ev / "sources.txt").write_text("\n".join(SOURCES) + "\n")
    for dim, note in NOTES.items():
        write_result(system="openlane", dimension=dim, policy="none", scenario="matrix-row", expected=None,
                     observed="not_applicable", grade="NOT", idiomatic=True, evidence_path=ev,
                     notes=f"Graded from documentation (results/openlane/evidence/docs/sources.txt): {note}. "
                           "Openlane is the reference layer for who governs the compliance program, a channel candidate for "
                           "the GRC adjudication layer, not a decision engine; NOT here is a boundary, not a defect.")
    print("openlane A1..A8 written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
