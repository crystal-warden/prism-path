# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A1 (abstain as a first class outcome), A2 (human routing as a routed outcome), A4 (signed, tamper
evident, per decision receipts carrying cause), graded from evidence already produced by the real
systems: the Phase 2 conformance rows (every scenario decided by the real binary, systems/<id>/
generated/conformance.json) and the A8 receipt evidence (results/<id>/evidence/A8/).

Each system's outcome carrier and absence behavior is declared here, from what the Phase 2
translators had to do and recorded in their TRANSLATION.json notes; the grade is then mechanical
against PREREGISTRATION.md section 5:

  A1 NATIVE  a distinct abstain outcome is a first class returned result AND an absent field leaves
             the rule unsatisfied (not an error, not a silent default)
     WITH-WORK  one of the two holds and the other needs a wrapper (an annotation or output field
             carries the outcome; guards had to be written for absence)
     NOT     outcomes are a fixed allow/deny, or the policy is not expressible
  A2 same shape for escalate_human, plus: the system can tell a policy selected escalation from a
     worker requested one
  A4 four sub properties graded separately as scenarios; the cell is the minimum

Usage: python -m prismpath.comparisons.groupa.a1a2a4
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

from prismpath.comparisons.groupa.common import RESULTS, evidence_dir, policy_by_id, write_result
from prismpath.comparisons.harness import HERE, SYSTEMS_DIR

SYSTEMS = ["prismpath", "opa", "cedar", "cerbos", "openfga"]

# Outcome carrier and absence behavior per system, as established in Phase 2 (TRANSLATION.json notes,
# toolchain/TOOLCHAIN.md observations) and in the A8 run.
MECHANISM: Dict[str, Dict[str, Any]] = {
    "prismpath": {
        "carrier": "first_class",
        "carrier_note": "a routed terminal node named for the outcome, the outcome on the receipt with a cause code",
        "absence": "unsatisfied",
        "absence_note": "a missing field is null; a comparison over it is unsatisfied (SPEC 4); on a policy with no "
                        "catch all the run stops as stuck with cause 36 route:stuck on the receipt (reported as: "
                        "refused, nothing routed, cause named)",
        "human_distinct": "cause 34 route:needs-human on the worker's own request vs cause 0 on a policy selected "
                          "escalation, stamped by the engine (A8 causes [0,0,0,0,0,34])",
    },
    "opa": {
        "carrier": "first_class",
        "carrier_note": "the decision rule returns an arbitrary document {outcome, rule}",
        "absence": "unsatisfied",
        "absence_note": "a reference to a missing input field is undefined, so the rule body fails (documented "
                        "undefined semantics); with no catch all the whole decision is undefined and opa eval "
                        "returns an empty result set with exit 0 (observed on sensor_interlock probes)",
        "human_distinct": "only by the rule id the policy author put in the result document (r1 vs r4/r8); no "
                          "system level cause",
    },
    "cedar": {
        "carrier": "annotation",
        "carrier_note": "Cedar decides ALLOW or DENY; the outcome rides an @outcome annotation on the one permit "
                        "that applied, read from `authorize -v` diagnostics",
        "absence": "guarded",
        "absence_note": "a reference to a missing context attribute is an evaluation error and the policy does "
                        "not apply (default DENY); the translation wrote `context has f &&` guards on every read to "
                        "obtain unsatisfied semantics",
        "human_distinct": "only by the policy id in the diagnostics (r1 vs r4/r8); no system level cause",
    },
    "cerbos": {
        "carrier": "output_field",
        "carrier_note": "Cerbos decides EFFECT_ALLOW or EFFECT_DENY per action; the outcome rides the rule's output "
                        "block {outcome, rule} in the response",
        "absence": "guarded",
        "absence_note": "a CEL read of a missing attribute is an evaluation error logged as a warning and the rule "
                        "does not match (default EFFECT_DENY); the translation wrote has() guards on every read",
        "human_distinct": "only by the rule id in the output block; no system level cause",
    },
    "openfga": {
        "carrier": "boolean_only",
        "carrier_note": "a Check returns one boolean for one relation; the decision policies are not expressible",
        "absence": "n/a",
        "absence_note": "not expressible",
        "human_distinct": "not expressible",
    },
}


def conformance_rows(system: str) -> List[Dict[str, Any]]:
    return json.loads((SYSTEMS_DIR / system / "generated" / "conformance.json").read_text())["rows"]


def row_for(rows, policy: str, scenario: str) -> Dict[str, Any]:
    return next(r for r in rows if r["policy"] == policy and r["scenario"] == scenario)


def outcome_grade(system: str) -> str:
    m = MECHANISM[system]
    if m["carrier"] == "boolean_only":
        return "NOT"
    if m["carrier"] == "first_class" and m["absence"] == "unsatisfied":
        return "NATIVE"
    return "WITH-WORK"


WRAPPER_GLUE = {
    "description": "a client wrapper that reads the outcome carrier (Cedar's applying policy annotation from the "
                   "verbose diagnostics, or Cerbos's output block) and returns it as the decision, plus the "
                   "absence guards the translator already writes",
    "components": ["response parser", "outcome mapping", "has guards in the translation"],
    "loc": 40, "hours": 1,
}


def run_a1() -> None:
    dims = {"expense_approval": ["insufficient_1", "insufficient_2", "undeclared_missing_1"],
            "ai_action_gate": ["abstain_low_confidence_1", "undeclared_missing_1"],
            "sensor_interlock": ["undeclared_missing_1", "undeclared_missing_2"]}
    for system in SYSTEMS:
        rows = conformance_rows(system)
        m = MECHANISM[system]
        ev = evidence_dir(system, "A1")
        (ev / "mechanism.json").write_text(json.dumps(m, indent=2) + "\n")
        for pol, scs in dims.items():
            for sc in scs:
                r = row_for(rows, pol, sc)
                obs = r["observed"]["observed"]
                exp = r["expected"]["outcome"]
                grade = outcome_grade(system)
                notes = (f"Observed by the real system in the Phase 2 conformance run: {obs} (expected {exp}"
                         f"{'; a probe scenario: the observed value is the measurement' if r['kind'] == 'undeclared_missing' else ''}). "
                         f"Carrier: {m['carrier']} ({m['carrier_note']}). Absence: {m['absence']} ({m['absence_note']}).")
                if system == "prismpath" and obs == "no_match":
                    notes += f" Cause on the receipt: {r['observed']['cause']} (refused, nothing routed)."
                write_result(system=system, dimension="A1", policy=pol, scenario=sc, expected=exp, observed=obs,
                             grade=grade, idiomatic=True, evidence_path=SYSTEMS_DIR / system / "generated",
                             glue=WRAPPER_GLUE if grade == "WITH-WORK" else None, notes=notes)


def run_a2() -> None:
    dims = {"expense_approval": ["escalation_1", "escalation_2", "escalation_3"],
            "ai_action_gate": ["escalate_execute_confidential_1", "escalate_org_write_1", "escalate_human_requested_1"]}
    for system in SYSTEMS:
        rows = conformance_rows(system)
        m = MECHANISM[system]
        ev = evidence_dir(system, "A2")
        (ev / "mechanism.json").write_text(json.dumps(m, indent=2) + "\n")
        for pol, scs in dims.items():
            for sc in scs:
                r = row_for(rows, pol, sc)
                obs = r["observed"]["observed"]
                exp = r["expected"]["outcome"]
                grade = outcome_grade(system)
                notes = (f"Observed by the real system in the Phase 2 conformance run: {obs} (expected {exp}). "
                         f"Carrier: {m['carrier']} ({m['carrier_note']}). Worker requested vs policy selected "
                         f"escalation: {m['human_distinct']}.")
                if sc == "escalate_human_requested_1":
                    notes += f" This is the worker requested case; cause observed: {r['observed']['cause']}."
                write_result(system=system, dimension="A2", policy=pol, scenario=sc, expected=exp, observed=obs,
                             grade=grade, idiomatic=True, evidence_path=SYSTEMS_DIR / system / "generated",
                             glue=WRAPPER_GLUE if grade == "WITH-WORK" else None, notes=notes)


# A4 sub properties, from the A8 receipt evidence. (grade, observed, note, glue)
RECEIPTS: Dict[str, Dict[str, Any]] = {
    "prismpath": {
        "per_decision": ("NATIVE", "true", "one audit_log event per decision (results/prismpath/evidence/A8/receipts.jsonl, 6 of 6)", None),
        "signed": ("NATIVE", "true", "the receipt Merkle root is bound to the policy authority key with policy_pack's Ed25519 canonical signing and verified (receipt_root.json); the same primitive signs policies", None),
        "tamper_evident": ("NATIVE", "true", "sha256 Merkle leaves over canonical events, verify_log true, inclusion proof for leaf 3 verified (audit_log, ledger_ots primitives)", None),
        "carries_cause": ("NATIVE", "true", "each receipt carries the registry cause code (0 on clean decisions, 34 on the worker requested escalation) distinct from the outcome", None),
    },
    "opa": {
        "per_decision": ("NATIVE", "true", "decision_logs.console emitted 6 records for 6 decisions with decision_id, input, result, timestamp (server_decision_log.jsonl)", None),
        "signed": ("WITH-WORK", "false", "decision logs are unsigned JSON shipped to console or an HTTP service; signing the per session Merkle root with the bundle signing key OPA already trusts is glue without a new anchor",
                   {"description": "sign a per session Merkle root of the decision log records with the deployment's bundle signing key", "components": ["log consumer", "Merkle root", "signature with existing bundle key", "verifier"], "loc": 150, "hours": 3}),
        "tamper_evident": ("WITH-WORK", "false", "no hash chain or Merkle root over decision log records; a sidecar computing one is glue (no key needed)",
                           {"description": "Merkle root or hash chain over the decision log records", "components": ["log consumer", "sha256 chain"], "loc": 80, "hours": 2}),
        "carries_cause": ("NATIVE", "true", "the record carries the result document the policy returned, here {outcome, rule}: a machine readable reason distinct from the outcome, authored by the policy", None),
    },
    "cedar": {
        "per_decision": ("WITH-WORK", "false", "no decision log; the CLI prints the decision and, with -v, the applying policy ids; a wrapper capturing each invocation is glue",
                         {"description": "wrapper that logs each authorize call, its request, and its verbose diagnostics", "components": ["CLI wrapper", "JSONL log"], "loc": 60, "hours": 1}),
        "signed": ("NOT", "false", "no key, no anchor anywhere in Cedar; signing would introduce a new trust anchor", None),
        "tamper_evident": ("WITH-WORK", "false", "a hash chain over the wrapper's log is glue without a key",
                           {"description": "hash chain over the wrapper log", "components": ["sha256 chain"], "loc": 40, "hours": 1}),
        "carries_cause": ("WITH-WORK", "false", "the applying policy id and the @outcome annotation are in the verbose diagnostics, readable by the wrapper",
                          {"description": "parse the verbose diagnostics for the applying policy id", "components": ["diagnostics parser"], "loc": 30, "hours": 1}),
    },
    "cerbos": {
        "per_decision": ("NATIVE", "true", "audit backend file wrote 6 decision records for 6 checks with call id, timestamp, inputs, effects, outputs (decision_audit.jsonl)", None),
        "signed": ("NOT", "false", "open source Cerbos has no signing key or anchor (policy signing is a Cerbos Hub feature); signing would introduce a new trust anchor", None),
        "tamper_evident": ("WITH-WORK", "false", "the audit file is append only JSON with no hash chain; a sidecar chain is glue without a key",
                           {"description": "hash chain over the decision audit records", "components": ["sha256 chain"], "loc": 60, "hours": 1}),
        "carries_cause": ("NATIVE", "true", "each record carries the rule's output block {outcome, rule}, a machine readable reason distinct from the effect", None),
    },
    "openfga": {
        "per_decision": ("NOT", "false", "the policy is not expressible; OpenFGA also has no built in decision log", None),
        "signed": ("NOT", "false", "not expressible; no key or anchor", None),
        "tamper_evident": ("NOT", "false", "not expressible", None),
        "carries_cause": ("NOT", "false", "not expressible; a Check returns a boolean", None),
    },
}


def run_a4() -> None:
    for system in SYSTEMS:
        ev8 = RESULTS / system / "evidence" / "A8"
        for sub, (grade, obs, note, glue) in RECEIPTS[system].items():
            write_result(system=system, dimension="A4", policy="ai_action_gate", scenario=sub, expected="true",
                         observed=obs, grade=grade, idiomatic=True, evidence_path=ev8, glue=glue,
                         notes=f"Sub property {sub}, from the A8 loop run of ai_action_gate/ai_worker_loop_1: {note}.")


def main() -> int:
    run_a1(); run_a2(); run_a4()
    print("A1, A2, A4 result files written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
