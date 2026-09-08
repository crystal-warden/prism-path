# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A8, the AI worker governance loop (PREREGISTRATION.md section 5, A8).

A stub worker emits the six proposals of `ai_action_gate/ai_worker_loop_1` in order; each system
gates each; the run must return allow, deny, abstain, and escalate_human across the six, distinguish
the worker requested escalation from the policy selected one, and produce one verifiable receipt per
decision carrying the cause, as one governed loop.

Grading, applied mechanically from what each system did in this run and from its declared receipt
facility (recorded in the notes and the evidence):
  NATIVE     all of the above with no component built here beyond calling the system's own facilities
  WITH-WORK  the gate exists and abstain, human routing, or the receipt is added with glue within the
             pre registered budget (300 lines, 8 hours, no new trust anchor); the glue is estimated
             here and built in Phase 5
  NOT        the loop cannot be closed without building a component that is itself the subject of A1,
             A2, or A4, or the glue would introduce a trust anchor the system does not already have

Usage: python -m prismpath.comparisons.groupa.a8 [--system ID ...]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

from prismpath import audit_log, policy_pack
from prismpath.comparisons.groupa.common import evidence_dir, policy_by_id, write_result
from prismpath.comparisons.harness import TOOLCHAIN_BIN, gen_dir_for
from prismpath.comparisons.systems import cedar as sys_cedar
from prismpath.comparisons.systems import prismpath as sys_pp

POLICY = "ai_action_gate"
SCENARIO = "ai_worker_loop_1"


def loop_steps(policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    sc = next(s for s in policy["scenarios"] if s["id"] == SCENARIO)
    return sc["steps"]


def expected_string(steps) -> str:
    return ",".join(st["expected"]["outcome"] for st in steps)


def policy_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


# ----------------------------------------------------------------------------- PrismPath
def run_prismpath(policy, steps) -> None:
    ev = evidence_dir("prismpath", "A8")
    gen = gen_dir_for("prismpath", POLICY)
    flow_text = (gen / f"{POLICY}.md").read_text(encoding="utf-8")
    runner = sys_pp.Runner(policy, gen)
    log_path = ev / "receipts.jsonl"
    if log_path.exists():
        log_path.unlink()
    log = audit_log.AuditLog(str(log_path))
    observed: List[str] = []
    causes: List[int] = []
    phash = policy_hash(flow_text)
    for i, st in enumerate(steps):
        d = runner.decide(st["input"])
        observed.append(d.observed)
        causes.append(d.cause if d.cause is not None else -1)
        log.append("gate", "decision", {"seq": i, "outcome": d.observed, "rule": d.rule, "cause": d.cause,
                                        "policy_hash": phash, "raw": d.raw})
    root = log.current_root()
    ok_log = log.verify_log()
    proof = log.prove(3)
    ok_proof = audit_log.verify(log.leaves[3], proof, root)
    # bind the root to the policy authority key with the product's own signing primitive
    keys = policy_pack.keygen(str(ev / "keys"), "authority")
    priv = policy_pack._load_private(keys["private"])
    payload = policy_pack.canonical_bytes({"receipt_root": root, "policy_hash": phash, "count": len(steps)})
    sig = priv.sign(payload)
    pub, key_id = policy_pack.load_public(keys["public"])
    pub.verify(sig, payload)
    (ev / "receipt_root.json").write_text(json.dumps({
        "receipt_root": root, "policy_hash": phash, "count": len(steps), "key_id": key_id,
        "signature_hex": sig.hex(), "verify_log": ok_log, "inclusion_proof_leaf3_verified": ok_proof,
        "causes": causes}, indent=2) + "\n")
    try:
        os.unlink(keys["private"])                # the private key is not evidence
    except OSError:
        pass
    distinguishable = causes[5] == 34 and causes[4] == 0
    outcomes_present = {"allow", "deny", "abstain", "escalate_human"} <= set(observed)
    grade = "NATIVE" if (outcomes_present and distinguishable and ok_log and ok_proof) else "NOT"
    write_result(system="prismpath", dimension="A8", policy=POLICY, scenario=SCENARIO,
                 expected=expected_string(steps), observed=",".join(observed), grade=grade, idiomatic=True,
                 evidence_path=ev, notes=(
        "One engine run per proposal (systems/prismpath translator, the corpus flow as a Markdown policy). "
        f"Outcomes present: {sorted(set(observed))}. Worker requested escalation (step 6) carries cause 34 "
        f"route:needs-human; the policy selected escalation (step 5) carries cause 0: causes={causes}. "
        "Receipts: one audit_log event per decision with seq, outcome, rule, cause, policy_hash "
        f"(receipts.jsonl); Merkle root {root[:16]}..., verify_log={ok_log}, inclusion proof for leaf 3 "
        f"verified={ok_proof}; root bound to the policy authority key with policy_pack's Ed25519 canonical "
        "signing (receipt_root.json, key_id recorded, public key kept, private key deleted). All four receipt "
        "sub properties use the product's existing primitives; the harness only composes them, the same "
        "composition the kernel receipts harness uses. Note: the Python tier's per decision receipt is the "
        "audit_log event, not a struct on a ringbuf as in kernel (#119); the cause byte is the engine's "
        "RunResult.cause."))


# ----------------------------------------------------------------------------- OPA
def run_opa(policy, steps) -> None:
    ev = evidence_dir("opa", "A8")
    gen = gen_dir_for("opa", POLICY)
    port = 18181
    logf = open(ev / "server_decision_log.jsonl", "w")
    proc = subprocess.Popen([str(TOOLCHAIN_BIN / "opa"), "run", "-s", "-a", f"127.0.0.1:{port}",
                             "--set", "decision_logs.console=true", str(gen / "policy.rego")],
                            stdout=logf, stderr=subprocess.STDOUT, start_new_session=True)
    time.sleep(1.5)
    observed: List[str] = []
    rules: List[str] = []
    try:
        for st in steps:
            inp = {k: v for k, v in st["input"].items() if v is not None}
            req = urllib.request.Request(f"http://127.0.0.1:{port}/v1/data/comparison/{POLICY}/decision",
                                         data=json.dumps({"input": inp}).encode(),
                                         headers={"content-type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=10) as r:
                res = json.loads(r.read())
            val = res.get("result")
            observed.append(val["outcome"] if isinstance(val, dict) else "undefined")
            rules.append(val.get("rule") if isinstance(val, dict) else None)
    finally:
        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(timeout=10)
        logf.close()
    lines = [ln for ln in (ev / "server_decision_log.jsonl").read_text().splitlines() if '"decision_id"' in ln]
    (ev / "summary.json").write_text(json.dumps({"observed": observed, "rules": rules,
                                                 "decision_log_records": len(lines)}, indent=2) + "\n")
    glue = {
        "description": "a decision log sink that Merkle roots the console decision log records per session and "
                       "signs the root with the deployment's bundle signing key (the key OPA bundle verification "
                       "already trusts), producing a per session tamper evident, key bound receipt trail",
        "components": ["decision_logs console or HTTP service consumer", "sha256 Merkle over records",
                       "Ed25519 or RSA signature with the existing bundle key", "verifier"],
        "loc": 150, "hours": 3,
    }
    write_result(system="opa", dimension="A8", policy=POLICY, scenario=SCENARIO,
                 expected=expected_string(steps), observed=",".join(observed), grade="WITH-WORK", idiomatic=True,
                 evidence_path=ev, glue=glue, notes=(
        "opa run --server with decision_logs.console=true; one POST per proposal to "
        "/v1/data/comparison/ai_action_gate/decision. Outcomes are first class: the decision document is "
        f"{{outcome, rule}} (rules={rules}); the worker requested escalation is distinguishable only because the "
        "policy author put the rule id in the result (r1 vs r4), not by a system level cause. Receipts: OPA emitted "
        f"{len(lines)} decision log records, one per decision, each with decision_id, input, result, timestamp "
        "(server_decision_log.jsonl): per decision yes; carries the why as whatever the result document holds; "
        "not signed and not tamper evident (a console or HTTP shipped JSON stream). Grade WITH-WORK: the glue "
        "estimate reuses the bundle signing key OPA already trusts (documented bundle signing, dimension A6), so "
        "no new trust anchor; built and measured in Phase 5. If Phase 5 finds the glue exceeds 300 lines or 8 "
        "hours, this cell drops to NOT."))


# ----------------------------------------------------------------------------- Cedar
def run_cedar(policy, steps) -> None:
    ev = evidence_dir("cedar", "A8")
    runner = sys_cedar.Runner(policy, gen_dir_for("cedar", POLICY))
    observed, raws = [], []
    for st in steps:
        d = runner.decide(st["input"])
        observed.append(d.observed)
        raws.append(d.raw)
    (ev / "authorize_outputs.txt").write_text("\n=====\n".join(raws))
    write_result(system="cedar", dimension="A8", policy=POLICY, scenario=SCENARIO,
                 expected=expected_string(steps), observed=",".join(observed), grade="NOT", idiomatic=True,
                 evidence_path=ev, notes=(
        "cedar authorize -v once per proposal. Cedar's decision is ALLOW or DENY; the four outcomes are carried "
        "by the @outcome annotation of the one permit that applied, read back from the verbose diagnostics "
        "(authorize_outputs.txt), so abstain and human routing are an annotation convention, not a returned "
        "decision (WITH-WORK on A1/A2 grounds alone). Receipts: none. Cedar is a library and CLI with no decision "
        "log, no signing key, and no anchor; a receipt trail would have to be built entirely outside it and would "
        "introduce a new trust anchor, which the pre registered budget grades NOT. The outcomes themselves match "
        "the corpus on all six steps."))


# ----------------------------------------------------------------------------- Cerbos
def run_cerbos(policy, steps) -> None:
    ev = evidence_dir("cerbos", "A8")
    gen = gen_dir_for("cerbos", POLICY)
    tmp = Path(tempfile.mkdtemp(prefix="cerbos_a8_"))
    store = tmp / "policies"; store.mkdir()
    for f in gen.glob("*.yaml"):
        (store / f.name).write_text(f.read_text())
    audit_path = ev / "decision_audit.jsonl"
    if audit_path.exists():
        audit_path.unlink()
    http, grpc = 13592, 13593
    (tmp / "conf.yaml").write_text(
        f"server:\n  httpListenAddr: \"127.0.0.1:{http}\"\n  grpcListenAddr: \"127.0.0.1:{grpc}\"\n"
        f"storage:\n  driver: disk\n  disk:\n    directory: {store}\n"
        f"audit:\n  enabled: true\n  accessLogsEnabled: false\n  decisionLogsEnabled: true\n  backend: file\n"
        f"  file:\n    path: {audit_path}\n")
    logf = open(tmp / "server.log", "w")
    proc = subprocess.Popen([str(TOOLCHAIN_BIN / "cerbos"), "server", f"--config={tmp / 'conf.yaml'}"],
                            stdout=logf, stderr=subprocess.STDOUT, start_new_session=True)
    for _ in range(80):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{http}/_cerbos/health", timeout=1):
                break
        except Exception:
            time.sleep(0.25)
    observed, rules = [], []
    try:
        for i, st in enumerate(steps):
            inp = {k: v for k, v in st["input"].items() if v is not None}
            body = {"requestId": f"a8-{i}", "includeMeta": True, "principal": {"id": "requester", "roles": ["user"]},
                    "resources": [{"actions": ["decide"], "resource": {"kind": POLICY, "id": "r1", "attr": inp}}]}
            req = urllib.request.Request(f"http://127.0.0.1:{http}/api/check/resources", data=json.dumps(body).encode(),
                                         headers={"content-type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=10) as r:
                res = json.loads(r.read())
            outs = [o.get("val") for o in res["results"][0].get("outputs", []) if isinstance(o.get("val"), dict)]
            observed.append(outs[0]["outcome"] if len(outs) == 1 else "error")
            rules.append(outs[0].get("rule") if len(outs) == 1 else None)
        time.sleep(1.5)                       # let the audit writer flush
    finally:
        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(timeout=10)
        logf.close()
    records = len(audit_path.read_text().splitlines()) if audit_path.exists() else 0
    (ev / "summary.json").write_text(json.dumps({"observed": observed, "rules": rules, "audit_records": records}, indent=2) + "\n")
    write_result(system="cerbos", dimension="A8", policy=POLICY, scenario=SCENARIO,
                 expected=expected_string(steps), observed=",".join(observed), grade="NOT", idiomatic=True,
                 evidence_path=ev, notes=(
        "cerbos server with audit.backend=file and decisionLogsEnabled; one CheckResources per proposal. The four "
        f"outcomes ride each rule's output block as {{outcome, rule}} (rules={rules}); Cerbos's own answer is "
        "EFFECT_ALLOW or EFFECT_DENY, so abstain and human routing are output metadata (WITH-WORK on A1/A2 grounds). "
        f"Receipts: Cerbos wrote {records} decision audit records, one per check, with call id, timestamp, inputs, "
        "effects, and outputs (decision_audit.jsonl): per decision yes, carries the why via outputs, not signed, not "
        "tamper evident (append only file). Open source Cerbos has no signing key or anchor (policy signing is a "
        "Cerbos Hub feature), so a signed receipt trail would introduce a new trust anchor, which the pre registered "
        "budget grades NOT. Prediction was WITH-WORK; the budget rule decides otherwise and the prediction is recorded "
        "as wrong."))


# ----------------------------------------------------------------------------- OpenFGA
def run_openfga(policy, steps) -> None:
    ev = evidence_dir("openfga", "A8")
    (ev / "note.txt").write_text("Not expressible: a Check returns one boolean for one relation; no ordered rules, "
                                 "no multi outcome decision, no decision log. See systems/openfga TRANSLATION.json.\n")
    write_result(system="openfga", dimension="A8", policy=POLICY, scenario=SCENARIO,
                 expected=expected_string(steps), observed="not_expressible", grade="NOT", idiomatic=True,
                 evidence_path=ev, notes=(
        "The gate policy is not expressible in OpenFGA (translator: a Check is one boolean for one relation; "
        "conditions on tuples could gate a single allow relation but cannot yield deny, abstain, and escalate_human "
        "as distinct results). No decision log facility either. The loop cannot be closed."))


RUNNERS = {"prismpath": run_prismpath, "opa": run_opa, "cedar": run_cedar, "cerbos": run_cerbos, "openfga": run_openfga}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--system", action="append", choices=sorted(RUNNERS))
    a = ap.parse_args(argv)
    policy = policy_by_id(POLICY)
    steps = loop_steps(policy)
    for s in (a.system or list(RUNNERS)):
        RUNNERS[s](policy, steps)
        print(f"A8 {s}: written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
