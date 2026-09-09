# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Phase 5: the combination column opa+glue for every Group A dimension (PREREGISTRATION.md sections
5, 9, 10). OPA is the direct comparator and every pre registered combination test names it, so the
one combination column is OPA plus the glue built in comparisons/glue/, each piece run here for real
and measured against the section 4 budget (300 lines, 8 hours, no new trust anchor):

  A1, A2  OPA alone is NATIVE; the combination adds nothing and the OPA rows are mirrored.
  A3      written by groupa/a3_opa_mcu.py from the RP2350 run (OPA wasm under wasm3).
  A4, A8  glue/opa_receipts.py: OPA ships decision logs to the sink, which Merkle roots them and signs
          the root with the bundle signing key OPA already trusts; receipts verified, tamper detected.
  A5      glue/facet_opa_input.py: Facet frame in, representative reading to OPA, decision compared.
  A6      glue/opa_revision_floor.py: the floor refuses the stale bundle before OPA loads it; OPA's own
          signature check refuses the tampered and unsigned bundles.
  A7      OPA's timeout configuration mirrored (WITH-WORK with zero lines, the same as the OPA cell).

Usage: python -m prismpath.comparisons.groupa.phase5
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

from prismpath.comparisons.glue import facet_opa_input as facet
from prismpath.comparisons.glue import opa_receipts, opa_revision_floor
from prismpath.comparisons.groupa.common import RESULTS, evidence_dir, policy_by_id, write_result
from prismpath.comparisons.harness import HERE, TOOLCHAIN_BIN, gen_dir_for, scenario_steps

OPA = str(TOOLCHAIN_BIN / "opa")
SYS = "opa+glue"
GLUE = HERE / "glue"


def loc(path: Path) -> int:
    return sum(1 for l in path.read_text().splitlines() if l.strip() and not l.strip().startswith("#"))


HOURS = {"opa_receipts.py": 1.0, "opa_revision_floor.py": 0.5, "facet_opa_input.py": 0.5}


def glue_record(desc: str, files: List[str], components: List[str]) -> Dict[str, Any]:
    return {"description": desc, "components": components, "loc": sum(loc(GLUE / f) for f in files), "hours": sum(HOURS[f] for f in files)}


def mirror(dim: str, note: str) -> None:
    for f in sorted((RESULTS / "opa").glob(f"{dim}__*.json")):
        d = json.loads(f.read_text())
        write_result(system=SYS, dimension=dim, policy=d["policy"], scenario=d["scenario"], expected=d["expected"], observed=d["observed"],
                     grade=d["grade"], idiomatic=d["idiomatic"], evidence_path=Path(d["evidence_path"]), glue=d.get("glue"),
                     notes=note + " OPA cell: " + d["notes"][:400])


def start_opa(args: List[str], logf) -> subprocess.Popen:
    return subprocess.Popen([OPA, "run", "-s"] + args, stdout=logf, stderr=subprocess.STDOUT, start_new_session=True)


def stop(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGTERM); proc.wait(timeout=10)
    except Exception:
        pass


def keys(tmp: Path) -> None:
    subprocess.run(["openssl", "genrsa", "-out", str(tmp / "priv.pem"), "2048"], check=True, capture_output=True)
    subprocess.run(["openssl", "rsa", "-in", str(tmp / "priv.pem"), "-pubout", "-out", str(tmp / "pub.pem")], check=True, capture_output=True)


# ----------------------------------------------------------------------------- A4 and A8: receipts
def run_receipts() -> None:
    ev4, ev8 = evidence_dir(SYS, "A4"), evidence_dir(SYS, "A8")
    policy = policy_by_id("ai_action_gate")
    steps = next(s for s in policy["scenarios"] if s["id"] == "ai_worker_loop_1")["steps"]
    tmp = Path(tempfile.mkdtemp(prefix="p5_receipts_")); keys(tmp)
    sink = opa_receipts.Sink(private_key_pem=(tmp / "priv.pem").read_bytes()); sport = sink.start()
    cfg = tmp / "opa.yaml"
    cfg.write_text(f"services:\n  sink:\n    url: http://127.0.0.1:{sport}\ndecision_logs:\n  service: sink\n  reporting:\n    min_delay_seconds: 1\n    max_delay_seconds: 2\n")
    port = 18191
    with open(ev8 / "opa_server.log", "w") as lf:
        proc = start_opa(["-a", f"127.0.0.1:{port}", "-c", str(cfg), str(gen_dir_for("opa", "ai_action_gate") / "policy.rego")], lf)
        observed, rules, ids = [], [], []
        try:
            time.sleep(1.5)
            for st in steps:
                inp = {k: v for k, v in st["input"].items() if v is not None}
                res, _, _ = facet.opa_decide(f"http://127.0.0.1:{port}/v1/data/comparison/ai_action_gate/decision", inp)
                observed.append(res["outcome"] if isinstance(res, dict) else "undefined"); rules.append(res.get("rule") if isinstance(res, dict) else None)
            # decision ids come with the log records; wait for OPA to ship them
            for _ in range(60):
                if len(sink.records) >= len(steps):
                    break
                time.sleep(0.5)
        finally:
            stop(proc)
    records = list(sink.records); sink.stop()
    pub = (tmp / "pub.pem").read_bytes()
    receipts = [sink.receipt_for(r["decision_id"]) for r in records]
    verified = [opa_receipts.verify_receipt(rc, pub) for rc in receipts]
    tampered = json.loads(json.dumps(receipts[0])); tampered["record"]["result"] = {"outcome": "allow", "rule": "r1"}
    tamper_detected = not opa_receipts.verify_receipt(tampered, pub)
    other = Path(tempfile.mkdtemp(prefix="p5_otherkey_")); keys(other)
    wrong_key_rejected = not opa_receipts.verify_receipt(receipts[0], (other / "pub.pem").read_bytes())
    (ev8 / "receipts.jsonl").write_text("".join(json.dumps(r) + "\n" for r in receipts))
    (ev8 / "summary.json").write_text(json.dumps({"observed": observed, "rules": rules, "records": len(records), "verified": verified,
                                                  "tamper_detected": tamper_detected, "wrong_key_rejected": wrong_key_rejected,
                                                  "signing": "RS256 with the bundle signing key (openssl RSA 2048, the key opa build --signing-key would use)"}, indent=2) + "\n")
    ok = len(records) == len(steps) and all(verified) and tamper_detected and wrong_key_rejected
    g = glue_record("a decision log HTTP service that receives OPA's decision_logs uploads, Merkle roots the records, signs the root with the "
                    "deployment's bundle signing key (RS256, the algorithm and key OPA bundle verification already trusts), and hands out per "
                    "decision receipts with inclusion proofs that a third party verifies with the bundle verification public key",
                    ["opa_receipts.py"], ["decision_logs.service consumer", "sha256 Merkle root and inclusion paths", "RS256 signature with the existing bundle key", "verifier"])
    within = g["loc"] <= 300 and g["hours"] <= 8
    grade = "WITH-WORK" if ok and within else "NOT"
    base = (f"Built and run: OPA shipped {len(records)} decision log records for {len(steps)} decisions to glue/opa_receipts.py over decision_logs.service; "
            f"{sum(verified)}/{len(receipts)} receipts verify against the bundle verification key, an altered record is detected ({tamper_detected}), a "
            f"foreign key is rejected ({wrong_key_rejected}). Glue {g['loc']} lines, {g['hours']} h, {'within' if within else 'OVER'} budget; the signing key "
            "is the bundle key the deployment already holds at the bundle service, so no new trust anchor; note that the sink must run where that "
            "private key lives, which is the bundle server, not the agent host.")
    subs = {"per_decision": ("NATIVE", None, "one record per decision from OPA itself"),
            "signed": (grade, g, "the session root is signed with the existing bundle key by the glue"),
            "tamper_evident": (grade, g, "Merkle inclusion proofs from the glue; the altered record failed verification"),
            "carries_cause": ("NATIVE", None, "the record carries the policy's result document {outcome, rule}")}
    for sub, (gr, gl, note) in subs.items():
        write_result(system=SYS, dimension="A4", policy="ai_action_gate", scenario=sub, expected="true", observed="true" if (gr != "NOT") else "false",
                     grade=gr, idiomatic=True, evidence_path=ev8, glue=gl, notes=f"Sub property {sub}: {note}. {base}")
    expected = ",".join(st["expected"]["outcome"] for st in steps)
    write_result(system=SYS, dimension="A8", policy="ai_action_gate", scenario="ai_worker_loop_1", expected=expected, observed=",".join(observed),
                 grade=grade, idiomatic=True, evidence_path=ev8, glue=g,
                 notes=("The six proposal loop through OPA with the receipt sink attached: outcomes are first class (rules=" + str(rules) + "), the worker "
                        "requested escalation is told apart only by the rule id the author put in the result, and every decision now has a verifiable, "
                        "key bound receipt carrying that result document as its cause. " + base))
    print(f"A4/A8 receipts: records={len(records)} verified={sum(verified)} tamper_detected={tamper_detected} grade={grade} loc={g['loc']}")


# ----------------------------------------------------------------------------- A5: Facet encode OPA input
def run_facet() -> None:
    ev = evidence_dir(SYS, "A5")
    table = []
    port = 18192
    g = glue_record("Facet frame from the sender (PrismPath's quantizer over the same policy), decoded to a representative reading and posted as "
                    "OPA's input JSON; the response stays OPA's JSON result document", ["facet_opa_input.py"],
                    ["quantizer partitions from the policy", "Zeckendorf packed frame", "decode to representative", "OPA REST call"])
    for pid in ("network_admission", "sensor_interlock"):
        policy = policy_by_id(pid)
        parts = facet.partitions_for((gen_dir_for("prismpath", pid) / f"{pid}.md").read_text())
        with open(ev / f"opa_{pid}.log", "w") as lf:
            proc = start_opa(["-a", f"127.0.0.1:{port}", str(gen_dir_for("opa", pid) / "policy.rego")], lf)
            try:
                time.sleep(1.5)
                url = f"http://127.0.0.1:{port}/v1/data/comparison/{pid}/decision"
                for sid, kind, inp, exp in scenario_steps(policy):
                    if kind == "undeclared_missing" or any(v is None for v in inp.values()):
                        continue
                    reading = dict(inp)
                    frame = facet.encode(parts, reading)
                    rep = facet.decode(parts, frame)
                    direct, req_direct, resp_direct = facet.opa_decide(url, reading)
                    via, _, resp_via = facet.opa_decide(url, rep)
                    same = direct == via and (direct or {}).get("outcome") == exp["outcome"]
                    row = {"policy": pid, "scenario": sid, "frame_bytes": len(frame), "json_request_bytes": req_direct, "response_bytes": resp_via,
                           "direct": direct, "via_facet": via, "representative": rep, "identical": same, "expected": exp["outcome"]}
                    table.append(row)
                    write_result(system=SYS, dimension="A5", policy=pid, scenario=sid, expected=exp["outcome"],
                                 observed=(via or {}).get("outcome", "undefined") if isinstance(via, dict) else "undefined",
                                 grade="WITH-WORK" if same else "NOT", idiomatic=True, evidence_path=ev, glue=g if same else None,
                                 measurements={"bytes_on_wire": len(frame) + resp_via, "request_bytes": len(frame), "result_bytes": resp_via,
                                               "json_request_bytes_direct": req_direct, "total_plus_envelope_28B": len(frame) + resp_via + 28},
                                 notes=(f"Facet frame {len(frame)} B replaces OPA's {req_direct} B JSON request; the receiver reconstructs {rep} and OPA "
                                        f"decides {via}, {'identical to' if same else 'DIFFERENT from'} its decision on the original reading {direct}. "
                                        f"The response stays OPA's {resp_via} B JSON document, so the round trip is {len(frame) + resp_via} B against "
                                        f"PrismPath's 4 to 6 B frame plus receipt. Finding as pre registered: Facet is a transport that composes with "
                                        f"OPA (glue {g['loc']} lines, {g['hours']} h), which is a real but different claim from a moat."))
            finally:
                stop(proc)
    (ev / "bytes.json").write_text(json.dumps(table, indent=1, default=str) + "\n")
    n = sum(1 for r in table if r["identical"])
    print(f"A5 facet over OPA: {n}/{len(table)} identical; frames {sorted(set(r['frame_bytes'] for r in table))} B vs JSON {sorted(set(r['json_request_bytes'] for r in table))} B")


# ----------------------------------------------------------------------------- A6: revision floor
def run_floor() -> None:
    ev = evidence_dir(SYS, "A6")
    tmp = Path(tempfile.mkdtemp(prefix="p5_floor_")); keys(tmp)
    src = tmp / "src"; src.mkdir(); shutil.copy(gen_dir_for("opa", "network_admission") / "policy.rego", src / "policy.rego")

    def build(rev: str, out: str, signed: bool = True) -> Path:
        cmd = [OPA, "build", "-b", str(src), "-r", rev, "-o", str(tmp / out)]
        if signed:
            cmd += ["--signing-key", str(tmp / "priv.pem"), "--signing-alg", "RS256"]
        subprocess.run(cmd, check=True, capture_output=True); return tmp / out

    v2, v1, v3, unsigned = build("2", "v2.tar.gz"), build("1", "v1.tar.gz"), build("3", "v3.tar.gz"), build("4", "unsigned.tar.gz", False)
    with tarfile.open(v3, "r:gz") as tf:
        members = [(m, tf.extractfile(m).read() if m.isfile() else None) for m in tf.getmembers()]
    tampered = tmp / "v3_tampered.tar.gz"
    import io
    with tarfile.open(tampered, "w:gz") as tf:
        for m, data in members:
            if m.isfile() and m.name.endswith("policy.rego"):
                data = data.replace(b'"deny"', b'"allow"', 1); m.size = len(data)
            tf.addfile(m, io.BytesIO(data) if data is not None else None)
    state = tmp / "floor.json"
    out: Dict[str, Any] = {}

    def attempt(name: str, bundle: Path, port: int) -> Dict[str, Any]:
        ok, reason = opa_revision_floor.Floor(str(state)).check(str(bundle))
        rec = {"floor_check": ok, "floor_reason": reason, "opa_loaded": None}
        if ok:
            proc = opa_revision_floor.activate(str(bundle), str(state), OPA, str(tmp / "pub.pem"), port)
            loaded = False
            try:
                for _ in range(20):
                    time.sleep(0.25)
                    try:
                        res, _, _ = facet.opa_decide(f"http://127.0.0.1:{port}/v1/data/comparison/network_admission/decision",
                                                     {"protocol": 6, "dst_port": 443, "pkt_len": 800, "src_internal": False})
                        loaded = isinstance(res, dict); break
                    except Exception:
                        if proc is not None and proc.poll() is not None:
                            break
            finally:
                if proc is not None:
                    stop(proc)
            rec["opa_loaded"] = loaded
        out[name] = rec; return rec

    attempt("baseline_v2", v2, 18201)
    attempt("stale_policy_1", v1, 18202)
    attempt("tampered_policy_1", tampered, 18203)
    attempt("unsigned_policy_1", unsigned, 18204)
    out["floor_state_after"] = json.loads(state.read_text())
    (ev / "floor_results.json").write_text(json.dumps(out, indent=2) + "\n")
    g = glue_record("a wrapper on the agent host that reads the bundle's .manifest revision, refuses anything below the persisted floor before "
                    "opa loads it, persists the accepted revision with fsync, and only then starts opa with bundle verification on",
                    ["opa_revision_floor.py"], ["manifest revision reader", "fsync'd floor file", "opa run wrapper"])
    within = g["loc"] <= 300 and g["hours"] <= 8
    expect_refused = {"stale_policy_1": "the floor refused the older signed revision before OPA loaded it",
                      "tampered_policy_1": "the floor accepted revision 3 and OPA's own signature verification then refused the altered bundle",
                      "unsigned_policy_1": "the floor accepted revision 4 and OPA refused the unsigned bundle under --verification-key"}
    for sid, how in expect_refused.items():
        rec = out[sid]
        refused = (not rec["floor_check"]) or (rec["opa_loaded"] is False)
        write_result(system=SYS, dimension="A6", policy="network_admission", scenario=sid, expected="refuse_policy",
                     observed="refuse_policy" if refused else "accepted", grade="WITH-WORK" if (refused and within) else "NOT", idiomatic=True,
                     evidence_path=ev, glue=g if refused else None,
                     notes=(f"{how}: floor_check={rec['floor_check']} ({rec['floor_reason']}), opa_loaded={rec['opa_loaded']}. Baseline v2 loaded "
                            f"({out['baseline_v2']['opa_loaded']}); floor after the sequence {out['floor_state_after']}. Glue {g['loc']} lines, "
                            f"{g['hours']} h, {'within' if within else 'OVER'} budget, no new trust anchor (the verification key is OPA's own). "
                            "Caveat recorded: the floor persists a revision before OPA verifies the signature, so a tampered bundle with a very "
                            "high revision could raise the floor and lock out later legitimate bundles; ordering the floor after verification "
                            "needs OPA to expose the verified manifest, which the wrapper does not have."))
    print(f"A6 floor: {json.dumps({k: (v['floor_check'], v['opa_loaded']) for k, v in out.items() if isinstance(v, dict) and 'floor_check' in v})}")


def main(argv=None) -> int:
    mirror("A1", "OPA alone grades NATIVE on this dimension (Rego returns any document); the combination column carries the OPA result unchanged.")
    mirror("A2", "OPA alone grades NATIVE on this dimension; the combination column carries the OPA result unchanged.")
    mirror("A7", "No glue can add a bound; the combination carries OPA's timeout configuration cell unchanged (WITH-WORK, zero lines).")
    run_receipts(); run_facet(); run_floor()
    print("phase5 opa+glue rows written (A3 comes from groupa/a3_opa_mcu.py)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
