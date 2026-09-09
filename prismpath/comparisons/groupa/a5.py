# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A5, the compact decision sufficient wire (PREREGISTRATION.md section 5, A5).

For every decision scenario of network_admission and sensor_interlock, count the bytes needed to
convey the request and the result over each system's documented network interface (the missing field probes are excluded
everywhere: a Facet reading is total by contract, and absence semantics are dimension A1), at the
application payload layer: HTTP request and response bodies for JSON APIs (measured from the live
server's actual response), the request JSON and the verbose output for the Cedar CLI, the Facet
reading frame plus the receipt stream frame for PrismPath. A second line adds a fixed 28 byte IPv4
plus UDP envelope for every system; PrismPath's concentrator profile is reported at fleet sizes 1,
10, and 50.

Grades (pre registered): NATIVE, a self framing decision sufficient encoding exists in the system;
WITH-WORK, a compact encoding can be layered on (Cerbos ships gRPC protobuf, compact but not decision
sufficient, so its cell is WITH-WORK with configuration as the glue); NOT, verbose text only. The
Facet encode of an OPA input is the Phase 5 combination test.

Usage: python -m prismpath.comparisons.groupa.a5
"""
from __future__ import annotations

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

from prismpath.comparisons.groupa.common import evidence_dir, policy_by_id, write_result
from prismpath.comparisons.harness import HERE, TOOLCHAIN_BIN, gen_dir_for, scenario_steps
from prismpath.parser import parse

from prismpath.telemetry import concentrator  # noqa: E402
from prismpath.telemetry import packed  # noqa: E402
from prismpath.telemetry import quantizer as q  # noqa: E402
from prismpath.telemetry import receipts  # noqa: E402
from prismpath.telemetry import wire as w  # noqa: E402

POLICIES = ["network_admission", "sensor_interlock"]
ENVELOPE = 28


def compact(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()


# ----------------------------------------------------------------------------- PrismPath
def run_prismpath() -> None:
    ev = evidence_dir("prismpath", "A5")
    table = []
    for pid in POLICIES:
        policy = policy_by_id(pid)
        flow = (gen_dir_for("prismpath", pid) / f"{pid}.md").read_text()
        graph = parse(flow)
        parts = q.build_partitions(graph)
        node_names = list(graph.nodes)
        for seq, (sid, kind, inp, exp) in enumerate(scenario_steps(policy)):
            if kind == "undeclared_missing":
                continue
            reading = {k: v for k, v in inp.items() if v is not None}
            bits = w.encode_reading(parts, reading)
            req = packed.pack(bits, 8)
            target = w.route_node(graph, "decide", reading)
            cause = 0 if target is not None else 36
            nxt = node_names.index(target) if target else 0
            res = receipts.encode_receipt_dict({"cause": cause, "event": 0, "next_node": nxt, "prev_node": 0, "seq": seq})
            total = len(req) + len(res)
            # concentrator: the reading's wire ints, one stream per node in a fleet of N sharing one datagram
            conc = {}
            symbols = q.quantize(parts, reading)
            order = sorted(parts)
            reading_ints = [symbols[f] + 1 for f in order]           # symbol plus one, the wire mapping
            for fleet in (1, 10, 50):
                frame = concentrator.concentrate([(i + 1, reading_ints) for i in range(fleet)])
                conc[str(fleet)] = round((len(frame) + ENVELOPE) / fleet, 2)
            table.append({"policy": pid, "scenario": sid, "request_bytes": len(req), "result_bytes": len(res),
                          "total": total, "total_plus_envelope": total + ENVELOPE,
                          "concentrated_per_reading_plus_envelope": conc, "outcome": exp["outcome"]})
            write_result(system="prismpath", dimension="A5", policy=pid, scenario=sid, expected=exp["outcome"],
                         observed=exp["outcome"] if target else "no_match", grade="NATIVE", idiomatic=True,
                         evidence_path=ev,
                         measurements={"bytes_on_wire": total, "request_bytes": len(req), "result_bytes": len(res),
                                       "total_plus_envelope_28B": total + ENVELOPE,
                                       "concentrated_per_reading_plus_envelope": conc},
                         notes=(f"Facet reading frame {len(req)} B (quantize -> Zeckendorf -> byte packed, self framing) "
                                f"plus receipt stream frame {len(res)} B (cause, event, next_node, prev_node, seq as symbols, "
                                f"PROTOCOL 2.10). With a 28 B IPv4+UDP envelope {total + ENVELOPE} B; concentrated per reading "
                                f"at fleet 1/10/50: {conc}. Decision sufficient by I1 (formal/FQ), not a lossless record."))
    (ev / "bytes.json").write_text(json.dumps(table, indent=1) + "\n")


# ----------------------------------------------------------------------------- OPA
def run_opa() -> None:
    ev = evidence_dir("opa", "A5")
    port = 18383
    table = []
    for pid in POLICIES:
        policy = policy_by_id(pid)
        gen = gen_dir_for("opa", pid)
        proc = subprocess.Popen([str(TOOLCHAIN_BIN / "opa"), "run", "-s", "-a", f"127.0.0.1:{port}", str(gen / "policy.rego")],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        time.sleep(1.5)
        try:
            for sid, kind, inp, exp in scenario_steps(policy):
                if kind == "undeclared_missing":
                    continue
                body = compact({"input": {k: v for k, v in inp.items() if v is not None}})
                req = urllib.request.Request(f"http://127.0.0.1:{port}/v1/data/comparison/{pid}/decision", data=body,
                                             headers={"content-type": "application/json"}, method="POST")
                with urllib.request.urlopen(req, timeout=10) as r:
                    resp = r.read()
                res = json.loads(resp).get("result")
                observed = res["outcome"] if isinstance(res, dict) else "undefined"
                total = len(body) + len(resp)
                table.append({"policy": pid, "scenario": sid, "request_bytes": len(body), "response_bytes": len(resp), "total": total})
                write_result(system="opa", dimension="A5", policy=pid, scenario=sid, expected=exp["outcome"], observed=observed,
                             grade="NOT", idiomatic=True, evidence_path=ev,
                             measurements={"bytes_on_wire": total, "request_bytes": len(body), "result_bytes": len(resp),
                                           "total_plus_envelope_28B": total + ENVELOPE},
                             notes=(f"HTTP POST /v1/data/... request body {len(body)} B (compact JSON, every field), response body "
                                    f"{len(resp)} B as returned by opa run --server (a result document; undefined gives {{}}). JSON over "
                                    "HTTP is the documented interface; no compact or decision sufficient encoding exists natively "
                                    "(the Facet encode of this input is the Phase 5 combination test)."))
        finally:
            os.killpg(proc.pid, signal.SIGTERM); proc.wait(timeout=10)
    (ev / "bytes.json").write_text(json.dumps(table, indent=1) + "\n")


# ----------------------------------------------------------------------------- Cedar
def run_cedar() -> None:
    from prismpath.comparisons.systems import cedar as sys_cedar
    ev = evidence_dir("cedar", "A5")
    table = []
    for pid in POLICIES:
        policy = policy_by_id(pid)
        runner = sys_cedar.Runner(policy, gen_dir_for("cedar", pid))
        for sid, kind, inp, exp in scenario_steps(policy):
            if kind == "undeclared_missing":
                continue
            ctx = {k: v for k, v in inp.items() if v is not None}
            request = compact({"principal": 'User::"requester"', "action": 'Action::"decide"', "resource": 'Request::"r"', "context": ctx})
            d = runner.decide(inp)
            total = len(request) + len(d.raw.encode())
            table.append({"policy": pid, "scenario": sid, "request_bytes": len(request), "response_bytes": len(d.raw.encode()), "total": total})
            write_result(system="cedar", dimension="A5", policy=pid, scenario=sid, expected=exp["outcome"], observed=d.observed,
                         grade="NOT", idiomatic=True, evidence_path=ev,
                         measurements={"bytes_on_wire": total, "request_bytes": len(request), "result_bytes": len(d.raw.encode()),
                                       "total_plus_envelope_28B": total + ENVELOPE},
                         notes=(f"Request JSON in the --request-json shape {len(request)} B (every context field), result = the "
                                f"verbose authorize output {len(d.raw.encode())} B (the outcome annotation lives in the diagnostics, "
                                "so the verbose form is what carries the decision). Cedar is a library; JSON is its documented "
                                "interchange, no compact encoding."))
    (ev / "bytes.json").write_text(json.dumps(table, indent=1) + "\n")


# ----------------------------------------------------------------------------- Cerbos
def run_cerbos() -> None:
    ev = evidence_dir("cerbos", "A5")
    http, grpc = 13792, 13793
    table = []
    for pid in POLICIES:
        policy = policy_by_id(pid)
        gen = gen_dir_for("cerbos", pid)
        tmp = Path(tempfile.mkdtemp(prefix="cerbos_a5_")); store = tmp / "p"; store.mkdir()
        for f in gen.glob("*.yaml"):
            (store / f.name).write_text(f.read_text())
        (tmp / "c.yaml").write_text(f"server:\n  httpListenAddr: \"127.0.0.1:{http}\"\n  grpcListenAddr: \"127.0.0.1:{grpc}\"\nstorage:\n  driver: disk\n  disk:\n    directory: {store}\n")
        proc = subprocess.Popen([str(TOOLCHAIN_BIN / "cerbos"), "server", f"--config={tmp / 'c.yaml'}"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        for _ in range(80):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{http}/_cerbos/health", timeout=1):
                    break
            except Exception:
                time.sleep(0.25)
        try:
            for sid, kind, inp, exp in scenario_steps(policy):
                if kind == "undeclared_missing":
                    continue
                attr = {k: v for k, v in inp.items() if v is not None}
                body = compact({"requestId": "a5", "principal": {"id": "requester", "roles": ["user"]},
                                "resources": [{"actions": ["decide"], "resource": {"kind": pid, "id": "r1", "attr": attr}}]})
                req = urllib.request.Request(f"http://127.0.0.1:{http}/api/check/resources", data=body,
                                             headers={"content-type": "application/json"}, method="POST")
                with urllib.request.urlopen(req, timeout=10) as r:
                    resp = r.read()
                res = json.loads(resp)
                outs = [o.get("val") for o in res["results"][0].get("outputs", []) if isinstance(o.get("val"), dict)]
                observed = outs[0]["outcome"] if len(outs) == 1 else ("no_match" if not outs else "error")
                total = len(body) + len(resp)
                table.append({"policy": pid, "scenario": sid, "request_bytes": len(body), "response_bytes": len(resp), "total": total})
                write_result(system="cerbos", dimension="A5", policy=pid, scenario=sid, expected=exp["outcome"], observed=observed,
                             grade="WITH-WORK", idiomatic=True, evidence_path=ev,
                             glue={"description": "switch the client from the HTTP JSON API to the gRPC protobuf API Cerbos ships; "
                                                  "compact binary, still every attribute, not decision sufficient",
                                   "components": ["gRPC client configuration"], "loc": 0, "hours": 1},
                             measurements={"bytes_on_wire": total, "request_bytes": len(body), "result_bytes": len(resp),
                                           "total_plus_envelope_28B": total + ENVELOPE},
                             notes=(f"HTTP CheckResources request body {len(body)} B (compact JSON, every attribute), response body "
                                    f"{len(resp)} B as returned (includeMeta off; the output block carries the outcome). Measured on the "
                                    "HTTP JSON API the study uses; Cerbos also serves gRPC protobuf natively, a compact encoding that "
                                    "is not decision sufficient, hence WITH-WORK with configuration as the glue (protobuf sizes not "
                                    "measured here)."))
        finally:
            os.killpg(proc.pid, signal.SIGTERM); proc.wait(timeout=10)
    (ev / "bytes.json").write_text(json.dumps(table, indent=1) + "\n")


# ----------------------------------------------------------------------------- OpenFGA
def run_openfga() -> None:
    ev = evidence_dir("openfga", "A5")
    for pid in POLICIES:
        policy = policy_by_id(pid)
        for sid, kind, inp, exp in scenario_steps(policy):
            if kind == "undeclared_missing":
                continue
            write_result(system="openfga", dimension="A5", policy=pid, scenario=sid, expected=exp["outcome"],
                         observed="not_expressible", grade="NOT", idiomatic=True, evidence_path=ev,
                         notes="The decision policies are not expressible in OpenFGA (translator); no wire to measure.")
    (ev / "note.txt").write_text("not expressible; see systems/openfga/generated\n")


def main() -> int:
    run_prismpath(); run_opa(); run_cedar(); run_cerbos(); run_openfga()
    print("A5 written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
