# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""One flow, end to end, through the installed Python package and the extracted Rust candidates, with
the two compared at every seam.

The Python chain runs under the interpreter this script is started with, which the acceptance run
points at the virtual environment holding the built wheel, and the script refuses to run from a
source tree. The chain: author a flow and its fixture; validate, test, verify and classify it with
the command line; run it through the engine on a set of readings; route the same readings through
the Facet layer and require the engine and the wire to agree; compile the image; make keys, an
envelope and a signed pack; verify, swap and attest through the policy host and read the audit log
back through the trail; encode every reading to the wire, decode it and require the decoded reading
to route as the original; encode and decode a receipt per decision; seal the stream into a durable
journal and reopen it; run preflight; and drive Mission Control through the same steps over HTTP.

The Rust chain is a generated program built against the four extracted candidate crates: the same
flow parsed by the Rust kernel, the same readings run through its engine and routed through its
Facet layer, encoded to the wire, decoded and routed again, the Python signed pack verified by the
Rust hot swap crate, and the Rust preflight binary run on the same sample. Every result is compared
with the Python result: engine paths, routes, wire bits, framed bytes, decoded routes, the pack
verdict and the preflight report. A disagreement fails the gate and names the seam.

    python tools/end_to_end.py --candidates <dir with the extracted crates> --out <dir>
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

FLOW = """---
name: perimeter
start: assess
---

## assess
Read the perimeter summary. Emit `temp`, `armed` and `zone`.
-> lockdown: when armed and temp >= 90
-> alert: when temp >= 90
-> restricted: when zone == "vault"
-> watch: when temp >= 50
-> clear: else

## lockdown
Seal the perimeter and page the duty officer.

## alert
Page the duty officer.

## restricted
Hold entry to the vault zone until a person clears it.

## watch
Log and keep watching.

## clear
Nothing to do.
"""
FIXTURE = """| node   | outcome                   | fields                                | expect     |
|--------|---------------------------|---------------------------------------|------------|
| assess | armed breach, hot         | temp=95; armed=true; zone=lobby       | lockdown   |
| assess | hot but disarmed          | temp=95; armed=false; zone=lobby      | alert      |
| assess | vault door opened         | temp=20; armed=false; zone=vault      | restricted |
| assess | warm evening              | temp=60; armed=false; zone=lobby      | watch      |
| assess | quiet night               | temp=20; armed=false; zone=lobby      | clear      |
"""
READINGS = [
    {"temp": 95, "armed": True, "zone": "lobby"},
    {"temp": 95, "armed": False, "zone": "lobby"},
    {"temp": 20, "armed": False, "zone": "vault"},
    {"temp": 60, "armed": False, "zone": "lobby"},
    {"temp": 20, "armed": False, "zone": "lobby"},
    {"temp": 90, "armed": 1, "zone": "vault"},
]
# A value the boundary refuses, carried through both encoders to the same refusal. Until the promotion
# to research a0cccf8 this string was a reading the encoders parsed; since then parsing is the adapter's
# job, and the encoders name the field and the reason instead (acceptance corpus version 2).
REFUSED_READING = {"temp": "90", "armed": 1, "zone": "vault"}
RUST_PROGRAM = r"""//! The Rust half of the end to end run: the same flow and readings through the extracted candidate
//! crates, results as JSON for the Python side to compare seam by seam.
use prismpath_rs::{parse, run, Graph, RunOpts, Value};
use prismpath_telemetry_rs::{packed, quantizer, wire};
use std::collections::HashMap;

fn reading_of(json: &serde_json::Value) -> HashMap<String, Value> {
    json.as_object().unwrap().iter().map(|(key, value)| (key.clone(), Value::from_json(value))).collect()
}

fn engine_path(graph: &Graph, outcome: &HashMap<String, Value>) -> (Vec<String>, String) {
    let fields: Vec<(String, Value)> = outcome.iter().map(|(key, value)| (key.clone(), value.clone())).collect();
    let agent = |node: &str, _instruction: &str, _state: &prismpath_rs::engine::RunState| -> Result<Value, String> {
        if node == "assess" { Ok(Value::Obj(fields.clone())) } else { Ok(Value::Obj(vec![("text".to_string(), Value::Str(node.to_string()))])) }
    };
    let result = run(graph, agent, RunOpts::default()).expect("engine run");
    (result.path, result.stopped)
}

fn main() {
    let job_path = std::env::args().nth(1).expect("job path");
    let job: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&job_path).expect("read job")).expect("parse job");
    let graph = parse(job["flow"].as_str().unwrap());
    let parts = quantizer::build_partitions(&graph).expect("a Level M flow the codec carries");
    let mut results = Vec::new();
    for (raw_json, accepted_json) in job["readings"].as_array().unwrap().iter().zip(job["accepted"].as_array().unwrap()) {
        let raw = reading_of(raw_json);
        let accepted = reading_of(accepted_json);
        let (path, stopped) = engine_path(&graph, &accepted);
        let bits = wire::encode_reading_checked(&parts, &raw).expect("checked encode");
        let frame = packed::pack(&bits, 8);
        let decoded = wire::decode_reading(&parts, &packed::unpack(&frame)).expect("decode");
        results.push(serde_json::json!({
            "raw_route": wire::route_node(&graph, "assess", &raw),
            "engine_path": path, "stopped": stopped,
            "route": wire::route_node(&graph, "assess", &accepted),
            "bits": bits, "frame_hex": hex_of(&frame),
            "decoded_route": wire::route_node(&graph, "assess", &decoded),
        }));
    }
    let refused = match wire::encode_reading_checked(&parts, &reading_of(&job["refused"])) {
        Err(error) => serde_json::json!({"field": error.field, "reason": error.refusal.reason()}),
        Ok(_) => serde_json::json!({"encoded": true}),
    };
    let (ok, reasons, _manifest) = prismpath_hotswap_rs::verify_pack(job["ppt"].as_str().unwrap(), &[job["pub"].as_str().unwrap().to_string()], &[]);
    let (level_m, _non_member) = prismpath_rs::flow_level_m(&graph);
    println!("{}", serde_json::json!({"readings": results, "refused": refused, "pack_verify": {"ok": ok, "reasons": reasons}, "level_m": level_m}));
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
"""


def sh(*command, cwd=None, env=None, check=True):
    completed = subprocess.run(list(command), cwd=cwd, env=env, capture_output=True, text=True)
    if check and completed.returncode != 0:
        raise SystemExit(f"command failed ({completed.returncode}): {' '.join(command)}\n{completed.stdout[-1500:]}\n{completed.stderr[-1500:]}")
    return completed


def require(condition, seam, detail=""):
    if not condition:
        raise SystemExit(f"end to end FAILED at seam: {seam}. {detail}")


def accepted_reading(parts, reading: dict) -> dict:
    """The reading as the wire carries it: every decision field through its acceptance rule."""
    from prismpath.telemetry import quantizer
    accepted = dict(reading)
    for field, partition in parts.items():
        refusal, value = quantizer.accept_value(partition.kind, reading.get(field))
        require(refusal is None, "acceptance", f"field {field} refused ({refusal}) in {reading}")
        accepted[field] = value
    return accepted


def python_chain(work: Path, report: dict) -> dict:
    import prismpath
    require("site-packages" in prismpath.__file__, "installed package", f"prismpath imported from {prismpath.__file__}")
    from prismpath.kernel.engine import run
    from prismpath.kernel.parser import parse_file
    from prismpath.hotswap import policy_pack
    from prismpath.kernel import causes
    from prismpath.ledgers.audit_log import AuditLog
    from prismpath.telemetry import epoch_journal, packed, quantizer, receipts, wire

    (work / "flows").mkdir(parents=True, exist_ok=True)
    flow = work / "flows" / "perimeter.md"
    flow.write_text(FLOW)
    (work / "flows" / "perimeter.tests.md").write_text(FIXTURE)
    (work / "sample.ndjson").write_text("".join(json.dumps(reading) + "\n" for reading in READINGS))
    python = sys.executable
    cli = [python, "-m", "prismpath"]
    for command in (["validate"], ["test"], ["verify"], ["capability"], ["portable"]):
        completed = sh(*cli, *command, str(flow), cwd=work)
        report[f"cli {command[0]}"] = "ok"
    graph = parse_file(str(flow))
    parts = quantizer.build_partitions(graph)
    outcomes = []
    stream_bits = []
    accepted_readings = []
    node_index = {name: index for index, name in enumerate(graph.nodes)}
    for sequence, reading in enumerate(READINGS):
        # The wire carries the accepted reading: the value each field's acceptance rule converts the
        # raw value into (a 0 or 1 on a boolean field becomes the bool, an integral float the integer).
        # The engine on the raw reading may decide differently, and the report records both routes.
        accepted = accepted_reading(parts, reading)
        raw_route = wire.route_node(graph, "assess", reading)
        route = wire.route_node(graph, "assess", accepted)

        def worker(node, instruction, state, outcome=accepted):
            return dict(outcome) if node == "assess" else {"text": node}
        result = run(graph, worker, max_steps=25)
        require(result.stopped == "terminal" and result.path[-1] == route, "engine versus Facet routing",
                f"reading {reading}: engine path {result.path}, wire route {route}")
        bits = wire.encode_reading_checked(parts, reading)
        frame = packed.pack(bits, 8)
        decoded = wire.decode_reading(parts, packed.unpack(frame))
        decoded_route = wire.route_node(graph, "assess", decoded)
        require(decoded_route == route, "Facet decode preserves the decision", f"reading {reading}: {route} became {decoded_route}")
        receipt = {"seq": sequence, "prev_node": node_index["assess"], "event": 0, "next_node": node_index[route], "cause": causes.CAUSE_NONE}
        decoded_receipt = receipts.decode_receipt(receipts.encode_receipt_dict(receipt))
        require(decoded_receipt.refusal_cause == "ok", "receipt round trip", str(decoded_receipt))
        require(decoded_receipt.receipt["next_node"] == receipt["next_node"] and decoded_receipt.receipt["seq"] == sequence, "receipt fields", str(decoded_receipt))
        stream_bits.append(bits)
        accepted_readings.append(accepted)
        outcomes.append({"raw_route": raw_route, "engine_path": result.path, "stopped": result.stopped, "route": route,
                         "bits": bits, "frame_hex": frame.hex(), "decoded_route": decoded_route})
    report["readings"] = outcomes
    # the image, the keys, the envelope, the pack, verify, swap, attest, and the trail
    sh(python, "-m", "prismpath.kernel.ppt_compile", str(flow), "-o", "perimeter.ppt", "--json", "perimeter.names.json", cwd=work)
    image = (work / "perimeter.ppt").read_bytes()
    header = policy_pack.read_ppt_header(image)
    ok, reasons = policy_pack.validate_image(image)
    require(ok, "image validates", str(reasons))
    report["image"] = {"bytes": len(image), "sha256": policy_pack.sha256_hex(image), "header": {key: header[key] for key in ("n_nodes", "n_edges") if key in header}}
    sh(*cli, "swap", "keygen", "--out", "keys", "--name", "authority", cwd=work)
    fields = "temp:int,armed:bool,zone:str"
    sh(*cli, "swap", "envelope", "--envelope-id", "env1", "--fields", fields, "--caps", "atoms=1024,nodes=256",
       "--priv", "keys/authority.key", "--pub", "keys/authority.pub", "--out", "env", cwd=work)
    sh(*cli, "swap", "pack", "--ppt", "perimeter.ppt", "--fields", fields, "--priv", "keys/authority.key", "--pub", "keys/authority.pub", "--version", "1", cwd=work)
    verified = json.loads(sh(*cli, "swap", "verify", "--ppt", "perimeter.ppt", "--pub", "keys/authority.pub", cwd=work).stdout)
    require(verified["ok"] is True, "pack verify (Python)", str(verified))
    swapped = json.loads(sh(*cli, "swap", "swap", "--ppt", "perimeter.ppt", "--pub", "keys/authority.pub", "--envelope", "env/env1.envelope", "--out", "state", cwd=work).stdout)
    require(swapped.get("ok") is True and swapped.get("active") == report["image"]["sha256"], "policy host swap", str(swapped))
    attested = json.loads(sh(*cli, "swap", "attest", "--pub", "keys/authority.pub", "--envelope", "env/env1.envelope", "--out", "state", cwd=work).stdout)
    require(attested.get("active") == report["image"]["sha256"] and attested.get("version") == 1, "attestation names the active image", str(attested))
    trail = json.loads(sh(*cli, "trail", "state/swaps.log", "--json", cwd=work).stdout)
    audit = AuditLog(str(work / "state" / "swaps.log"))
    require(audit.verify_log() and audit.verify_persisted(), "audit log verifies and is persisted", "")
    actions = [event["action"] for event in audit.events]
    require("swap" in actions and "attestation" in actions, "trail carries the swap and the attestation", str(actions))
    report["trail"] = {"events": len(audit.events), "actions": actions, "root": audit.current_root()}
    # the durable journal over the wire stream
    journal = epoch_journal.EpochJournal(str(work / "journal"), block_bits=64, max_data_epochs=4)
    journal.seal("".join(stream_bits))
    reopened = epoch_journal.EpochJournal(str(work / "journal"), block_bits=64, max_data_epochs=4)
    require(reopened.recovery_report() == [] and reopened.verify_chain() and reopened.retained(), "journal survives a reopen", str(reopened.recovery_report()))
    report["journal"] = {"chain": reopened.chain()}
    # preflight on the same sample, run the way an operator runs it
    sh(python, "-m", "prismpath.telemetry.preflight", "flows/perimeter.md", "sample.ndjson", "--json", "preflight_python.json", cwd=work)
    preflight_python = json.loads((work / "preflight_python.json").read_text())
    require(preflight_python["ready"] is True and preflight_python["refused_by_field"] == {}, "Python preflight READY", json.dumps(preflight_python)[:400])
    report["preflight_python"] = {"ready": preflight_python["ready"], "encoded": preflight_python["encoded"]}
    try:
        wire.encode_reading_checked(parts, REFUSED_READING)
        report["refused"] = {"encoded": True}
    except quantizer.InputRefused as refusal:
        report["refused"] = {"field": refusal.field, "reason": refusal.reason}
    require(report["refused"] == {"field": "temp", "reason": "wrong_type"}, "the boundary refuses a numeric string (Python)", str(report["refused"]))
    return {"flow": FLOW, "readings": READINGS, "accepted": accepted_readings, "refused": REFUSED_READING,
            "ppt": str(work / "perimeter.ppt"), "pub": str(work / "keys" / "authority.pub")}


def mission_control_chain(work: Path, report: dict) -> None:
    port = "9931"
    env = dict(os.environ, MC_PROJ=str(work), MC_PORT=port, MC_SCAN=str(work / "status.json"), MC_AUDIT=str(work / "console_audit.log"), LLM_BASE="http://127.0.0.1:9/v1")
    server = subprocess.Popen([sys.executable, "-m", "prismpath.mission_control"], env=env, cwd=str(work), stdout=open(work / "console.log", "w"), stderr=subprocess.STDOUT)

    def post(path, payload):
        request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.loads(response.read())
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/status", timeout=5)
                break
            except Exception:
                time.sleep(0.2)
        else:
            raise SystemExit("Mission Control did not start")
        validation = post("/api/v1/inspect/validate", {"flow_md": "flows/perimeter.md"})
        require(validation.get("ok") is True and validation.get("errors") == 0, "console validate", str(validation))
        portable = post("/api/v1/inspect/portable", {"flow_md": "flows/perimeter.md"})
        require(portable.get("portable") is True, "console portable", str(portable))
        first = report["readings"][0]
        encoded = post("/api/v1/policy/facet-encode", {"flow_md": "flows/perimeter.md", "reading_json": READINGS[0]})
        require(encoded.get("payload_hex") == first["frame_hex"], "console Facet encode equals the library frame", f"{encoded} versus {first['frame_hex']}")
        decoded = post("/api/v1/policy/facet-decode", {"flow_md": "flows/perimeter.md", "payload_hex": first["frame_hex"]})
        require(decoded.get("next_node") == first["route"] or decoded.get("route") == first["route"], "console Facet decode routes as the library", str(decoded))
        verified = post("/api/v1/policy/pack-verify", {"ppt_path": "perimeter.ppt", "pub": ["keys/authority.pub"]})
        require(verified.get("ok") is True, "console pack verify", str(verified))
        attested = post("/api/v1/policy/pack-attest", {"state_dir": "state", "envelope": "env/env1.envelope", "pub": ["keys/authority.pub"]})
        require(attested.get("active") == report["image"]["sha256"], "console attest names the active image", str(attested))
        trail = post("/api/v1/attest/trail", {"source": "state/swaps.log"})
        require(isinstance(trail, dict) and json.dumps(trail).count("attestation") >= 1, "console trail reads the audit log", json.dumps(trail)[:300])
        report["mission_control"] = {"validate": "ok", "portable": "ok", "facet": "ok", "pack_verify": "ok", "attest": "ok", "trail": "ok"}
    finally:
        server.terminate()
        server.wait(timeout=10)


def rust_chain(candidates: Path, out: Path, job: dict, report: dict) -> None:
    program = out / "rust"
    (program / "src").mkdir(parents=True, exist_ok=True)
    crate_dirs = {crate: next(candidates.glob(f"{crate}-*")) for crate in ("prismpath-rs", "prismpath-telemetry-rs", "prismpath-hotswap-rs", "prismpath-preflight")}
    dependencies = "\n".join(f'{crate} = {{ path = "{path}" }}' for crate, path in crate_dirs.items() if crate != "prismpath-preflight")
    patch = "\n".join(f'{crate} = {{ path = "{path}" }}' for crate, path in crate_dirs.items())
    (program / "Cargo.toml").write_text(f'[package]\nname = "end_to_end"\nversion = "0.0.0"\nedition = "2021"\n\n[dependencies]\n{dependencies}\nserde_json = "1"\n\n[patch.crates-io]\n{patch}\n\n[workspace]\n')
    (program / "src" / "main.rs").write_text(RUST_PROGRAM)
    (out / "job.json").write_text(json.dumps(job))
    env = dict(os.environ, CARGO_TARGET_DIR=str(out / "cargo-target"))
    built = sh("cargo", "run", "-q", "--manifest-path", str(program / "Cargo.toml"), "--", str(out / "job.json"), env=env)
    rust = json.loads(built.stdout.strip().splitlines()[-1])
    for index, (python_side, rust_side) in enumerate(zip(report["readings"], rust["readings"])):
        for seam in ("raw_route", "engine_path", "stopped", "route", "bits", "frame_hex", "decoded_route"):
            require(python_side[seam] == rust_side[seam], f"Python versus Rust {seam}", f"reading {index}: {python_side[seam]!r} versus {rust_side[seam]!r}")
    require(len(rust["readings"]) == len(report["readings"]), "Rust ran every reading", "")
    require(rust["refused"] == report["refused"], "Python versus Rust refusal of a numeric string", f"{report['refused']} versus {rust['refused']}")
    require(rust["pack_verify"]["ok"] is True, "pack signed by Python verifies in Rust", str(rust["pack_verify"]))
    require(rust["level_m"] is True, "Rust classifies the flow as Level M", "")
    report["rust"] = {"readings_compared": len(rust["readings"]), "pack_verify": rust["pack_verify"], "level_m": rust["level_m"]}
    # the Rust preflight twin on the same sample, the same report expected
    work = Path(job["ppt"]).parent
    sh("cargo", "run", "-q", "--manifest-path", str(candidates / "Cargo.toml"), "-p", "prismpath-preflight", "--",
       "flows/perimeter.md", "sample.ndjson", "--json", "preflight_rust.json", cwd=work, env=dict(os.environ, CARGO_TARGET_DIR=str(out / "cargo-target-candidates")))
    python_report = json.loads((work / "preflight_python.json").read_text())
    rust_report = json.loads((work / "preflight_rust.json").read_text())
    differences = sorted(key for key in set(python_report) | set(rust_report) if python_report.get(key) != rust_report.get(key))
    require(not differences, "Python and Rust preflight reports are identical", f"keys that differ: {differences}")
    report["preflight_rust"] = {"ready": rust_report["ready"], "identical_to_python": True}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--candidates", required=True, type=Path, help="the directory holding the four extracted candidate crates and their workspace Cargo.toml")
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--skip-console", action="store_true", help="leave Mission Control out (it needs the control-plane extra)")
    args = parser.parse_args(argv)
    out = args.out.resolve()
    work = out / "work"
    work.mkdir(parents=True, exist_ok=True)
    report: dict = {}
    job = python_chain(work, report)
    if not args.skip_console:
        mission_control_chain(work, report)
    rust_chain(args.candidates.resolve(), out, job, report)
    (out / "end_to_end_report.json").write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print(f"end to end ok: {len(report['readings'])} readings agree across engine, wire, decode, receipts and the Rust candidates; "
          f"pack verified in both languages; preflight reports identical; console {report.get('mission_control', 'skipped')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
