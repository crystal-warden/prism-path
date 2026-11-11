// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Rust produces receipts, a concentrated datagram and a tick stream that the Python modules verify, replay and
//! demultiplex, and Python produces the same kinds of material that Rust verifies, replays and demultiplexes.
//! Both directions run through `PRISMPATH_PYTHON`. With `PRISMPATH_REQUIRE_CROSS_LANGUAGE` set a missing
//! interpreter fails the test; without it a machine with no Python skips and says so.

use prismpath_telemetry_rs::concentrator::{concentrate, demux, Record};
use prismpath_telemetry_rs::receipts::{self as r, CauseRef};
use prismpath_telemetry_rs::refresh::{KeyframeScheduler, StalenessTracker};
use prismpath_telemetry_rs::replay::TickWindow;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};

/// Reads one JSON request on stdin and answers on stdout; `mode` picks what the Python side does.
const PYTHON_SIDE: &str = r#"
import json, os, random, sys
sys.path.insert(0, os.environ["PP_REPO"])
from prismpath.telemetry import concentrator, receipts, refresh, replay

request = json.load(sys.stdin)
mode = request["mode"]
registry = {int(sid): count for sid, count in request["registry"].items()}

def window_answers(reorder, ticks):
    window = replay.TickWindow(reorder)
    return [list(window.observe(tick)) for tick in ticks]

def refresh_answers(script):
    scheduler = refresh.KeyframeScheduler(script["keyframe_ms"])
    tracker = refresh.StalenessTracker(script["stale_ms"], "SAFE")
    out = []
    for op in script["ops"]:
        if op[0] == "emit":
            out.append(scheduler.should_emit(op[1], op[2]))
            if out[-1]:
                scheduler.note_emit(op[1])
        elif op[0] == "frame":
            tracker.on_frame(op[1], op[2]); out.append(None)
        else:
            out.append(list(tracker.acting_state(op[1])))
    return {"answers": out, "transitions": [list(t) for t in tracker.transitions]}

if mode == "verify_rust":
    # Rust's frames: decode, check the carried fields, re-encode to the same bytes; demux the datagram; replay the ticks
    out = {"receipts": [], "reencoded_equal": []}
    for item in request["receipts"]:
        frame = bytes.fromhex(item["hex"])
        decoded = receipts.decode_receipt(frame)
        out["receipts"].append({"refusal_cause": decoded.refusal_cause, "receipt": decoded.receipt})
        out["reencoded_equal"].append(receipts.encode_receipt_dict(decoded.receipt) == frame)
    records, cause = concentrator.demux(bytes.fromhex(request["datagram"]), registry)
    out["demux"] = {"cause": cause, "records": [[sid, list(ints)] for sid, ints in records]}
    out["window"] = window_answers(request["reorder"], request["ticks"])
    out["refresh"] = refresh_answers(request["refresh"])
    print(json.dumps(out))
else:
    # Python's own material, from a seed Rust does not share
    rng = random.Random(request["seed"])
    items = []
    for _ in range(request["count"]):
        width = rng.randrange(1, 64)
        fields = {k: rng.getrandbits(width) for k in ("seq", "prev_node", "event", "next_node")}
        cause = rng.choice([0, 0, 36, 52, rng.randrange(0, 256)])
        frame = receipts.encode_receipt(fields["seq"], fields["prev_node"], fields["event"], fields["next_node"], cause)
        items.append({"hex": frame.hex(), "fields": {**fields, "cause": cause}})
    records = []
    for _ in range(12):
        sid = rng.choice([sid for sid in registry if registry[sid] > 0])
        records.append([sid, [rng.randrange(1, 1000) for _ in range(registry[sid])]])
    datagram = concentrator.concentrate([(sid, ints) for sid, ints in records]).hex()
    ticks = [rng.randrange(0, 60) for _ in range(200)]
    window = replay.TickWindow(request["reorder"])
    answers = [list(window.observe(tick)) for tick in ticks]
    print(json.dumps({"items": items, "records": records, "datagram": datagram, "ticks": ticks, "window": answers,
                      "refresh": refresh_answers(request["refresh"])}))
"#;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

fn python() -> Option<String> {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_str().unwrap().to_string();
    let required = std::env::var("PRISMPATH_REQUIRE_CROSS_LANGUAGE").is_ok_and(|value| !value.is_empty());
    let configured = std::env::var("PRISMPATH_PYTHON").ok().filter(|value| !value.is_empty());
    let candidate = configured.clone().unwrap_or_else(|| format!("{repo}/.venv/bin/python"));
    let found = if configured.is_some() {
        Command::new(&candidate).arg("--version").output().is_ok_and(|out| out.status.success())
    } else {
        std::path::Path::new(&candidate).exists()
    };
    if found {
        return Some(candidate);
    }
    assert!(!required, "PRISMPATH_REQUIRE_CROSS_LANGUAGE is set but no Python was found ({candidate})");
    eprintln!("SKIPPED (not run): the telemetry cross language test needs Python; set PRISMPATH_PYTHON. CI sets PRISMPATH_REQUIRE_CROSS_LANGUAGE.");
    None
}

fn ask_python(python: &str, request: &Value) -> Value {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut child = Command::new(python)
        .args(["-c", PYTHON_SIDE])
        .env("PP_REPO", repo)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start python");
    child.stdin.take().unwrap().write_all(request.to_string().as_bytes()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    serde_json::from_slice(&output.stdout).expect("python answered JSON")
}

fn registry() -> HashMap<u64, usize> {
    [(1, 2), (2, 5), (3, 1), (7, 3), (9, 0), (40, 4)].into_iter().collect()
}

fn registry_json() -> Value {
    json!({"1": 2, "2": 5, "3": 1, "7": 3, "9": 0, "40": 4})
}

/// One script both runtimes run: keyframe emit decisions and the staleness tracker, with the states JSON.
fn refresh_script() -> Value {
    json!({"keyframe_ms": 100, "stale_ms": 250, "ops": [
        ["emit", 0, false], ["emit", 50, false], ["emit", 100, false], ["emit", 120, true], ["emit", 230, false],
        ["acting", 0], ["frame", 10, {"mode": "run"}], ["acting", 100], ["acting", 259], ["acting", 260], ["frame", 300, 7], ["acting", 301]]})
}

fn rust_refresh_answers(script: &Value) -> Value {
    let mut scheduler = KeyframeScheduler::new(script["keyframe_ms"].as_i64()).unwrap();
    let mut tracker = StalenessTracker::new(script["stale_ms"].as_i64().unwrap(), json!("SAFE")).unwrap();
    let mut out = Vec::new();
    for op in script["ops"].as_array().unwrap() {
        match op[0].as_str().unwrap() {
            "emit" => {
                let emit = scheduler.should_emit(op[1].as_i64().unwrap(), op[2].as_bool().unwrap());
                if emit {
                    scheduler.note_emit(op[1].as_i64().unwrap());
                }
                out.push(json!(emit));
            }
            "frame" => {
                tracker.on_frame(op[1].as_i64().unwrap(), op[2].clone());
                out.push(Value::Null);
            }
            _ => {
                let (state, fresh) = tracker.acting_state(op[1].as_i64().unwrap());
                out.push(json!([state, fresh]));
            }
        }
    }
    json!({"answers": out, "transitions": tracker.transitions().iter().map(|(when, kind)| json!([when, kind])).collect::<Vec<_>>()})
}

fn rust_window_answers(reorder: i64, ticks: &[i64]) -> Value {
    let mut window = TickWindow::new(reorder).unwrap();
    Value::Array(ticks.iter().map(|tick| {
        let (ok, cause) = window.observe(*tick);
        json!([ok, cause])
    }).collect())
}

#[test]
fn rust_receipts_datagrams_and_ticks_are_verified_replayed_and_demuxed_by_python() {
    let Some(python) = python() else { return };
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut items = Vec::new();
    let mut expected = Vec::new();
    for _ in 0..200 {
        let width = 1 + rng.below(63);
        let mut field = || rng.next() >> (64 - width);
        let (seq, prev, event, next) = (field(), field(), field(), field());
        let cause = rng.below(256) as u8;
        let frame = r::encode_receipt(seq, prev, event, next, CauseRef::from(cause)).unwrap();
        items.push(json!({"hex": hex::encode(&frame)}));
        expected.push((frame, seq, prev, event, next, cause));
    }
    let records: Vec<Record> = (0..12)
        .map(|_| {
            let sid = [1u64, 2, 3, 7, 40][rng.below(5) as usize];
            (sid, (0..registry()[&sid]).map(|_| 1 + rng.below(1000)).collect())
        })
        .collect();
    let datagram = concentrate(&records).unwrap();
    let ticks: Vec<i64> = (0..200).map(|_| rng.below(60) as i64).collect();
    let script = refresh_script();
    let answer = ask_python(
        &python,
        &json!({"mode": "verify_rust", "registry": registry_json(), "receipts": items, "datagram": hex::encode(&datagram),
                "reorder": 8, "ticks": ticks, "refresh": script}),
    );
    for (index, (frame, seq, prev, event, next, cause)) in expected.iter().enumerate() {
        let got = &answer["receipts"][index];
        assert_eq!(got["refusal_cause"], "ok", "receipt {index}");
        let receipt = &got["receipt"];
        assert_eq!(
            (receipt["seq"].as_u64(), receipt["prev_node"].as_u64(), receipt["event"].as_u64(), receipt["next_node"].as_u64(), receipt["cause"].as_u64()),
            (Some(*seq), Some(*prev), Some(*event), Some(*next), Some(u64::from(*cause))),
            "receipt {index}"
        );
        assert_eq!(receipt["cause_name"].as_str(), prismpath_rs::causes::name(*cause), "receipt {index}");
        assert_eq!(answer["reencoded_equal"][index], true, "receipt {index}: Python re-encodes to the bytes Rust wrote ({})", frame.len());
    }
    assert_eq!(answer["demux"]["cause"], "ok");
    let python_records: Vec<Record> = answer["demux"]["records"].as_array().unwrap().iter()
        .map(|record| (record[0].as_u64().unwrap(), record[1].as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).collect())).collect();
    assert_eq!(python_records, records);
    let ticks_rust: Vec<i64> = ticks.clone();
    assert_eq!(answer["window"], rust_window_answers(8, &ticks_rust));
    assert_eq!(answer["refresh"], rust_refresh_answers(&script));
    println!("cross-language telemetry: Python decoded, re-encoded, demultiplexed and replayed what Rust wrote (200 receipts, 12 records, 200 ticks)");
}

#[test]
fn python_receipts_datagrams_and_ticks_are_verified_replayed_and_demuxed_by_rust() {
    let Some(python) = python() else { return };
    let script = refresh_script();
    let answer = ask_python(&python, &json!({"mode": "make_python", "seed": 424242, "count": 200, "registry": registry_json(), "reorder": 8, "refresh": script}));
    for (index, item) in answer["items"].as_array().unwrap().iter().enumerate() {
        let frame = hex::decode(item["hex"].as_str().unwrap()).unwrap();
        let decoded = r::decode_receipt(&frame).unwrap();
        assert_eq!(decoded.refusal_cause, r::OK, "receipt {index}");
        let receipt = decoded.receipt.unwrap();
        let fields = &item["fields"];
        assert_eq!(
            (receipt.seq, receipt.prev_node, receipt.event, receipt.next_node, u64::from(receipt.cause)),
            (fields["seq"].as_u64().unwrap(), fields["prev_node"].as_u64().unwrap(), fields["event"].as_u64().unwrap(),
             fields["next_node"].as_u64().unwrap(), fields["cause"].as_u64().unwrap()),
            "receipt {index}"
        );
        assert_eq!(r::encode_receipt_struct(&receipt).unwrap(), frame, "receipt {index}: Rust re-encodes to the bytes Python wrote");
    }
    let (records, cause) = demux(&hex::decode(answer["datagram"].as_str().unwrap()).unwrap(), &registry()).unwrap();
    assert_eq!(cause, "ok");
    let python_records: Vec<Record> = answer["records"].as_array().unwrap().iter()
        .map(|record| (record[0].as_u64().unwrap(), record[1].as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).collect())).collect();
    assert_eq!(records, python_records);
    assert_eq!(hex::encode(concentrate(&records).unwrap()), answer["datagram"].as_str().unwrap(), "Rust re-concentrates to Python's datagram");
    let ticks: Vec<i64> = answer["ticks"].as_array().unwrap().iter().map(|v| v.as_i64().unwrap()).collect();
    assert_eq!(rust_window_answers(8, &ticks), answer["window"]);
    assert_eq!(rust_refresh_answers(&script), answer["refresh"]);
    println!("cross-language telemetry: Rust decoded, re-encoded, demultiplexed and replayed what Python wrote (200 receipts, 12 records, 200 ticks)");
}
