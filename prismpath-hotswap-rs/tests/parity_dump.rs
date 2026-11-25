// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The Rust half of the cross implementation parity test (spec-policy-distribution.md case 104,
//! `prismpath/tests/test_distribution_parity.py`). When `PRISMPATH_PARITY_OUT` names a file, this runs every row
//! of the shared distribution corpora that the Rust host PEP can run and writes what it answered as one JSON
//! document. The corpora are read from `PRISMPATH_PARITY_CORPORA` (the shared `portable/conformance` directory)
//! so the three implementations read the same files. With no `PRISMPATH_PARITY_OUT` it does nothing, so a plain
//! `cargo test` is unchanged. Python compares the answers; this file asserts nothing about them.

#[path = "common/mod.rs"]
mod common;
#[path = "common/dist.rs"]
mod dist;
#[path = "common/install.rs"]
mod installs;

use dist::*;
use installs::*;
use prismpath_hotswap_rs::dist::envelope as env;
use prismpath_hotswap_rs::dist::install::SetKind;
use prismpath_hotswap_rs::dist::trust::TrustStore;
use prismpath_hotswap_rs::dist::verify::{self, PepView};
use prismpath_hotswap_rs::dist::{ArtifactKind, Hex64};
use prismpath_rs::canon2::{self, codec};
use serde_json::{json, Map, Value};
use std::panic::{catch_unwind, AssertUnwindSafe};

fn read_corpus(name: &str) -> Value {
    let dir = std::env::var("PRISMPATH_PARITY_CORPORA").expect("PRISMPATH_PARITY_CORPORA");
    serde_json::from_str(&std::fs::read_to_string(format!("{dir}/{name}.json")).unwrap()).unwrap()
}

fn runs_on_rust(row: &Value) -> bool {
    row["runs_on"].as_array().is_some_and(|list| list.iter().any(|item| item == "R"))
}

fn bytes(case: &Value, member: &str) -> Vec<u8> {
    hex::decode(case[member].as_str().unwrap()).unwrap()
}

fn decide(case: &Value) -> Value {
    let trust = if case["trust"].is_null() {
        TrustStore::unreadable()
    } else {
        TrustStore::from_bytes(&canon2::write_json(&case["trust"]).unwrap()).unwrap()
    };
    let pep: PepView = codec::from_doc(canon2::from_json(&case["pep"]).unwrap()).unwrap();
    let verdict = verify::verify(&bytes(case, "sealed"), &bytes(case, "body"), &trust, &pep, case["now"].as_i64().unwrap());
    json!({"cause": verdict.cause, "unchanged": verdict.unchanged, "time_floor": verdict.time_floor,
           "envelope_id": verdict.envelope.map(|envelope| envelope.envelope_id().to_string())})
}

fn hex_or_none(entry: &Value, member: &str) -> Option<Vec<u8>> {
    entry[member].as_str().map(|text| hex::decode(text).unwrap())
}

fn decide_widening(entry: &Value) -> Value {
    use prismpath_hotswap_rs::dist::pep::{compare_artifact, widening_check};
    use prismpath_hotswap_rs::dist::TargetKind;
    let sealed = bytes(entry, "sealed");
    let envelope = env::read(env::unseal(&sealed).unwrap().0).unwrap();
    let target = TargetKind::Host.target().unwrap();
    let active_table = hex_or_none(entry, "active_table");
    let answer = active_table.as_deref().filter(|_| target.compares.contains(&envelope.artifact)).map(|active| {
        compare_artifact(envelope.artifact, Some(active), Some(&bytes(entry, "table")))
    });
    let active_policy = entry["active_policy"].as_str().map(|text| Hex64::try_from(text).unwrap());
    let statement = hex_or_none(entry, "statement");
    let cause = widening_check(&target, envelope.widens, &envelope.replaces, active_policy.as_ref(), answer, statement.as_deref(), None);
    json!({"cause": cause})
}

fn decide_commit(entry: &Value) -> Value {
    let name = entry["name"].as_str().unwrap();
    let mut point = Point::new(&format!("parity_{name}"));
    point.now.set(entry["now"].as_i64().unwrap());
    let mut last = None;
    for step in entry["steps"].as_array().unwrap() {
        let signed = if step["op"] == "stage" {
            point.pep.stage(&bytes(step, "sealed"), &bytes(step, "body")).unwrap()
        } else {
            let policy = Hex64::try_from(step["policy_sha256"].as_str().unwrap().to_string()).unwrap();
            point.pep.commit(STREAM, step["seq"].as_i64().unwrap(), &policy, 0).unwrap()
        };
        last = Some(point.read(&signed));
    }
    let record = last.unwrap();
    json!({"cause": record.cause, "active_seq": point.pep.active().map_or(0, |active| active.seq)})
}

fn table(name: &str) -> Vec<u8> {
    match name {
        "T1" => image(5),
        "T2" => image(7),
        "T3" => image(9),
        "F1" => good_table(),
        "F2" => floor_of(4),
        other => panic!("no table {other}"),
    }
}

fn rate(value: &Value) -> Option<(i64, i64)> {
    value.as_array().map(|pair| (pair[0].as_i64().unwrap(), pair[1].as_i64().unwrap()))
}

fn statements(kind: ArtifactKind, spec: &Value, seq: i64, widens: bool, replaces: Option<Hex64>) -> Vec<(Vec<u8>, Vec<u8>)> {
    let args = SetArgs { widens, replaces, ..installs::seq(seq) };
    if spec == "empty" {
        return empty_set(kind, &args);
    }
    if kind == CEILING {
        let tables: Vec<Vec<u8>> = spec["list"].as_array().unwrap().iter().map(|name| table(name.as_str().unwrap())).collect();
        let refs: Vec<&[u8]> = tables.iter().map(Vec::as_slice).collect();
        return ceiling_set(&refs, &args);
    }
    let body = table(spec["table"].as_str().unwrap());
    let mut meta = table_meta(&body);
    if let Some((allows, window)) = rate(&spec["answer_rate"]) {
        meta["answer_rate"] = json!({"allows": allows, "window": window});
    }
    floor_set(&body, &SetArgs { meta: Some(meta), rate: rate(&spec["rate"]), ..args })
}

fn decide_larger(row: &Value) -> Value {
    let name = row["name"].as_str().unwrap();
    let (kind, set_kind) = if row["set"] == "ceiling" { (CEILING, SetKind::Ceiling) } else { (FLOOR, SetKind::Floor) };
    let mut point = Installer::new(&format!("parity_larger_{name}"), 2);
    let before = row["before"].as_str().unwrap();
    let (mut held, mut seq) = (None, 1);
    if before != "none" {
        point.send(&statements(kind, &row["held"], 1, kind == FLOOR, None));
        held = point.pep.installed.record.as_ref().and_then(|record| record.held(set_kind)).map(|set| set.policy_sha256().clone());
        seq = 2;
    }
    if before == "withdrawn" {
        point.send(&statements(kind, &json!("empty"), 2, kind == CEILING, held.clone()));
        seq = 3;
    }
    if before == "lost" {
        for dir in ["install/blobs", "install-copy/blobs"] {
            for entry in std::fs::read_dir(point.dist().join(dir)).unwrap() {
                std::fs::write(entry.unwrap().path(), b"unreadable").unwrap();
            }
        }
        point.reopen();
        point.pep.drain();
    }
    let replaces = match row["replaces"].as_str().unwrap() {
        "held" => held,
        "" => None,
        _ => Some(h(b"a set this PEP never held")),
    };
    let record = point.send(&statements(kind, &row["new"], seq, row["widens"].as_bool().unwrap(), replaces));
    json!({"event": record.event, "cause": record.cause})
}

fn guarded(out: &mut Map<String, Value>, name: &str, run: impl FnOnce() -> Value) {
    let result = catch_unwind(AssertUnwindSafe(run)).unwrap_or_else(|_| json!({"error": "the Rust row panicked"}));
    out.insert(name.to_string(), result);
}

#[test]
fn dump_the_rust_answers_for_the_parity_test() {
    let Ok(path) = std::env::var("PRISMPATH_PARITY_OUT") else { return };
    std::panic::set_hook(Box::new(|_| {}));
    let corpus = read_corpus("distribution");
    let mut cases = Map::new();
    for case in corpus["cases"].as_array().unwrap().iter().filter(|row| runs_on_rust(row)) {
        guarded(&mut cases, case["name"].as_str().unwrap(), || decide(case));
    }
    let mut widening = Map::new();
    for entry in corpus["widening"].as_array().unwrap().iter().filter(|row| runs_on_rust(row) && row["kind"] == "host") {
        guarded(&mut widening, entry["name"].as_str().unwrap(), || decide_widening(entry));
    }
    let mut commits = Map::new();
    for entry in corpus["commits"].as_array().unwrap().iter().filter(|row| runs_on_rust(row) && row["kind"] == "host") {
        guarded(&mut commits, entry["name"].as_str().unwrap(), || decide_commit(entry));
    }
    let mut larger = Map::new();
    for row in read_corpus("install_larger")["rows"].as_array().unwrap().iter().filter(|row| row["kinds"].as_array().unwrap().contains(&json!("host"))) {
        guarded(&mut larger, row["name"].as_str().unwrap(), || decide_larger(row));
    }
    let doc = json!({"cases": cases, "widening": widening, "commits": commits, "larger": larger});
    std::fs::write(path, serde_json::to_vec(&doc).unwrap()).unwrap();
}
