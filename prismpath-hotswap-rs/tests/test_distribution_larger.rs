// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Rust's replay of `tests/fixtures/install_larger.json`, a byte identical copy of the IS12 table
//! (`prismpath/portable/conformance/install_larger.json`, spec-policy-distribution.md IS10, IS12, AF8, OP4). Every row
//! runs on a `host` PEP: the set the row holds is applied, withdrawn or lost first, then the row's set is sent and the
//! PEP's state record must carry the row's event and cause. Python replays the same rows on `host` and `mesh`, and the
//! C core on `mesh`.

#[path = "common/mod.rs"]
mod common;
#[path = "common/dist.rs"]
mod dist;
#[path = "common/install.rs"]
mod installs;

use dist::*;
use installs::*;
use prismpath_hotswap_rs::dist::install::SetKind;
use prismpath_hotswap_rs::dist::{ArtifactKind, Hex64};
use serde_json::{json, Value};

fn corpus() -> Value {
    let path = format!("{}/tests/fixtures/install_larger.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).expect("read install_larger.json")).expect("parse install_larger.json")
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

/// The statements of the set `spec` of `kind` at `seq`.
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

/// The event and the cause a fresh `host` PEP answers `row` with.
fn replay(row: &Value) -> Value {
    let name = row["name"].as_str().unwrap();
    let (kind, set_kind) = if row["set"] == "ceiling" { (CEILING, SetKind::Ceiling) } else { (FLOOR, SetKind::Floor) };
    let mut point = Installer::new(&format!("larger_{name}"), 2);
    let before = row["before"].as_str().unwrap();
    let (mut held, mut seq) = (None, 1);
    if before != "none" {
        let first = point.send(&statements(kind, &row["held"], 1, kind == FLOOR, None));
        assert!(["install-applied", "install-widened"].contains(&first.event), "{name}: {:?}", first.cause);
        held = point.pep.installed.record.as_ref().and_then(|record| record.held(set_kind)).map(|set| set.policy_sha256().clone());
        seq = 2;
    }
    if before == "withdrawn" {
        let withdrawn = point.send(&statements(kind, &json!("empty"), 2, kind == CEILING, held.clone()));
        assert!(["install-applied", "install-widened"].contains(&withdrawn.event), "{name}: {:?}", withdrawn.cause);
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
        assert!(point.pep.installed.held(set_kind).is_none(), "{name}");
    }
    let replaces = match row["replaces"].as_str().unwrap() {
        "held" => held,
        "" => None,
        _ => Some(h(b"a set this PEP never held")),
    };
    let record = point.send(&statements(kind, &row["new"], seq, row["widens"].as_bool().unwrap(), replaces));
    json!({"event": record.event, "cause": record.cause})
}

/// case_307 and IS12 as a table: every row answers on `host` with its event and cause.
#[test]
fn case_307_every_row_of_the_is12_table_answers_as_it_says() {
    let corpus = corpus();
    let rows = corpus["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 47);
    let mut wrong = Vec::new();
    for row in rows.iter().filter(|row| row["kinds"].as_array().unwrap().contains(&json!("host"))) {
        let got = replay(row);
        if got != row["expect"] {
            wrong.push(format!("{}: {got} where the table says {}", row["name"], row["expect"]));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
