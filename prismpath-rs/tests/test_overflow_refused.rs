// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! A number beyond the double range (`1e400`) is the one input serde_json holds that canonical JSON has no
//! form for. Every public API that takes caller or file data and reaches an engine value or canonical bytes
//! returns an error for it, and none panics.
#![cfg(feature = "durable")]

mod common;

use common::Scratch;
use prismpath_rs::connector::{flatten, short_hash, Connector, EchoConnector};
use prismpath_rs::crypto_agility::registry_hash;
use prismpath_rs::durable::{override_manifest, resume, try_py_canonical_string, verify_manifest};
use prismpath_rs::value::Value as V;
use serde_json::{json, Value};
use std::collections::BTreeMap;

fn overflow() -> Value {
    serde_json::from_str("1e400").expect("serde_json holds the digits of a number beyond the range")
}

fn no_panic<T>(what: &str, call: impl FnOnce() -> T + std::panic::UnwindSafe) -> T {
    std::panic::catch_unwind(call).unwrap_or_else(|_| panic!("{what} panicked instead of returning an error"))
}

#[test]
fn engine_values_refuse_it() {
    let nested = json!({"a": [1, {"b": overflow()}]});
    assert!(no_panic("try_from_json", || V::try_from_json(&nested)).is_err());
    assert!(no_panic("try_from_json scalar", || V::try_from_json(&overflow())).is_err());
}

#[test]
fn the_connector_ports_refuse_it() {
    let conn = EchoConnector { name: "echo".to_string() };
    let payload = json!({"temp": overflow()});
    assert!(no_panic("short_hash", || short_hash(&payload)).is_err());
    assert!(no_panic("ingestion_hash", || conn.ingestion_hash(&payload)).is_err());
    assert!(no_panic("knowledge_hash", || conn.knowledge_hash(&payload)).is_err());
    assert!(no_panic("adjudication_prompt", || conn.adjudication_prompt(&payload, None, None)).is_err());
    assert!(no_panic("adjudication_prompt scalar", || conn.adjudication_prompt(&overflow(), None, None)).is_err());
    assert!(no_panic("adjudication_prompt list", || conn.adjudication_prompt(&json!({"l": [1, overflow()]}), None, None)).is_err());
    assert!(no_panic("adjudicate", || conn.adjudicate(&payload, &mut |_: &str| String::new(), None, None)).is_err());
    assert!(no_panic("attest_decision", || conn.attest_decision(&payload, "p", "g", &[], "k", None, "2026-01-01")).is_err());
    let mut flat = BTreeMap::new();
    assert!(no_panic("flatten", move || flatten(&json!([overflow()]), "k", ".", &mut flat)).is_err());
    let dir = Scratch::new("overflow_sink");
    let sink = dir.join("out.jsonl");
    let outcome = no_panic("emit_record", || conn.emit_record(&json!({"id": 1, "v": overflow()}), sink.to_str().unwrap(), "id"));
    assert!(outcome.is_err());
    assert!(!sink.exists(), "a refused record writes nothing");
}

#[test]
fn canonical_bytes_hashes_and_manifests_refuse_it() {
    let bad = json!({"suites": {"x": overflow()}});
    assert!(try_py_canonical_string(&bad, false).is_err());
    assert!(no_panic("registry_hash", || registry_hash(&bad)).is_err());
    let prior = json!({"label": "l", "root": "r", "created": "c", "ingestion_hashes": [overflow()], "manifest_hash": "h"});
    assert!(no_panic("override_manifest", || override_manifest(&prior, "id", "why", "root", None, "2026")).is_err());
    assert!(!no_panic("verify_manifest", || verify_manifest(&json!({"manifest_hash": "h", "n": overflow()}))));
}

#[test]
fn a_checkpoint_holding_it_is_an_error_on_resume() {
    let dir = Scratch::new("overflow_resume");
    let path = dir.join("cp.json");
    std::fs::write(&path, r#"{"version": 1, "state": {"x": 1e400}, "stopped": "needs_human"}"#).unwrap();
    let outcome = no_panic("resume", || resume(path.to_str().unwrap(), |_: &str, _: &str, _: &prismpath_rs::RunState| Ok::<_, String>(V::Null), None, None, 5, false));
    assert!(outcome.is_err());
}
