// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Conformance gate for the Rust proof layer — Level M classification + capability report.
//! Gates byte-for-byte against the SAME frozen corpora the Python reference and the JS twin pass
//! (`prismpath/portable/conformance/{level_m,capability}.json`). Parity is proven, not asserted.

use prismpath_rs::{capability_report, check_reach, flow_level_m, parse};
use serde_json::Value;
use std::fs;

fn cases(name: &str) -> Vec<Value> {
    let path = format!(
        "{}/../prismpath/portable/conformance/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    );
    let doc: Value = serde_json::from_str(&fs::read_to_string(&path).expect("read corpus"))
        .expect("parse corpus");
    doc.get("cases")
        .and_then(|value| value.as_array())
        .cloned()
        .or_else(|| doc.as_array().cloned())
        .expect("corpus is a list or {cases:[...]}")
}

#[test]
fn level_m_conformance() {
    let corpus_cases = cases("level_m.json");
    for case in &corpus_cases {
        let flow = case["flow"].as_str().expect("flow");
        let graph = parse(flow);
        let (lm, non_member) = flow_level_m(&graph);
        // Mirror run_level_m.mjs's normalizer: the level_m corpus drops the `level_m` flag from
        // each non-member edge (capability.json keeps it — the two runners differ deliberately).
        let nm: Vec<Value> = non_member
            .iter()
            .map(|edge| {
                serde_json::json!({
                    "node": edge.node, "target": edge.target, "condition": edge.condition, "reason": edge.reason,
                })
            })
            .collect();
        let got = serde_json::json!({ "level_m": lm, "non_member_edges": nm });
        assert_eq!(got, case["expected"], "level_m case {}", case["key"]);
    }
    assert!(!corpus_cases.is_empty());
    eprintln!("level_m: {}/{} CONFORMANT", corpus_cases.len(), corpus_cases.len());
}

#[test]
fn capability_conformance() {
    let corpus_cases = cases("capability.json");
    for case in &corpus_cases {
        let flow = case["flow"].as_str().expect("flow");
        let graph = parse(flow);
        let got = capability_report(&graph);
        assert_eq!(got, case["expected"], "capability case {}", case["key"]);
    }
    assert!(!corpus_cases.is_empty());
    eprintln!("capability: {}/{} CONFORMANT", corpus_cases.len(), corpus_cases.len());
}

#[test]
fn reach_conformance() {
    let corpus_cases = cases("reach.json");
    for case in &corpus_cases {
        let flow = case["flow"].as_str().expect("flow");
        let graph = parse(flow);
        let targets: Vec<String> = case["targets"]
            .as_array()
            .expect("targets")
            .iter()
            .map(|target| target.as_str().expect("target str").to_string())
            .collect();
        let assume = case["assume"].as_str(); // null -> None
        let bound = case["bound"].as_u64().unwrap_or(25) as usize;
        let inc_err = case["include_errors"].as_bool().unwrap_or(true);
        let inc_evt = case["include_events"].as_bool().unwrap_or(true);
        let got = check_reach(&graph, &targets, assume, bound, inc_err, inc_evt);
        assert_eq!(got, case["expected"], "reach case {}", case["key"]);
    }
    assert!(!corpus_cases.is_empty());
    eprintln!("reach: {}/{} CONFORMANT", corpus_cases.len(), corpus_cases.len());
}
