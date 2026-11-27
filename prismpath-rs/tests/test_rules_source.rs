// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Rules-source refusal conformance against `tests/fixtures/rules_source.json`, generated from the Python
//! reference (`prismpath/portable/gen_rules_source_fixtures.py`): rules lines (`-> refuse <cause>:`,
//! `-> escalate <cause>:`) and `.rules.md` filenames are refused with a parse error naming
//! `prismpath policy compile`, while rendered code edges (`refuse_106:`), normal edges (`-> next: when x`)
//! and prose mentioning refuse continue to parse as ordinary flows.

use prismpath_rs::{parse, parse_checked, parse_file, parse_named, run, EngineError, RunOpts, RunState, Value};
use serde_json::{json, Value as Json};
use std::path::PathBuf;

fn corpus() -> Json {
    let text = std::fs::read_to_string("tests/fixtures/rules_source.json").expect("read rules_source.json");
    serde_json::from_str(&text).expect("parse rules_source.json")
}

fn outcome(flow: &str, filename: Option<&str>) -> Json {
    let graph = match filename {
        Some(name) => parse_named(flow, Some(name)),
        None => parse(flow),
    };
    match graph.parse_error {
        Some(message) => {
            assert!(graph.rules_source_error, "expected rules_source_error=true for {message}");
            assert!(graph.nodes.is_empty() && graph.order.is_empty() && graph.start.is_empty());
            assert!(message.contains("prismpath policy compile"), "message must name prismpath policy compile: {message}");
            json!({"error": message, "error_class": "RulesSourceError"})
        }
        None => {
            assert!(!graph.rules_source_error);
            let nodes: Vec<Json> = graph
                .order
                .iter()
                .map(|name| {
                    let edges: Vec<Json> = graph.nodes[name]
                        .edges
                        .iter()
                        .map(|(target, cond)| json!([target, cond]))
                        .collect();
                    json!([name, edges])
                })
                .collect();
            json!({"ok": true, "start": graph.start, "nodes": nodes})
        }
    }
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("prismpath-rs-rules-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[test]
fn every_rules_source_case_gives_the_reference_outcome() {
    let corpus = corpus();
    let cases = corpus["cases"].as_array().unwrap();
    assert!(cases.len() >= 10);
    let mut bad = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let flow = case["flow"].as_str().unwrap();
        let filename = case["filename"].as_str();
        let got = outcome(flow, filename);
        if got != case["expect"] {
            bad.push(format!("{name}: want {} got {got}", case["expect"]));
        }
    }
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

#[test]
fn parse_checked_parse_file_and_engine_refuse_rules_sources() {
    let corpus = corpus();
    let base = temp_dir("parse-file");
    for (index, case) in corpus["cases"].as_array().unwrap().iter().enumerate() {
        let name = case["name"].as_str().unwrap();
        let flow = case["flow"].as_str().unwrap();
        let filename = case["filename"].as_str();
        let want_err = case["expect"].get("error").and_then(Json::as_str);

        if let Some(fname) = filename {
            let file_path = base.join(format!("case_{index}")).join(fname);
            std::fs::create_dir_all(file_path.parent().unwrap()).expect("mkdir");
            std::fs::write(&file_path, flow).expect("write temp flow");
            let file_res = parse_file(&file_path);
            match want_err {
                Some(expected_msg) => {
                    let err = file_res.unwrap_err();
                    assert_eq!(err, expected_msg, "{name}: parse_file should refuse");
                }
                None => {
                    let graph = file_res.unwrap_or_else(|err| panic!("{name}: parse_file should accept: {err}"));
                    assert_eq!(graph.start, case["expect"]["start"].as_str().unwrap(), "{name}");
                }
            }
        } else {
            let checked = parse_checked(flow);
            let graph = parse(flow);
            match want_err {
                Some(expected_msg) => {
                    assert_eq!(checked.unwrap_err(), expected_msg, "{name}");
                    let run_res = run(&graph, |_: &str, _: &str, _: &RunState| Ok::<_, String>(Value::Null), RunOpts::default());
                    assert!(
                        matches!(&run_res, Err(EngineError::InvalidFlow(msg)) if msg == expected_msg),
                        "{name}: {run_res:?}"
                    );
                }
                None => {
                    assert!(checked.is_ok(), "{name}: {checked:?}");
                }
            }
        }
    }
    let _ = std::fs::remove_dir_all(&base);
}
