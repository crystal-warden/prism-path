// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Field definitions (SPEC section 4.5), replayed from the frozen vectors the Python reference
//! generates (`prismpath/portable/conformance/field_definitions.json`): the shared conversion,
//! parse time lowering to the exact text the reference produces, the policy rules, the canonical
//! boundary, and the engine's routes on canonical readings. Every expected value comes from the
//! reference, so this crate is held to it rather than to the code it was ported from.

use prismpath_rs::{accept_canonical, canonical_value, first_deterministic, parse, parse_checked, run, EngineError, RunOpts, Value};
use prismpath_rs::field_definitions::parse_definition;
use std::collections::HashMap;

fn corpus() -> serde_json::Value {
    let path = format!("{}/../prismpath/portable/conformance/field_definitions.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).expect("read field_definitions.json")).expect("parse field_definitions.json")
}

fn reading(object: &serde_json::Value) -> HashMap<String, Value> {
    object.as_object().expect("a reading is an object").iter().map(|(key, value)| (key.clone(), Value::from_json(value))).collect()
}

#[test]
fn the_shared_conversion_matches_the_reference() {
    let corpus = corpus();
    for case in corpus["conversion"].as_array().unwrap() {
        let definition = parse_definition("value", case["definition"].as_str().unwrap()).expect("a vector's definition parses");
        let raw = Value::from_json(&case["raw"]);
        let got = canonical_value(&definition, &raw);
        match case.get("refused") {
            Some(reason) => assert_eq!(got.map_err(|refusal| refusal.reason), Err(reason.as_str().unwrap()), "{case}"),
            None => assert_eq!(got.ok(), Some(Value::from_json(&case["canonical"])), "{case}"),
        }
    }
}

#[test]
fn an_accepted_policy_lowers_to_the_reference_text_and_routes_as_frozen() {
    let corpus = corpus();
    for policy in corpus["policies"].as_array().unwrap().iter().filter(|policy| policy["accepted"] == true) {
        let name = policy["name"].as_str().unwrap();
        let graph = parse_checked(policy["flow"].as_str().unwrap()).unwrap_or_else(|reason| panic!("[{name}] refused: {reason}"));
        let lowered: Vec<&str> = graph.nodes["s"].edges.iter().map(|(_target, cond)| cond.as_str()).collect();
        let expected: Vec<&str> = policy["lowered"].as_array().unwrap().iter().map(|cond| cond.as_str().unwrap()).collect();
        assert_eq!(lowered, expected, "[{name}] lowering");
        for probe in policy["probes"].as_array().unwrap() {
            let route = first_deterministic(&graph.nodes["s"].edges, &reading(&probe["reading"])).map(|(target, _)| target.to_string());
            assert_eq!(route.as_deref(), probe["route"].as_str(), "[{name}] {}", probe["reading"]);
        }
        for refusal in policy["refused_readings"].as_array().unwrap() {
            let values = reading(&refusal["reading"]);
            let first = graph.fields.iter().find_map(|(field, definition)| {
                accept_canonical(definition, values.get(field).unwrap_or(&Value::Null)).err().map(|reason| (field.clone(), reason))
            });
            assert_eq!(first, Some((refusal["field"].as_str().unwrap().to_string(), refusal["reason"].as_str().unwrap())), "[{name}] {}", refusal["reading"]);
        }
    }
}

#[test]
fn a_refused_policy_is_disabled_and_the_engine_will_not_run_it() {
    let corpus = corpus();
    for policy in corpus["policies"].as_array().unwrap().iter().filter(|policy| policy["accepted"] == false) {
        let name = policy["name"].as_str().unwrap();
        let graph = parse(policy["flow"].as_str().unwrap());
        assert!(graph.field_error.is_some(), "[{name}] parsed although the reference refuses it");
        assert!(graph.nodes.values().flat_map(|node| node.edges.iter()).all(|(_target, cond)| cond == "never"), "[{name}] an edge stayed live");
        let outcome = run(&graph, |_node, _instruction, _state| Ok(Value::Null), RunOpts::default());
        assert!(matches!(outcome, Err(EngineError::InvalidFlow(_))), "[{name}] the engine ran a refused flow");
    }
}

#[test]
fn a_flow_without_definitions_is_untouched() {
    let graph = parse("---\nname: t\nstart: s\n---\n## s\n-> hit: when x >= 0.85\n-> miss: else\n## hit\n## miss\n");
    assert!(graph.fields.is_empty() && graph.field_error.is_none());
    assert_eq!(graph.nodes["s"].edges[0].1, "when x >= 0.85");
}

#[test]
fn canonical_text_matches_the_reference_spelling() {
    let one = parse_definition("r", "fixed rounding=floor scale=10000 unit=ratio max=10000 min=0").unwrap();
    assert_eq!(one.canonical_text(), "fixed scale=10000 rounding=floor unit=ratio min=0 max=10000 absent=refused");
}
