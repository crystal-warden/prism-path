// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The Rust twin of the frozen policy forms corpus: every carried Level M form decodes to the
//! engine's own route on both the permissive and the checked path, the spiral packer sees its field,
//! and every other form refuses the whole flow. Found in October 2026 by the reading boundary audit,
//! when this crate's token scanner read a chained range as its first bound alone, a boolean constant
//! as 0, `True == x` as a bare `x`, `2.5` as `2`, and `None` as a field, and skipped field against
//! field and string ordering without a word. quantizer.py replays the same file.
use prismpath_rs::{parse, V};
use prismpath_telemetry_rs::{quantizer, spiral, wire};
use serde_json::Value;
use std::collections::HashMap;

fn corpus() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../prismpath/telemetry/conformance/policy_forms.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("read policy_forms.json"))
        .expect("parse policy_forms.json")
}

fn flow_for(corpus: &Value, condition: &str) -> prismpath_rs::Graph {
    parse(&corpus["flow_template"].as_str().unwrap().replace("{condition}", condition))
}

#[test]
fn corpus_pinned() {
    let corpus = corpus();
    assert_eq!(corpus["carried"].as_array().unwrap().len(), 12);
    assert_eq!(corpus["refused"].as_array().unwrap().len(), 11);
}

#[test]
fn a_carried_form_routes_as_the_engine_does_on_both_paths() {
    let corpus = corpus();
    let node = corpus["node"].as_str().unwrap();
    for case in corpus["carried"].as_array().unwrap() {
        let condition = case["condition"].as_str().unwrap();
        let field = case["field"].as_str().unwrap();
        let graph = flow_for(&corpus, condition);
        let parts = quantizer::build_partitions(&graph)
            .unwrap_or_else(|reason| panic!("[{condition}] refused a carried form: {reason}"));
        assert!(parts.contains_key(field), "[{condition}] the field is missing from the partition");
        for probe in case["readings"].as_array().unwrap() {
            let raw: HashMap<String, V> = HashMap::from([(field.to_string(), V::from_json(&probe["value"]))]);
            let expected = probe["route"].as_str().map(str::to_string);
            assert_eq!(wire::route_node(&graph, node, &raw), expected, "[{condition}] engine drift on {raw:?}");
            let permissive = quantizer::reconstruct(&parts, &quantizer::quantize(&parts, &raw).unwrap());
            let checked = quantizer::reconstruct(&parts, &quantizer::checked_quantize(&parts, &raw).unwrap());
            assert_eq!(wire::route_node(&graph, node, &permissive), expected,
                       "[{condition}] permissive decode {permissive:?} of {raw:?} changed the route");
            assert_eq!(wire::route_node(&graph, node, &checked), expected,
                       "[{condition}] checked decode {checked:?} of {raw:?} changed the route");
        }
    }
}

#[test]
fn the_spiral_packer_sees_the_field() {
    let corpus = corpus();
    let node = corpus["node"].as_str().unwrap();
    for case in corpus["carried"].as_array().unwrap() {
        let condition = case["condition"].as_str().unwrap();
        let layout = spiral::SpiralLayout::new(&flow_for(&corpus, condition), node)
            .unwrap_or_else(|reason| panic!("[{condition}] no spiral layout: {reason}"));
        assert_eq!(layout.fields, vec![case["field"].as_str().unwrap().to_string()], "[{condition}]");
    }
}

#[test]
fn a_form_the_codec_cannot_carry_refuses_the_whole_flow() {
    let corpus = corpus();
    for case in corpus["refused"].as_array().unwrap() {
        let condition = case["condition"].as_str().unwrap();
        assert!(quantizer::build_partitions(&flow_for(&corpus, condition)).is_err(),
                "[{condition}] partitioned a form the codec cannot carry");
    }
}

#[test]
fn the_refusal_names_the_condition_and_its_reason() {
    let corpus = corpus();
    let reason = quantizer::build_partitions(&flow_for(&corpus, "x == y")).unwrap_err();
    assert!(reason.contains("\"when x == y\" (field-vs-field)"), "{reason}");
    let reason = quantizer::build_partitions(&flow_for(&corpus, "x == None")).unwrap_err();
    assert!(reason.contains("absent field"), "{reason}");
}
