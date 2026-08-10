use prismpath_rs::{parse, V};
use prismpath_telemetry_rs::{quantizer as q, wire as w};
use serde_json::Value;
use std::collections::HashMap;

fn load_decisions_corpus() -> Value {
    let path = std::path::Path::new("../adapters/telemetry/conformance/decisions.json");
    let content = std::fs::read_to_string(path).expect("read decisions.json");
    serde_json::from_str(&content).expect("parse decisions.json")
}

fn json_to_v(val: &Value) -> V {
    V::from_json(val)
}

fn json_obj_to_reading(obj: &serde_json::Map<String, Value>) -> HashMap<String, V> {
    obj.iter().map(|(k, v)| (k.clone(), json_to_v(v))).collect()
}

#[test]
fn test_corpus_pinned() {
    let corpus = load_decisions_corpus();
    let cases = corpus["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    let total_readings: usize = cases
        .iter()
        .map(|c| c["readings"].as_array().unwrap().len())
        .sum();
    assert!(total_readings >= 50);
}

#[test]
fn test_engine_matches_frozen_routes() {
    let corpus = load_decisions_corpus();
    let cases = corpus["cases"].as_array().unwrap();

    for case in cases {
        let name = case["name"].as_str().unwrap();
        let flow = case["flow"].as_str().unwrap();
        let g = parse(flow);

        for entry in case["readings"].as_array().unwrap() {
            let reading = json_obj_to_reading(entry["reading"].as_object().unwrap());
            let routes_obj = entry["routes"].as_object().unwrap();

            for (node, target_val) in routes_obj {
                let target = target_val.as_str().map(|s| s.to_string());
                let got = w::route_node(&g, node, &reading);
                assert_eq!(
                    got, target,
                    "[{name}] engine drift at {node} on {reading:?}: {got:?} != {target:?}"
                );
            }
        }
    }
}

#[test]
fn test_wire_round_trip_preserves_decisions() {
    let corpus = load_decisions_corpus();
    let cases = corpus["cases"].as_array().unwrap();

    for case in cases {
        let name = case["name"].as_str().unwrap();
        let flow = case["flow"].as_str().unwrap();
        let g = parse(flow);
        let parts = q::build_partitions(&g);

        for entry in case["readings"].as_array().unwrap() {
            let reading = json_obj_to_reading(entry["reading"].as_object().unwrap());
            let routes_obj = entry["routes"].as_object().unwrap();

            let bits = w::encode_reading(&parts, &reading).expect("encode reading");
            let recon = w::decode_reading(&parts, &bits).expect("decode reading");

            for (node, target_val) in routes_obj {
                let target = target_val.as_str().map(|s| s.to_string());
                let got = w::route_node(&g, node, &recon);
                assert_eq!(
                    got, target,
                    "[{name}] DECISION CHANGED at {node} on {reading:?} (reconstructed {recon:?}): {got:?} != {target:?}"
                );
            }
        }
    }
}

#[test]
fn test_wire_round_trip_is_stable() {
    let corpus = load_decisions_corpus();
    let case = &corpus["cases"].as_array().unwrap()[0];
    let flow = case["flow"].as_str().unwrap();
    let g = parse(flow);
    let parts = q::build_partitions(&g);

    let reading = json_obj_to_reading(case["readings"][0]["reading"].as_object().unwrap());
    let bits = w::encode_reading(&parts, &reading).unwrap();
    let recon = w::decode_reading(&parts, &bits).unwrap();
    assert_eq!(w::encode_reading(&parts, &recon).unwrap(), bits);
}
