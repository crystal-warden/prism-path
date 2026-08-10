use prismpath_rs::{parse, V};
use prismpath_telemetry_rs::{quantizer as q, wire as w};
use std::collections::HashMap;

const FLOW: &str = r#"---
name: sample
start: start
---
## start
-> a: when x >= 10
-> b: else
## a
## b
"#;

#[test]
fn test_encode_decode_round_trip() {
    let g = parse(FLOW);
    let parts = q::build_partitions(&g);
    let mut reading = HashMap::new();
    reading.insert("x".to_string(), V::Num(15.0));

    let bits = w::encode_reading(&parts, &reading).unwrap();
    let decoded = w::decode_reading(&parts, &bits).unwrap();

    assert_eq!(
        w::route_node(&g, "start", &reading),
        w::route_node(&g, "start", &decoded)
    );
}

#[test]
fn test_missing_field_error() {
    let g = parse(FLOW);
    let parts = q::build_partitions(&g);
    let reading = HashMap::new();

    let err = w::encode_reading(&parts, &reading).unwrap_err();
    assert!(err.contains("missing decision fields"));
}

#[test]
fn test_symbol_count_mismatch_error() {
    let g = parse(FLOW);
    let parts = q::build_partitions(&g);
    let err = w::decode_reading(&parts, "1111").unwrap_err();
    assert!(err.contains("symbol count"));
}

#[test]
fn test_decision_nodes() {
    let g = parse(FLOW);
    let nodes = w::decision_nodes(&g);
    assert_eq!(nodes, vec!["start".to_string()]);
}
