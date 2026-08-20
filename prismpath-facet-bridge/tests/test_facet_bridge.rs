// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC

use facet::Facet;
use prismpath_facet_bridge::{bind, reading_from, BindError, FieldKind};
use prismpath_rs::{parse, V};
use prismpath_telemetry_rs::{quantizer, wire};
use std::collections::HashMap;

#[derive(Facet)]
struct SamplePolicyRecord {
    latency_ns: i64,
    is_active: bool,
    tenant_id: String,
}

#[derive(Facet)]
struct MissingFieldPolicyRecord {
    latency_ns: i64,
    is_active: bool,
}

#[derive(Facet)]
struct FloatPolicyRecord {
    latency_ns: f64,
    is_active: bool,
    tenant_id: String,
}

#[derive(Facet)]
struct Nested {
    val: i64,
}

#[derive(Facet)]
struct NestedPolicyRecord {
    latency_ns: Nested,
    is_active: bool,
    tenant_id: String,
}

#[test]
fn test_bind_and_reading_round_trip() {
    let expected = [
        ("latency_ns", FieldKind::Numeric),
        ("is_active", FieldKind::Boolean),
        ("tenant_id", FieldKind::Categorical),
    ];

    let binding = bind::<SamplePolicyRecord>(&expected).expect("bind should succeed for valid struct");

    // Check canonical sorted-name order in binding
    let bound_field_names: Vec<&str> = binding.fields().iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(bound_field_names, vec!["is_active", "latency_ns", "tenant_id"]);

    let record = SamplePolicyRecord {
        latency_ns: 42000,
        is_active: true,
        tenant_id: "tenant-alpha".to_string(),
    };

    let reading = reading_from(&binding, &record).expect("reading_from should succeed");

    let mut hand_built = HashMap::new();
    hand_built.insert("latency_ns".to_string(), V::Num(42000.0));
    hand_built.insert("is_active".to_string(), V::Bool(true));
    hand_built.insert("tenant_id".to_string(), V::Str("tenant-alpha".to_string()));

    assert_eq!(reading, hand_built);

    // Verify bitstream encoding parity with telemetry wire codec
    let flow = r#"---
name: test_policy
start: start
---
## start
-> n1: when latency_ns >= 1000 and is_active and tenant_id == "tenant-alpha"
-> n2: else
## n1
## n2
"#;
    let graph = parse(flow);
    let parts = quantizer::build_partitions(&graph);

    let bits_extracted = wire::encode_reading(&parts, &reading).expect("encode reading from extracted");
    let bits_hand_built = wire::encode_reading(&parts, &hand_built).expect("encode reading from hand-built");

    assert_eq!(bits_extracted, bits_hand_built);
}

#[test]
fn test_missing_field_fails_bind() {
    let expected = [
        ("latency_ns", FieldKind::Numeric),
        ("is_active", FieldKind::Boolean),
        ("tenant_id", FieldKind::Categorical),
    ];

    let err = bind::<MissingFieldPolicyRecord>(&expected).expect_err("bind should fail when field is missing");
    match err {
        BindError::MissingField { field } => {
            assert_eq!(field, "tenant_id");
        }
        other => panic!("expected MissingField error, got {:?}", other),
    }
}

#[test]
fn test_f64_policy_field_fails_bind_unrepresentable() {
    let expected = [
        ("latency_ns", FieldKind::Numeric),
        ("is_active", FieldKind::Boolean),
        ("tenant_id", FieldKind::Categorical),
    ];

    let err = bind::<FloatPolicyRecord>(&expected).expect_err("bind should fail for f64 policy field");
    match err {
        BindError::UnrepresentableType { field, details: _ } => {
            assert_eq!(field, "latency_ns");
        }
        other => panic!("expected UnrepresentableType error, got {:?}", other),
    }
}

#[test]
fn test_nested_struct_fails_bind_unrepresentable() {
    let expected = [
        ("latency_ns", FieldKind::Numeric),
        ("is_active", FieldKind::Boolean),
        ("tenant_id", FieldKind::Categorical),
    ];

    let err = bind::<NestedPolicyRecord>(&expected).expect_err("bind should fail for nested struct policy field");
    match err {
        BindError::UnrepresentableType { field, details: _ } => {
            assert_eq!(field, "latency_ns");
        }
        other => panic!("expected UnrepresentableType error, got {:?}", other),
    }
}
