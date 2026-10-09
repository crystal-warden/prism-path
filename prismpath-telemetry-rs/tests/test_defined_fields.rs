// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The Rust twin of test_defined_fields.py: over a flow that defines its fields (SPEC section 4.5),
//! the engine's route survives the wire for every canonical reading in the frozen vectors, absence has
//! a cell of its own, and a value that is not canonical is refused on every path with the reference's
//! field and reason.
use prismpath_rs::{parse, V};
use prismpath_telemetry_rs::{quantizer, wire};
use std::collections::HashMap;

fn corpus() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../prismpath/portable/conformance/field_definitions.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("read field_definitions.json")).expect("parse field_definitions.json")
}

fn reading(object: &serde_json::Value) -> HashMap<String, V> {
    object.as_object().unwrap().iter().map(|(key, value)| (key.clone(), V::from_json(value))).collect()
}

fn accepted() -> Vec<serde_json::Value> {
    corpus()["policies"].as_array().unwrap().iter().filter(|policy| policy["accepted"] == true).cloned().collect()
}

#[test]
fn every_canonical_reading_keeps_its_route_through_the_wire() {
    for policy in accepted() {
        let name = policy["name"].as_str().unwrap();
        let graph = parse(policy["flow"].as_str().unwrap());
        let parts = quantizer::build_partitions(&graph).unwrap_or_else(|reason| panic!("[{name}] {reason}"));
        for probe in policy["probes"].as_array().unwrap() {
            let raw = reading(&probe["reading"]);
            let expected = probe["route"].as_str().map(str::to_string);
            let permissive = wire::encode_reading(&parts, &raw).unwrap_or_else(|error| panic!("[{name}] {raw:?}: {error}"));
            let checked = wire::encode_reading_checked(&parts, &raw).unwrap_or_else(|error| panic!("[{name}] {raw:?}: {error}"));
            assert_eq!(permissive, checked, "[{name}] the two encoders disagree on {raw:?}");
            let decoded = wire::decode_reading(&parts, &checked).unwrap();
            assert_eq!(wire::route_node(&graph, "s", &decoded), expected, "[{name}] {raw:?} decoded to {decoded:?}");
            assert_eq!(wire::encode_reading(&parts, &decoded).unwrap(), checked, "[{name}] re-encoding moved the cell");
        }
    }
}

#[test]
fn a_value_that_is_not_canonical_is_refused_on_every_path() {
    for policy in accepted() {
        let name = policy["name"].as_str().unwrap();
        let graph = parse(policy["flow"].as_str().unwrap());
        let parts = quantizer::build_partitions(&graph).unwrap();
        for refusal in policy["refused_readings"].as_array().unwrap() {
            let raw = reading(&refusal["reading"]);
            let error = wire::encode_reading_checked(&parts, &raw).expect_err("refused");
            assert_eq!((error.field.as_str(), error.refusal.reason()), (refusal["field"].as_str().unwrap(), refusal["reason"].as_str().unwrap()), "[{name}] {raw:?}");
            assert!(wire::encode_reading(&parts, &raw).is_err(), "[{name}] the permissive encoder accepted {raw:?}");
        }
    }
}

#[test]
fn absence_is_its_own_cell() {
    let policy = accepted().into_iter().find(|policy| policy["name"] == "int_and_bool_with_absent_count").unwrap();
    let parts = quantizer::build_partitions(&parse(policy["flow"].as_str().unwrap())).unwrap();
    let count = &parts["count"];
    let absent = count.symbol(&V::Null).unwrap();
    assert_eq!(Some(absent), count.absent_symbol);
    assert_eq!(absent, count.n - 1);
    assert_eq!(count.representative(absent), V::Null);
    for value in -5..=5 {
        assert_ne!(count.symbol(&V::Num(value as f64)).unwrap(), absent);
    }
    let label_policy = accepted().into_iter().find(|policy| policy["name"] == "floor_ratio_with_absent_label").unwrap();
    let label = &quantizer::build_partitions(&parse(label_policy["flow"].as_str().unwrap())).unwrap()["label"];
    let absent_label = label.symbol(&V::Null).unwrap();
    for text in ["", "a", "b", "anything"] {
        assert_ne!(label.symbol(&V::Str(text.to_string())).unwrap(), absent_label, "{text:?}");
    }
}

#[test]
fn a_refused_policy_is_never_partitioned() {
    for policy in corpus()["policies"].as_array().unwrap().iter().filter(|policy| policy["accepted"] == false) {
        let graph = parse(policy["flow"].as_str().unwrap());
        assert!(quantizer::build_partitions(&graph).is_err(), "[{}] was partitioned", policy["name"]);
    }
}

#[test]
fn the_streams_are_byte_identical_to_the_reference() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../prismpath/telemetry/conformance/defined_wire.json");
    let frozen: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).expect("read defined_wire.json")).unwrap();
    let flows: HashMap<String, String> = accepted().iter()
        .map(|policy| (policy["name"].as_str().unwrap().to_string(), policy["flow"].as_str().unwrap().to_string()))
        .collect();
    for policy in frozen["policies"].as_array().unwrap() {
        let name = policy["name"].as_str().unwrap();
        let parts = quantizer::build_partitions(&parse(&flows[name])).unwrap();
        for (field, layout) in policy["fields"].as_object().unwrap() {
            assert_eq!(parts[field].n as u64, layout["cells"].as_u64().unwrap(), "[{name}] {field} cells");
            assert_eq!(parts[field].absent_symbol.map(|symbol| symbol as u64), layout["absent_symbol"].as_u64(), "[{name}] {field} absent");
        }
        for probe in policy["probes"].as_array().unwrap() {
            let raw = reading(&probe["reading"]);
            let symbols = quantizer::checked_quantize(&parts, &raw).unwrap();
            for (field, symbol) in probe["symbols"].as_object().unwrap() {
                assert_eq!(symbols[field] as u64, symbol.as_u64().unwrap(), "[{name}] {field} on {raw:?}");
            }
            assert_eq!(wire::encode_reading_checked(&parts, &raw).unwrap(), probe["bits"].as_str().unwrap(), "[{name}] {raw:?}");
        }
    }
}
