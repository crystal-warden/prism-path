// Wire byte-identity vs the Python reference (the true 1-1 / cross-impl-interop property): the Rust wire
// must emit the SAME Fibonacci bit-strings Python does, not merely self-round-trip. Expected bits are
// frozen from the Python reference in tests/fixtures/wire_parity.json (regenerate from adapters/telemetry).
use prismpath_rs::{parse, V};
use prismpath_telemetry_rs::{quantizer as q, wire as w};
use serde_json::Value;
use std::collections::HashMap;

fn load(p: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(p).expect(p)).expect("json")
}

fn reading_of(obj: &serde_json::Map<String, Value>) -> HashMap<String, V> {
    obj.iter().map(|(k, v)| (k.clone(), V::from_json(v))).collect()
}

#[test]
fn test_wire_bytes_match_python_and_decode_cross_impl() {
    let corpus = load("../adapters/telemetry/conformance/decisions.json");
    let fixture = load("tests/fixtures/wire_parity.json");
    let mut n = 0;
    for case in corpus["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let g = parse(case["flow"].as_str().unwrap());
        let parts = q::build_partitions(&g);
        let py_bits = fixture[name].as_array().unwrap();
        for (i, entry) in case["readings"].as_array().unwrap().iter().enumerate() {
            let reading = reading_of(entry["reading"].as_object().unwrap());
            let expected = py_bits[i].as_str().unwrap();

            // (1) Rust encodes byte-identical to Python.
            let rs_bits = w::encode_reading(&parts, &reading).expect("encode");
            assert_eq!(rs_bits, expected, "[{name}] reading {i}: Rust bits != Python bits");

            // (2) Rust decodes the PYTHON-produced bit-string and routes to the tagged route.
            let recon = w::decode_reading(&parts, expected).expect("decode python bits");
            for (node, tgt) in entry["routes"].as_object().unwrap() {
                assert_eq!(
                    w::route_node(&g, node, &recon),
                    tgt.as_str().map(String::from),
                    "[{name}] reading {i}: cross-impl decode routed wrong at {node}"
                );
            }
            n += 1;
        }
    }
    assert_eq!(n, 55, "expected 55 readings across the corpus");
}
