// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Canonical JSON gate: replay `conformance/canonical.json`, generated from `prismpath.canon`, so the
//! bytes every signature and Merkle leaf is hashed over are pinned for floats (exponents, tiny and
//! huge values, integral values, negative zero), integers beyond 64 bits, unicode escapes, key
//! ordering and nesting, and the inputs canonical JSON refuses (NaN, Infinity, a number beyond the double
//! range, a lone surrogate). Each input is JSON text, parsed here and written back in both encodings.
#![cfg(feature = "durable")]

use prismpath_rs::durable::{py_canonical_string, py_float_repr, try_py_canonical_string};
use serde_json::Value;

fn corpus() -> Value {
    let path = format!("{}/../prismpath/portable/conformance/canonical.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).expect("read canonical.json")).expect("parse canonical.json")
}

#[test]
fn canonical_bytes_match_python_for_every_case() {
    let corpus = corpus();
    let cases = corpus["cases"].as_array().unwrap();
    let mut failures = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let value: Value = prismpath_rs::value::parse_strict(case["json"].as_str().unwrap())
            .unwrap_or_else(|error| panic!("{name}: Rust cannot parse {}: {error}", case["json"]));
        for (spaced, key) in [(false, "compact"), (true, "spaced")] {
            let got = py_canonical_string(&value, spaced);
            if got != case[key].as_str().unwrap() {
                failures.push(format!("{name} {key}: rust {got} python {}", case[key].as_str().unwrap()));
            }
        }
    }
    assert!(failures.is_empty(), "{} of {} outputs differ from Python:\n{}", failures.len(), cases.len() * 2, failures.join("\n"));
    eprintln!("canonical: {}/{} cases identical to Python in both encodings", cases.len(), cases.len());
}

/// Canonical JSON has no form for these inputs, and neither language converts them: both refuse the
/// document when they read it (`canon.loads`, `parse_strict`). The list of inputs Python writes
/// bytes for and Rust refuses is empty, so the corpus has no divergence to record.
#[test]
fn every_refused_input_is_refused_on_read() {
    let corpus = corpus();
    let refused = corpus["refused"].as_array().unwrap();
    assert!(refused.len() >= 14, "the refused list shrank");
    for case in refused {
        let (name, text) = (case["name"].as_str().unwrap(), case["json"].as_str().unwrap());
        assert!(case.get("compact").is_none(), "{name}: a refused input carries no bytes");
        let error = prismpath_rs::value::parse_strict(text).expect_err(&format!("{name}: parse_strict accepted {text}"));
        eprintln!("canonical: refused {name}: {error}");
    }
    eprintln!("canonical: {}/{} refused inputs refused on read", refused.len(), refused.len());
}

/// A number beyond the double range is the one input serde_json holds; plain parsing keeps its digits,
/// and every use of it refuses: no canonical bytes, no engine value, no double. It is never infinity
/// and never zero.
#[test]
fn a_number_beyond_the_double_range_is_refused_never_converted() {
    for text in ["1e400", "-1e400", "1.7976931348623159e308", "[1, 1e999]", r#"{"a": 1E+999}"#] {
        let json: Value = serde_json::from_str(text).unwrap();
        assert!(py_canonical_string_refused(&json), "{text}: canonical bytes were written");
        assert!(prismpath_rs::value::Value::try_from_json(&json).is_err(), "{text}: became an engine value");
        assert!(prismpath_rs::value::parse_strict(text).is_err(), "{text}: parse_strict accepted it");
    }
    let huge: Value = serde_json::from_str("1e400").unwrap();
    assert_eq!(prismpath_rs::value::number_to_f64(huge.as_number().unwrap()), None);
    for (text, expect) in [("1e30", 1e30), ("1.7976931348623157e308", f64::MAX), ("1e-400", 0.0)] {
        let json = prismpath_rs::value::parse_strict(text).unwrap();
        assert!(matches!(prismpath_rs::value::Value::from_json(&json), prismpath_rs::value::Value::Num(number) if number == expect), "{text}");
    }
}

fn py_canonical_string_refused(value: &Value) -> bool {
    [false, true].iter().all(|spaced| try_py_canonical_string(value, *spaced).is_err())
}

#[test]
fn float_spellings_match_python_repr_for_bit_patterns() {
    let corpus = corpus();
    for item in corpus["floats"].as_array().unwrap() {
        let bits = u64::from_str_radix(item["bits"].as_str().unwrap(), 16).unwrap();
        assert_eq!(py_float_repr(f64::from_bits(bits)), item["repr"].as_str().unwrap(), "bits {:016x}", bits);
    }
}
