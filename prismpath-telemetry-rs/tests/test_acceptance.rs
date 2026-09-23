//! The Facet acceptance, pinned by the frozen inputs corpus the Python side reads too: every
//! case's value is accepted to the recorded symbol or refused for the recorded reason, by
//! `checked_symbol` and by `encode_reading_checked`; the permissive `symbol` agrees on every
//! accepted value; and an unsupported input can never become a valid zero reading.
use prismpath_rs::{parse, V};
use prismpath_telemetry_rs::quantizer::{self, InputRefusal};
use prismpath_telemetry_rs::wire;
use serde_json::Value;
use std::collections::HashMap;

fn corpus() -> Value {
    let text = std::fs::read_to_string(FIXTURE).expect("read inputs corpus");
    serde_json::from_str(&text).expect("parse inputs corpus")
}

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../prismpath/telemetry/conformance/inputs.json");

fn partitions(corpus: &Value) -> HashMap<String, quantizer::FieldPartition> {
    quantizer::build_partitions(&parse(corpus["flow"].as_str().unwrap()))
}

fn expected_refusal(reason: &str) -> InputRefusal {
    match reason {
        "missing" => InputRefusal::Missing,
        "wrong_type" => InputRefusal::WrongType,
        "unparseable_string" => InputRefusal::UnparseableString,
        "fractional" => InputRefusal::Fractional,
        "out_of_range" => InputRefusal::OutOfRange,
        other => panic!("unknown reason {other}"),
    }
}

#[test]
fn checked_symbol_follows_the_corpus() {
    let corpus = corpus();
    let parts = partitions(&corpus);
    let mut checked = 0;
    for case in corpus["cases"].as_array().unwrap() {
        let field = case["field"].as_str().unwrap();
        let value = V::from_json(&case["input"]);
        let outcome = parts[field].checked_symbol(&value);
        if let Some(symbol) = case["expect"]["symbol"].as_u64() {
            assert_eq!(outcome, Ok(symbol as usize), "{field} {}", case["input"]);
            let converted = quantizer::accept_value(&parts[field].kind, &value).unwrap();
            assert_eq!(parts[field].symbol(&converted), Ok(symbol as usize), "permissive symbol agrees on {field} {}", case["input"]);
        } else {
            let error = outcome.expect_err(&format!("{field} {} must be refused", case["input"]));
            assert_eq!(error.field, field);
            assert_eq!(error.refusal, expected_refusal(case["expect"]["refuse"].as_str().unwrap()), "{field} {}", case["input"]);
        }
        checked += 1;
    }
    assert!(checked >= 50);
}

#[test]
fn checked_encoding_follows_the_corpus() {
    let corpus = corpus();
    let parts = partitions(&corpus);
    for entry in corpus["readings"].as_array().unwrap() {
        let reading: HashMap<String, V> = entry["reading"].as_object().unwrap().iter()
            .map(|(key, value)| (key.clone(), V::from_json(value))).collect();
        let outcome = wire::encode_reading_checked(&parts, &reading);
        if let Some(symbols) = entry["expect"]["symbols"].as_object() {
            let bits = outcome.expect("accepted reading encodes");
            let expected: HashMap<String, usize> = symbols.iter().map(|(key, value)| (key.clone(), value.as_u64().unwrap() as usize)).collect();
            assert_eq!(quantizer::checked_quantize(&parts, &reading).unwrap(), expected);
            assert_eq!(wire::decode_reading(&parts, &bits).unwrap(), quantizer::reconstruct(&parts, &expected));
        } else {
            let error = outcome.expect_err("refused reading does not encode");
            assert_eq!(error.field, entry["expect"]["refuse"]["field"].as_str().unwrap());
            assert_eq!(error.refusal.reason(), entry["expect"]["refuse"]["reason"].as_str().unwrap());
        }
    }
}

#[test]
fn an_unparseable_string_is_never_a_zero_reading() {
    let corpus = corpus();
    let parts = partitions(&corpus);
    let text = V::Str("abc".to_string());
    assert!(parts["error_rate"].checked_symbol(&text).is_err());
    assert!(parts["error_rate"].symbol(&text).is_err(), "the permissive path errors too; it no longer reads the string as zero");
    assert!(parts["error_rate"].symbol(&V::Null).is_err());
    assert_eq!(parts["error_rate"].symbol(&V::Num(0.0)), Ok(0), "the zero cell exists and is reached only by a number");
}
