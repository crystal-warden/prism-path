//! The concentrator profile (PROTOCOL.md section 2.9) against `concentrator.json`: datagrams built by the Python
//! `concentrate`, every cut of a multi record datagram, noise and bit flips, each with the records and cause the
//! Python `demux` returns, and the integers beyond 64 bits that Python carries and this crate refuses.

use prismpath_telemetry_rs::concentrator::{concentrate, demux, demux_cause, ConcentratorError, Record, CONCENTRATOR_TRUNCATED, CONCENTRATOR_UNKNOWN_STREAM, OK};
use serde_json::Value;
use std::collections::HashMap;

fn corpus() -> Value {
    let text = std::fs::read_to_string(format!("{}/tests/fixtures/concentrator.json", env!("CARGO_MANIFEST_DIR"))).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn registry(doc: &Value, name: &str) -> HashMap<u64, usize> {
    doc["registries"][name].as_object().unwrap().iter().map(|(sid, count)| (sid.parse().unwrap(), count.as_u64().unwrap() as usize)).collect()
}

fn records_of(value: &Value) -> Vec<Record> {
    value.as_array().unwrap().iter().map(|record| (record[0].as_i64().unwrap() as u64, record[1].as_array().unwrap().iter().map(|v| v.as_i64().unwrap() as u64).collect())).collect()
}

#[test]
fn the_cause_names_are_pythons() {
    let doc = corpus();
    assert_eq!(doc["causes"]["ok"], OK);
    assert_eq!(doc["causes"]["unknown"], CONCENTRATOR_UNKNOWN_STREAM);
    assert_eq!(doc["causes"]["truncated"], CONCENTRATOR_TRUNCATED);
}

#[test]
fn concentrate_cases_match_python_byte_for_byte() {
    let doc = corpus();
    let cases = doc["concentrate"].as_array().unwrap();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let negative = case["records"].as_array().unwrap().iter().any(|record| record[0].as_i64().unwrap() < 0 || record[1].as_array().unwrap().iter().any(|v| v.as_i64().unwrap() < 0));
        if negative {
            assert!(case.get("refuse").is_some(), "{name}"); // a negative has no u64: refused by the type, as Python refuses it
            continue;
        }
        let records = records_of(&case["records"]);
        match case.get("hex") {
            Some(frame) => assert_eq!(hex::encode(concentrate(&records).unwrap()), frame.as_str().unwrap(), "{name}"),
            None => assert!(concentrate(&records).is_err(), "{name}"),
        }
    }
    println!("concentrator encode: {} cases match Python", cases.len());
}

#[test]
fn demux_cases_match_python() {
    let doc = corpus();
    let cases = doc["demux"].as_array().unwrap();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let frame = hex::decode(case["hex"].as_str().unwrap()).unwrap();
        let (records, cause, registry_cause) = demux_cause(&frame, &registry(&doc, case["registry"].as_str().unwrap()))
            .unwrap_or_else(|err| panic!("{name}: {err}"));
        assert_eq!(cause, case["cause"].as_str().unwrap(), "{name}");
        assert_eq!(registry_cause, case["registry_cause"].as_u64().map(|code| code as u8), "{name}: registry cause");
        // `demux` is the same answer without the cause
        assert_eq!(demux(&frame, &registry(&doc, case["registry"].as_str().unwrap())).unwrap(), (records.clone(), cause), "{name}");
        assert_eq!(records, records_of(&case["records"]), "{name}");
    }
    println!("concentrator demux: {} cases match Python", cases.len());
}

#[test]
fn only_a_truncation_carries_a_strict_decode_cause() {
    let doc = corpus();
    let mut seen = std::collections::BTreeSet::new();
    for case in doc["demux"].as_array().unwrap() {
        if let Some(code) = case["registry_cause"].as_u64() {
            assert_eq!(case["cause"], CONCENTRATOR_TRUNCATED, "{}", case["name"]);
            seen.insert(code);
        }
        if case["cause"] == CONCENTRATOR_UNKNOWN_STREAM || case["cause"] == OK {
            assert!(case["registry_cause"].is_null(), "{}", case["name"]);
        }
    }
    assert_eq!(seen.into_iter().collect::<Vec<_>>(), [48, 49]);
}

#[test]
fn a_whole_datagram_is_rejected_never_partly_delivered() {
    let doc = corpus();
    for case in doc["demux"].as_array().unwrap() {
        if case["cause"] != OK {
            assert!(case["records"].as_array().unwrap().is_empty(), "{}", case["name"]);
        }
    }
}

#[test]
fn integers_beyond_64_bits_are_refused_not_wrapped() {
    let doc = corpus();
    for case in doc["wide"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let result = demux(&hex::decode(case["hex"].as_str().unwrap()).unwrap(), &registry(&doc, case["registry"].as_str().unwrap()));
        if case["rust_overflow"].as_bool().unwrap() {
            assert_eq!(result.unwrap_err(), ConcentratorError::Overflow, "{name}");
        } else {
            let (records, cause) = result.unwrap_or_else(|err| panic!("{name}: {err}"));
            assert_eq!(cause, case["cause"].as_str().unwrap(), "{name}");
            let registry_cause = demux_cause(&hex::decode(case["hex"].as_str().unwrap()).unwrap(), &registry(&doc, case["registry"].as_str().unwrap())).unwrap().2;
            assert_eq!(registry_cause, case["registry_cause"].as_u64().map(|code| code as u8), "{name}: registry cause");
            let python: Vec<(String, Vec<String>)> = case["python_records"].as_array().unwrap().iter().map(|record| (record[0].as_str().unwrap().to_string(), record[1].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect())).collect();
            let ours: Vec<(String, Vec<String>)> = records.iter().map(|(sid, ints)| (sid.to_string(), ints.iter().map(u64::to_string).collect())).collect();
            assert_eq!(ours, python, "{name}");
        }
    }
}

#[test]
fn a_hostile_datagram_neither_panics_nor_runs_long() {
    let registry: HashMap<u64, usize> = [(1, 2)].into_iter().collect();
    // a run of 40,000 zero bits, 40,000 one bits, an alternating pattern and a 40,000 bit codeword: each fails closed, quickly
    for frame in [vec![0u8; 5000], vec![0xffu8; 5000], vec![0x55u8; 5000], [vec![0u8; 5000], vec![0xc0]].concat()] {
        let result = demux(&frame, &registry);
        assert!(result.is_ok() || result == Err(ConcentratorError::Overflow), "{result:?}");
    }
}
