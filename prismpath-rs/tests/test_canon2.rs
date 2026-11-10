// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The canon/2 reader and writer replay the reference's frozen vectors
//! (`prismpath/portable/conformance/canon2.json`, written by `gen_canon2_fixtures.py`): every case is
//! refused with the reference's rule, or read and written back to the reference's canonical bytes.

use prismpath_rs::canon2::{self, Doc};
use serde_json::Value;

fn corpus() -> Value {
    let text = std::fs::read_to_string("../prismpath/portable/conformance/canon2.json").expect("read canon2.json");
    serde_json::from_str(&text).expect("parse canon2.json")
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex")).collect()
}

#[test]
fn every_vector_reads_as_the_reference_reads_it() {
    let doc = corpus();
    let cases = doc["cases"].as_array().expect("cases");
    assert!(cases.len() > 60);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let bytes = unhex(case["hex"].as_str().unwrap());
        match (canon2::read(&bytes), case.get("refuse").and_then(Value::as_str)) {
            (Err(error), Some(rule)) => assert_eq!(error.rule(), rule, "[{name}]"),
            (Ok(document), None) => {
                let want = unhex(case["canonical_hex"].as_str().unwrap());
                let written = canon2::write(&document).expect("a read document writes");
                assert_eq!(written, want, "[{name}] canonical bytes");
                let again = canon2::read(&written).expect("canonical bytes read");
                assert_eq!(canon2::write(&again).unwrap(), written, "[{name}] the canonical bytes are a fixed point");
            }
            (got, want) => panic!("[{name}] the reference says {want:?}, Rust read {got:?}"),
        }
    }
}

#[test]
fn the_writer_refuses_what_the_reader_would() {
    assert_eq!(canon2::write(&Doc::Int(1 << 53)), Err(canon2::Canon2Error::IntegerRange));
    let mut deep = Doc::Arr(Vec::new());
    for _ in 0..128 {
        deep = Doc::Arr(vec![deep]);
    }
    assert_eq!(canon2::write(&deep), Err(canon2::Canon2Error::Depth));
    let duplicate = Doc::Obj(vec![("a".into(), Doc::Null), ("a".into(), Doc::Null)]);
    assert_eq!(canon2::write(&duplicate), Err(canon2::Canon2Error::DuplicateKey));
}

#[test]
fn members_sort_by_utf16_code_units() {
    let doc = Doc::Obj(vec![("\u{ffff}".into(), Doc::Int(1)), ("\u{1f600}".into(), Doc::Int(2)), ("\u{e000}".into(), Doc::Int(3))]);
    assert_eq!(String::from_utf8(canon2::write(&doc).unwrap()).unwrap(), "{\"\u{1f600}\":2,\"\u{e000}\":3,\"\u{ffff}\":1}");
}
