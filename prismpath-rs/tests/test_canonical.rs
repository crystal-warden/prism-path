// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The byte rules under everything hashed or signed: canon/2 is the one encoding, a document without its tag
//! is refused (canon/1 is retired), a float in hashed content is refused, and what has no JSON form at all (a
//! number beyond the double range) is refused on read and on write. The canon/2 bytes themselves are pinned by
//! `conformance/canon2.json` (`test_canon2.rs`).
#![cfg(feature = "durable")]

use prismpath_rs::durable::{
    canon2_bytes, content_bytes, document_bytes, encoding_of, plain_dumps, py_float_repr, read_document, signed_message, tagged,
    CANON2_DOMAIN,
};
use serde_json::{json, Value};

/// JSON has no form for these inputs, and neither language converts them: both refuse the document when
/// they read it (`canon.plain_loads`, `value::parse_plain`).
#[test]
fn every_refused_input_is_refused_on_read() {
    let refused = [
        "NaN", "[Infinity]", "-Infinity", r#"{"x": NaN}"#, "1e400", "-1e400", "[1, 1e999]", r#"{"x": 1E+999}"#,
        r#"{"x": -1e400}"#, "1.7976931348623159e308",
    ];
    for text in refused {
        assert!(prismpath_rs::value::parse_plain(text).is_err(), "{text}: parse_plain accepted it");
        assert!(read_document(text).is_err(), "{text}: read_document accepted it");
    }
}

/// A number beyond the double range is the one input serde_json holds; plain parsing keeps its digits,
/// and every use of it refuses: no bytes, no engine value, no double. It is never infinity and never zero.
#[test]
fn a_number_beyond_the_double_range_is_refused_never_converted() {
    for text in ["1e400", "-1e400", "1.7976931348623159e308", "[1, 1e999]", r#"{"a": 1E+999}"#] {
        let json: Value = serde_json::from_str(text).unwrap();
        assert!(plain_dumps(&json).is_err(), "{text}: bytes were written");
        assert!(canon2_bytes(&json).is_err(), "{text}: canon/2 bytes were written");
        assert!(content_bytes(&json).is_err(), "{text}: content bytes were written");
        assert!(prismpath_rs::value::Value::try_from_json(&json).is_err(), "{text}: became an engine value");
        assert!(prismpath_rs::value::parse_plain(text).is_err(), "{text}: parse_plain accepted it");
    }
    let huge: Value = serde_json::from_str("1e400").unwrap();
    assert_eq!(prismpath_rs::value::number_to_f64(huge.as_number().unwrap()), None);
    for (text, expect) in [("1e30", 1e30), ("1.7976931348623157e308", f64::MAX), ("1e-400", 0.0)] {
        let json = prismpath_rs::value::parse_plain(text).unwrap();
        assert!(matches!(prismpath_rs::value::Value::from_json(&json), prismpath_rs::value::Value::Num(number) if number == expect), "{text}");
    }
}

/// canon/1 is retired: a document with no tag, another tag or no object at all has no bytes, no signed message
/// and no reading, and is never read under another encoding.
#[test]
fn a_document_that_does_not_name_canon2_is_refused_everywhere() {
    for doc in [json!({"a": 1}), json!({"encoding": "canon/1"}), json!({"encoding": "canon/3"}), json!({"encoding": null}), json!([1]), json!("x"), json!(7)] {
        assert!(encoding_of(&doc).is_err(), "{doc}");
        assert!(document_bytes(&doc).is_err(), "{doc}");
        assert!(signed_message(&doc).is_err(), "{doc}");
    }
    for text in [r#"{"a":1}"#, r#"{"a":1.5}"#, r#"{"encoding":"canon/1"}"#, "[1]", "7"] {
        let error = read_document(text).expect_err(text);
        assert!(error.to_string().contains("canon/2") || error.to_string().contains("JSON object"), "{text}: {error}");
    }
    let doc = tagged(json!({"b": 2, "a": "é"}));
    assert_eq!(document_bytes(&doc).unwrap(), r#"{"a":"é","b":2,"encoding":"canon/2"}"#.as_bytes().to_vec());
    let mut message = CANON2_DOMAIN.to_vec();
    message.extend(document_bytes(&doc).unwrap());
    assert_eq!(signed_message(&doc).unwrap(), message);
    assert_eq!(read_document(r#"{"encoding":"canon/2","n":1}"#).unwrap(), json!({"encoding": "canon/2", "n": 1}));
    assert!(read_document(r#"{"encoding":"canon/2","n":1.5}"#).is_err());
}

/// A float anywhere in hashed content is refused with the words Python's `FloatRefused` uses.
#[test]
fn a_float_in_hashed_content_is_refused_not_converted() {
    for text in ["0.5", r#"{"r": 0.1}"#, r#"{"n": [1, 2.0]}"#, r#"{"x": {"y": [1e30]}}"#, "-0.0", "1E2"] {
        let value = prismpath_rs::value::parse_plain(text).unwrap();
        let error = content_bytes(&value).expect_err(text);
        assert!(error.to_string().contains("integer of a stated unit"), "{text}: {error}");
        assert!(error.to_string().contains("a decimal string"), "{text}: {error}");
    }
    assert_eq!(content_bytes(&json!({"r": "0.1", "n": [1, 2]})).unwrap(), br#"{"n":[1,2],"r":"0.1"}"#.to_vec());
    assert_eq!(content_bytes(&json!({"big": 9007199254740991i64, "neg": -9007199254740991i64})).unwrap().len(), 48);
    assert!(content_bytes(&json!({"big": 9007199254740992i64})).is_err(), "an integer past 2^53 minus 1 is refused");
}

/// The sink's line is Python's `json.dumps(sort_keys=True)`: it is not canon/2 and nothing hashed is written with it.
#[test]
fn plain_dumps_is_pythons_json_dumps() {
    assert_eq!(plain_dumps(&json!({"b": 1, "a": [1, 2.5, "é", null, true]})).unwrap(), r#"{"a": [1, 2.5, "\u00e9", null, true], "b": 1}"#);
}

#[test]
fn float_spellings_match_python_repr() {
    // Each right hand side is `repr(float)` from CPython, which is what `json.dumps` writes.
    for (value, python) in [
        (0.0, "0.0"), (-0.0, "-0.0"), (1.0, "1.0"), (100.0, "100.0"), (2.5, "2.5"), (0.1, "0.1"),
        (0.30000000000000004, "0.30000000000000004"), (0.0001, "0.0001"), (0.00001, "1e-05"),
        (1.5e-7, "1.5e-07"), (5e-324, "5e-324"), (1e15, "1000000000000000.0"), (1e16, "1e+16"), (1.5e20, "1.5e+20"),
        (1.7976931348623157e308, "1.7976931348623157e+308"),
    ] {
        assert_eq!(py_float_repr(value), python, "{value:e}");
    }
}

/// The strict reader and the canonicalize path (spec section 3.2): a hashed or signed document is read only
/// as its exact canonical bytes, followed by at most the one line feed that ends a file or a line; a document
/// a person wrote is written through `canonicalize_document` first, which keeps every other canon/2 rule.
#[test]
fn a_document_is_read_only_as_its_canonical_bytes_and_canonicalize_writes_them() {
    use prismpath_rs::durable::{canonicalize_document, NOT_CANONICAL_CAUSE};
    let human = "{\n  \"encoding\": \"canon/2\",\n  \"name\": \"\\u0041pple\",\n  \"a\": [1, 2,  3]\n}\n";
    let canonical = r#"{"a":[1,2,3],"encoding":"canon/2","name":"Apple"}"#;
    let error = read_document(human).unwrap_err();
    assert!(error.is_not_canonical() && error.0.starts_with(NOT_CANONICAL_CAUSE), "{error}");
    let written = canonicalize_document(human).unwrap();
    assert_eq!(written, canonical.as_bytes());
    assert_eq!(read_document(canonical).unwrap(), json!({"a": [1, 2, 3], "encoding": "canon/2", "name": "Apple"}));
    assert!(read_document(&format!("{canonical}\n")).is_ok());
    for respelled in [format!("{canonical}\r\n"), format!("{canonical}\n\n"), format!(" {canonical}"), format!("{canonical} ")] {
        assert!(read_document(&respelled).unwrap_err().is_not_canonical(), "{respelled:?}");
    }
    assert_eq!(canonicalize_document(canonical).unwrap(), canonical.as_bytes());
    for refused in [r#"{"x": 1.5}"#, r#"{"a":1,"a":2}"#, r#"{"x": 9007199254740992}"#, "{"] {
        assert!(canonicalize_document(refused).is_err(), "{refused}");
    }
    // a float, a duplicate key and a range break are their own refusals, never `not-canonical`
    assert!(!read_document(r#"{"encoding":"canon/2","x": 1.5}"#).unwrap_err().is_not_canonical());
}
