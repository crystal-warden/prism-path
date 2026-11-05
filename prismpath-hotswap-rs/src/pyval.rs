// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Small helpers that reproduce how the Python reference reads text and values, so the verifiers in
//! `root_statement` and `flow_authority` accept and refuse exactly what it does.

use serde_json::Value;

/// `bytes.fromhex(text)`: pairs of hex digits in either case, with ASCII whitespace allowed between
/// pairs (never inside one); anything else is a `ValueError`, here `None`.
pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 2);
    let mut chars = text.chars().peekable();
    loop {
        while matches!(chars.peek(), Some(' ' | '\t' | '\n' | '\r' | '\u{b}' | '\u{c}')) {
            chars.next();
        }
        let Some(high) = chars.next() else { return Some(out) };
        let low = chars.next()?;
        out.push((high.to_digit(16)? * 16 + low.to_digit(16)?) as u8);
    }
}

/// A JSON integer as Python's `isinstance(value, int)` sees it, except that a boolean is not one
/// (Python's `True` is an `int`; a verifier that fails closed is the safer reading) and an integer
/// past the `i64` range is not one either.
pub fn py_int(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number) => number.as_i64(),
        _ => None,
    }
}

/// Text read through Python's universal newlines: `\r\n` and a lone `\r` both become `\n`.
pub fn universal_newlines(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

/// The first `count` characters (Python's `text[:count]`).
pub fn head(text: &str, count: usize) -> String {
    text.chars().take(count).collect()
}

/// `str(value)` for the JSON values a manifest field can hold, for the places the reference keys a
/// dictionary by `str(...)`.
pub fn py_str(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "None".to_string(),
        Some(Value::Bool(true)) => "True".to_string(),
        Some(Value::Bool(false)) => "False".to_string(),
        Some(Value::String(text)) => text.clone(),
        Some(Value::Number(number)) => match number.as_i64() {
            Some(int) => int.to_string(),
            None => match number.as_u64() {
                Some(int) => int.to_string(),
                None => prismpath_rs::durable::py_float_repr(number.as_f64().unwrap_or(f64::NAN)),
            },
        },
        Some(other) => prismpath_rs::durable::py_canonical_string(other, true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_hex_reads_what_python_reads() {
        assert_eq!(from_hex(""), Some(vec![]));
        assert_eq!(from_hex("00ff"), Some(vec![0, 255]));
        assert_eq!(from_hex("AbCd"), Some(vec![0xab, 0xcd]));
        assert_eq!(from_hex(" 00 ff\n"), Some(vec![0, 255]));
        assert_eq!(from_hex("0 0"), None);
        assert_eq!(from_hex("abc"), None);
        assert_eq!(from_hex("zz"), None);
        assert_eq!(from_hex("\u{e9}\u{e9}"), None);
        assert_eq!(from_hex("0x00"), None);
    }

    #[test]
    fn newlines_read_as_python_reads_them() {
        assert_eq!(universal_newlines("a\r\nb\rc\nd"), "a\nb\nc\nd");
        assert_eq!(universal_newlines("\r\r\n"), "\n\n");
    }

    #[test]
    fn integers_are_json_integers_only() {
        assert_eq!(py_int(&serde_json::json!(3)), Some(3));
        assert_eq!(py_int(&serde_json::json!(-1)), Some(-1));
        assert_eq!(py_int(&serde_json::json!(3.0)), None);
        assert_eq!(py_int(&serde_json::json!(true)), None);
        assert_eq!(py_int(&serde_json::json!("3")), None);
        assert_eq!(py_int(&serde_json::json!(u64::MAX)), None);
    }

    #[test]
    fn str_of_values() {
        assert_eq!(py_str(None), "None");
        assert_eq!(py_str(Some(&serde_json::json!(null))), "None");
        assert_eq!(py_str(Some(&serde_json::json!("triage"))), "triage");
        assert_eq!(py_str(Some(&serde_json::json!(7))), "7");
        assert_eq!(py_str(Some(&serde_json::json!(true))), "True");
        assert_eq!(py_str(Some(&serde_json::json!(2.5))), "2.5");
    }
}
