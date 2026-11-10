// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Value domain definitions for the PrismPath Rust kernel.

pub const MAX_DEPTH: usize = 50;

/// The comparison-recursion cap standing in for the .mjs catch in compareOp. JS absorbs an
/// engine-level recursion overflow on absurdly nested contexts into unsatisfied; Rust has no
/// catchable stack overflow, so the same protection must be an explicit depth budget. Generous:
/// no legitimate context comes close, and running out behaves exactly like the .mjs catch.
pub const CMP_DEPTH: usize = 200;

/// The evaluator's value domain: JSON plus Python's ellipsis.
///
/// Ellipsis has to live INSIDE the recursive type, not beside it, because predicate source can put
/// it anywhere a literal goes (when x in [..., 1]). All numbers are f64, mirroring the .mjs (and
/// JSON itself): the corpus cannot distinguish 3 from 3.0 or the certified port would not pass.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    List(Vec<Value>),
    /// Insertion-ordered, like a JS object / Python dict: ordering is observable through
    /// py_str, which renders dict outcomes into text that predicates then route on.
    Obj(Vec<(String, Value)>),
    Ellipsis,
}

/// Backwards compatibility alias for the Value enum.
pub type V = Value;

impl Value {
    /// Inverse of from_json. An integral finite Num serializes as a JSON integer: the
    /// reference (Python/JS) writes 3, never 3.0, and checkpoints must round-trip that.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Value::Null | Value::Ellipsis => serde_json::Value::Null,
            Value::Bool(bool_val) => serde_json::Value::Bool(*bool_val),
            Value::Num(num_val) => {
                if num_val.fract() == 0.0 && num_val.is_finite() && num_val.abs() < 9.0e15 {
                    serde_json::Value::Number((*num_val as i64).into())
                } else {
                    serde_json::Number::from_f64(*num_val)
                        .map(serde_json::Value::Number)
                        .unwrap_or(serde_json::Value::Null)
                }
            }
            Value::Str(str_val) => serde_json::Value::String(str_val.clone()),
            Value::List(items) => serde_json::Value::Array(items.iter().map(Value::to_json).collect()),
            Value::Obj(entries) => {
                let mut map_obj = serde_json::Map::new();
                for (key, val) in entries {
                    map_obj.insert(key.clone(), val.to_json());
                }
                serde_json::Value::Object(map_obj)
            }
        }
    }

    /// A JSON value as an engine value. A number beyond the double range is refused (see
    /// `try_from_json`); every input boundary reads with `parse_strict`, so none reaches here, and
    /// one that did stops with a panic rather than become infinity or zero.
    pub fn from_json(json_val: &serde_json::Value) -> Value {
        Self::try_from_json(json_val).unwrap_or_else(|error| panic!("{error}; read documents with value::parse_strict"))
    }

    /// `from_json`, refusing a number with no finite double (past 1.8e308, written as an integer or
    /// not) instead of converting it to infinity, zero or NaN.
    pub fn try_from_json(json_val: &serde_json::Value) -> Result<Value, String> {
        Ok(match json_val {
            serde_json::Value::Null => Value::Null,
            serde_json::Value::Bool(bool_val) => Value::Bool(*bool_val),
            serde_json::Value::Number(num_val) => Value::Num(number_to_f64(num_val).ok_or_else(|| {
                let text = num_val.to_string();
                let shown: String = text.chars().take(24).collect();
                format!("number {shown} is beyond the double range and is refused, not read as infinity")
            })?),
            serde_json::Value::String(str_val) => Value::Str(str_val.clone()),
            serde_json::Value::Array(arr_val) => {
                Value::List(arr_val.iter().map(Value::try_from_json).collect::<Result<Vec<_>, _>>()?)
            }
            serde_json::Value::Object(obj_val) => Value::Obj(
                obj_val
                    .iter()
                    .map(|(key, item)| Value::try_from_json(item).map(|value| (key.clone(), value)))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
        })
    }

    pub fn obj_get<'a>(entries: &'a [(String, Value)], key: &str) -> Option<&'a Value> {
        entries.iter().find(|(k, _)| k == key).map(|(_, val)| val)
    }
}

#[derive(Debug, Clone)]
pub struct PredicateError(pub String);

impl std::fmt::Display for PredicateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.0)
    }
}
impl std::error::Error for PredicateError {}

pub fn perr<ValType>(msg: impl Into<String>) -> Result<ValType, PredicateError> {
    Err(PredicateError(msg.into()))
}

/// A JSON number as a finite double, or `None` when it has none. serde_json is built with
/// `arbitrary_precision`, where a number beyond the double range (`1e400`) keeps its digits and has
/// no `as_f64`. Such a number is REFUSED, never read as infinity and never as zero: canonical JSON
/// has no non finite number, and `prismpath.canon` refuses the same text (`CanonicalReadError`).
pub fn number_to_f64(number: &serde_json::Number) -> Option<f64> {
    number.as_f64().or_else(|| number.to_string().parse::<f64>().ok()).filter(|double| double.is_finite())
}

/// A number written with digits only (and an optional sign) is an integer of any width, which both
/// languages keep exactly, so it has no double and needs none.
pub fn is_integer_text(number: &serde_json::Number) -> bool {
    let text = number.to_string();
    let digits = text.strip_prefix('-').unwrap_or(&text);
    !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
}

/// Refuse a document that holds a number canonical JSON cannot carry: one beyond the double range
/// (`1e400`, `-1e400`). NaN, Infinity and lone surrogates never reach a `serde_json::Value`, which
/// refuses them at parse; this is the refusal for the one case serde_json accepts.
pub fn check_canonical(value: &serde_json::Value) -> Result<(), String> {
    match value {
        serde_json::Value::Number(number) => {
            if is_integer_text(number) || number_to_f64(number).is_some() {
                Ok(())
            } else {
                let text = number.to_string();
                let shown: String = text.chars().take(24).collect();
                Err(format!("number {shown} is beyond the double range and is refused, not read as infinity"))
            }
        }
        serde_json::Value::Array(items) => items.iter().try_for_each(check_canonical),
        serde_json::Value::Object(entries) => entries.values().try_for_each(check_canonical),
        _ => Ok(()),
    }
}

/// `serde_json::from_str::<Value>` for a document that is hashed, signed or verified: the same
/// text prismpath.canon.loads accepts. NaN, Infinity, lone surrogates and any text serde_json
/// refuses fail in the parse; a number beyond the double range fails here. The error type is
/// serde_json's, so a caller swaps this in for `serde_json::from_str` unchanged.
pub fn parse_strict(text: &str) -> Result<serde_json::Value, serde_json::Error> {
    let value: serde_json::Value = serde_json::from_str(text)?;
    check_canonical(&value).map_err(<serde_json::Error as serde::de::Error>::custom)?;
    Ok(value)
}
