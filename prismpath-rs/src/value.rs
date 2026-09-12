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

    pub fn from_json(json_val: &serde_json::Value) -> Value {
        match json_val {
            serde_json::Value::Null => Value::Null,
            serde_json::Value::Bool(bool_val) => Value::Bool(*bool_val),
            serde_json::Value::Number(num_val) => Value::Num(num_val.as_f64().unwrap_or(0.0)),
            serde_json::Value::String(str_val) => Value::Str(str_val.clone()),
            serde_json::Value::Array(arr_val) => Value::List(arr_val.iter().map(Value::from_json).collect()),
            serde_json::Value::Object(obj_val) => {
                Value::Obj(obj_val.iter().map(|(key, item)| (key.clone(), Value::from_json(item))).collect())
            }
        }
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
