// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! canon/2, the one encoding of the verified core's documents (docs/design/spec-verified-core.md,
//! section 3): the Rust twin of `prismpath/kernel/canon2.py`, held to the same frozen vectors
//! (`prismpath/portable/conformance/canon2.json`, replayed by `tests/test_canon2.rs`), and to the Lean
//! reader `Core.readBytes` by the differential harness.
//!
//! `read` is the strict reader (the Lean `Core.readCanonical`): it accepts exactly the canonical bytes of
//! a canon/2 value. A text is first read as canon/2: numbers are integers within plus or minus 2^53 minus
//! 1 written without a fraction, an exponent or a negative zero, objects hold no key twice, strings hold
//! no lone surrogate escape, and nesting is at most 128; a text that breaks one is a `Canon2Error` naming
//! the first rule broken reading left to right. A text that reads but is not the canonical spelling of its
//! value (whitespace, members out of key order, a needless escape) is `Canon2Error::NotCanonical`. `write`
//! produces the canonical bytes (RFC 8785 with no float: no whitespace, members sorted by UTF-16 code
//! units, raw UTF-8 with only `"`, `\` and control characters escaped) and refuses every value `read`
//! could not read back. `canonicalize` is the path for text a person wrote: every rule but the spelling,
//! then the canonical bytes, which `read` accepts; it is a writer's step and no reader calls it.
//! `codec` is serde for canon/2, so a document type derives its reader and writer.

use crate::value::Value;

pub mod codec;

pub const EXACT_LIMIT: i64 = (1i64 << 53) - 1;
pub const MAX_DEPTH: usize = 128;

/// A canon/2 value. There is no float: a number is an integer within the exact range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Doc {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Arr(Vec<Doc>),
    /// In document order; the reader guarantees distinct keys.
    Obj(Vec<(String, Doc)>),
}

/// The first canon/2 rule a text breaks, with the reference's names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Canon2Error {
    Utf8,
    Syntax,
    Float,
    IntegerRange,
    NegativeZero,
    DuplicateKey,
    LoneSurrogate,
    Depth,
    /// The text reads as canon/2 but is not the canonical spelling of its value.
    NotCanonical,
}

impl Canon2Error {
    pub fn rule(self) -> &'static str {
        match self {
            Canon2Error::Utf8 => "utf8",
            Canon2Error::Syntax => "syntax",
            Canon2Error::Float => "float",
            Canon2Error::IntegerRange => "integer-range",
            Canon2Error::NegativeZero => "negative-zero",
            Canon2Error::DuplicateKey => "duplicate-key",
            Canon2Error::LoneSurrogate => "lone-surrogate",
            Canon2Error::Depth => "depth",
            Canon2Error::NotCanonical => "not-canonical",
        }
    }
}

impl std::fmt::Display for Canon2Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "canon/2 {}", self.rule())
    }
}

impl std::error::Error for Canon2Error {}

struct Reader {
    chars: Vec<char>,
    pos: usize,
}

impl Reader {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos + offset).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
            self.pos += 1;
        }
    }

    fn starts_with(&self, word: &str) -> bool {
        word.chars().enumerate().all(|(index, expected)| self.at(index) == Some(expected))
    }

    fn value(&mut self, depth: usize) -> Result<Doc, Canon2Error> {
        self.skip_ws();
        for (word, doc) in [("null", Doc::Null), ("true", Doc::Bool(true)), ("false", Doc::Bool(false))] {
            if self.starts_with(word) {
                self.pos += word.len();
                return Ok(doc);
            }
        }
        match self.peek() {
            Some('"') => {
                self.pos += 1;
                self.string().map(Doc::Str)
            }
            Some('-') => {
                self.pos += 1;
                self.number(true)
            }
            Some('[') => {
                if depth + 1 > MAX_DEPTH {
                    return Err(Canon2Error::Depth);
                }
                self.pos += 1;
                self.skip_ws();
                if self.peek() == Some(']') {
                    self.pos += 1;
                    return Ok(Doc::Arr(Vec::new()));
                }
                let mut items = vec![self.value(depth + 1)?];
                loop {
                    self.skip_ws();
                    match self.peek() {
                        Some(']') => {
                            self.pos += 1;
                            return Ok(Doc::Arr(items));
                        }
                        Some(',') => {
                            self.pos += 1;
                            items.push(self.value(depth + 1)?);
                        }
                        _ => return Err(Canon2Error::Syntax),
                    }
                }
            }
            Some('{') => {
                if depth + 1 > MAX_DEPTH {
                    return Err(Canon2Error::Depth);
                }
                self.pos += 1;
                self.skip_ws();
                if self.peek() == Some('}') {
                    self.pos += 1;
                    return Ok(Doc::Obj(Vec::new()));
                }
                let mut members: Vec<(String, Doc)> = Vec::new();
                loop {
                    self.skip_ws();
                    if self.peek() != Some('"') {
                        return Err(Canon2Error::Syntax);
                    }
                    self.pos += 1;
                    let key = self.string()?;
                    if members.iter().any(|(seen, _)| *seen == key) {
                        return Err(Canon2Error::DuplicateKey);
                    }
                    self.skip_ws();
                    if self.peek() != Some(':') {
                        return Err(Canon2Error::Syntax);
                    }
                    self.pos += 1;
                    let value = self.value(depth + 1)?;
                    members.push((key, value));
                    self.skip_ws();
                    match self.peek() {
                        Some('}') => {
                            self.pos += 1;
                            return Ok(Doc::Obj(members));
                        }
                        Some(',') => self.pos += 1,
                        _ => return Err(Canon2Error::Syntax),
                    }
                }
            }
            Some(digit) if digit.is_ascii_digit() => self.number(false),
            _ => Err(Canon2Error::Syntax),
        }
    }

    /// Four hex digits at `offset`, `None` when they are not hex (the caller has checked they exist).
    fn hex4(&self, offset: usize) -> Option<u32> {
        let mut value = 0u32;
        for index in 0..4 {
            value = value * 16 + self.at(offset + index)?.to_digit(16)?;
        }
        Some(value)
    }

    fn string(&mut self) -> Result<String, Canon2Error> {
        let mut out = String::new();
        loop {
            let Some(character) = self.peek() else { return Err(Canon2Error::Syntax) };
            if character == '"' {
                self.pos += 1;
                return Ok(out);
            }
            if character == '\\' && self.at(1).is_some() {
                let escape = self.at(1).unwrap_or_default();
                if escape == 'u' && self.pos + 6 <= self.chars.len() {
                    let high = self.hex4(2).ok_or(Canon2Error::Syntax)?;
                    if (0xD800..=0xDBFF).contains(&high) {
                        if self.at(6) == Some('\\') && self.at(7) == Some('u') && self.pos + 12 <= self.chars.len() {
                            let low = self.hex4(8).ok_or(Canon2Error::Syntax)?;
                            if (0xDC00..=0xDFFF).contains(&low) {
                                let code = 0x10000 + (high - 0xD800) * 0x400 + (low - 0xDC00);
                                out.push(char::from_u32(code).ok_or(Canon2Error::LoneSurrogate)?);
                                self.pos += 12;
                                continue;
                            }
                        }
                        return Err(Canon2Error::LoneSurrogate);
                    }
                    if (0xDC00..=0xDFFF).contains(&high) {
                        return Err(Canon2Error::LoneSurrogate);
                    }
                    out.push(char::from_u32(high).ok_or(Canon2Error::Syntax)?);
                    self.pos += 6;
                    continue;
                }
                let unescaped = match escape {
                    '"' => '"',
                    '\\' => '\\',
                    '/' => '/',
                    'b' => '\u{8}',
                    'f' => '\u{c}',
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    _ => return Err(Canon2Error::Syntax),
                };
                out.push(unescaped);
                self.pos += 2;
                continue;
            }
            if (character as u32) < 0x20 {
                return Err(Canon2Error::Syntax);
            }
            out.push(character);
            self.pos += 1;
        }
    }

    fn digits(&mut self) -> String {
        let start = self.pos;
        while matches!(self.peek(), Some(digit) if digit.is_ascii_digit()) {
            self.pos += 1;
        }
        self.chars[start..self.pos].iter().collect()
    }

    fn number(&mut self, negative: bool) -> Result<Doc, Canon2Error> {
        let digits = match self.peek() {
            Some('0') => {
                self.pos += 1;
                "0".to_string()
            }
            Some(digit) if digit.is_ascii_digit() => self.digits(),
            _ => return Err(Canon2Error::Syntax),
        };
        let mut float = false;
        if self.peek() == Some('.') {
            self.pos += 1;
            if self.digits().is_empty() {
                return Err(Canon2Error::Syntax);
            }
            float = true;
        }
        if matches!(self.peek(), Some('e' | 'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some('+' | '-')) {
                self.pos += 1;
            }
            if self.digits().is_empty() {
                return Err(Canon2Error::Syntax);
            }
            float = true;
        }
        if float {
            return Err(Canon2Error::Float);
        }
        if negative && digits == "0" {
            return Err(Canon2Error::NegativeZero);
        }
        if digits.len() > 16 {
            return Err(Canon2Error::IntegerRange);
        }
        let magnitude: i64 = digits.parse().map_err(|_| Canon2Error::IntegerRange)?;
        if magnitude > EXACT_LIMIT {
            return Err(Canon2Error::IntegerRange);
        }
        Ok(Doc::Int(if negative { -magnitude } else { magnitude }))
    }
}

/// The value of a text read by every canon/2 rule but the spelling.
fn parse(text: &str) -> Result<Doc, Canon2Error> {
    let mut reader = Reader { chars: text.chars().collect(), pos: 0 };
    let value = reader.value(0)?;
    reader.skip_ws();
    if reader.pos != reader.chars.len() {
        return Err(Canon2Error::Syntax);
    }
    Ok(value)
}

/// The canon/2 document in `bytes`, when `bytes` is exactly the canonical spelling of its value: strict
/// UTF-8 first, then the document, then the spelling (`NotCanonical`).
pub fn read(bytes: &[u8]) -> Result<Doc, Canon2Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| Canon2Error::Utf8)?;
    read_str(text)
}

/// `read` on text already known to be UTF-8.
pub fn read_str(text: &str) -> Result<Doc, Canon2Error> {
    let value = parse(text)?;
    if write(&value)?.as_slice() != text.as_bytes() {
        return Err(Canon2Error::NotCanonical);
    }
    Ok(value)
}

fn write_string(text: &str, out: &mut String) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            control if (control as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", control as u32)),
            other => out.push(other),
        }
    }
    out.push('"');
}

fn write_into(doc: &Doc, depth: usize, out: &mut String) -> Result<(), Canon2Error> {
    match doc {
        Doc::Null => out.push_str("null"),
        Doc::Bool(true) => out.push_str("true"),
        Doc::Bool(false) => out.push_str("false"),
        Doc::Int(number) => {
            if *number > EXACT_LIMIT || *number < -EXACT_LIMIT {
                return Err(Canon2Error::IntegerRange);
            }
            out.push_str(&number.to_string());
        }
        Doc::Str(text) => write_string(text, out),
        Doc::Arr(items) => {
            if depth + 1 > MAX_DEPTH {
                return Err(Canon2Error::Depth);
            }
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_into(item, depth + 1, out)?;
            }
            out.push(']');
        }
        Doc::Obj(members) => {
            if depth + 1 > MAX_DEPTH {
                return Err(Canon2Error::Depth);
            }
            let mut sorted: Vec<&(String, Doc)> = members.iter().collect();
            sorted.sort_by(|left, right| left.0.encode_utf16().cmp(right.0.encode_utf16()));
            if sorted.windows(2).any(|pair| pair[0].0 == pair[1].0) {
                return Err(Canon2Error::DuplicateKey);
            }
            out.push('{');
            for (index, (key, value)) in sorted.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_into(value, depth + 1, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// The canonical canon/2 bytes of a document, or the rule it would break on reading back.
pub fn write(doc: &Doc) -> Result<Vec<u8>, Canon2Error> {
    let mut out = String::new();
    write_into(doc, 0, &mut out)?;
    Ok(out.into_bytes())
}

/// The canonical bytes of the canon/2 value a person wrote in `bytes`, in any legal spelling
/// (whitespace, member order, escapes); every other rule holds as in `read`, and the result is what
/// `read` accepts. A writer's step, never a reader's (`prismpath.kernel.canon2.canonicalize`).
pub fn canonicalize(bytes: &[u8]) -> Result<Vec<u8>, Canon2Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| Canon2Error::Utf8)?;
    write(&parse(text)?)
}

impl Doc {
    /// The engine's value of a document. Every canon/2 integer is exact as a double.
    pub fn to_value(&self) -> Value {
        match self {
            Doc::Null => Value::Null,
            Doc::Bool(flag) => Value::Bool(*flag),
            Doc::Int(number) => Value::Num(*number as f64),
            Doc::Str(text) => Value::Str(text.clone()),
            Doc::Arr(items) => Value::List(items.iter().map(Doc::to_value).collect()),
            Doc::Obj(members) => Value::Obj(members.iter().map(|(key, value)| (key.clone(), value.to_value())).collect()),
        }
    }

    /// The document as a serde_json value, for callers that work in serde_json.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Doc::Null => serde_json::Value::Null,
            Doc::Bool(flag) => serde_json::Value::Bool(*flag),
            Doc::Int(number) => serde_json::Value::Number((*number).into()),
            Doc::Str(text) => serde_json::Value::String(text.clone()),
            Doc::Arr(items) => serde_json::Value::Array(items.iter().map(Doc::to_json).collect()),
            Doc::Obj(members) => {
                let mut map = serde_json::Map::new();
                for (key, value) in members {
                    map.insert(key.clone(), value.to_json());
                }
                serde_json::Value::Object(map)
            }
        }
    }
}

/// A serde_json value as a canon/2 document: an integer number within plus or minus 2^53 minus 1 is an
/// `Int`, a number written with a fraction or an exponent is refused as `Float`, an integer beyond the
/// range as `IntegerRange`, and nesting deeper than `MAX_DEPTH` as `Depth`. This is how a writer that
/// builds its document in serde_json hands it to `write`.
pub fn from_json(value: &serde_json::Value) -> Result<Doc, Canon2Error> {
    from_json_at(value, 0)
}

fn from_json_at(value: &serde_json::Value, depth: usize) -> Result<Doc, Canon2Error> {
    Ok(match value {
        serde_json::Value::Null => Doc::Null,
        serde_json::Value::Bool(flag) => Doc::Bool(*flag),
        serde_json::Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                if !(-EXACT_LIMIT..=EXACT_LIMIT).contains(&integer) {
                    return Err(Canon2Error::IntegerRange);
                }
                Doc::Int(integer)
            } else if number.as_u64().is_some() {
                return Err(Canon2Error::IntegerRange);
            } else {
                // serde_json keeps the digits it read (`arbitrary_precision`): an integer too wide for
                // 64 bits has only digits and a sign, a float has a fraction or an exponent.
                let text = number.to_string();
                let digits = text.strip_prefix('-').unwrap_or(&text);
                if !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(Canon2Error::IntegerRange);
                }
                return Err(Canon2Error::Float);
            }
        }
        serde_json::Value::String(text) => Doc::Str(text.clone()),
        serde_json::Value::Array(items) => {
            if depth + 1 > MAX_DEPTH {
                return Err(Canon2Error::Depth);
            }
            Doc::Arr(items.iter().map(|item| from_json_at(item, depth + 1)).collect::<Result<_, _>>()?)
        }
        serde_json::Value::Object(members) => {
            if depth + 1 > MAX_DEPTH {
                return Err(Canon2Error::Depth);
            }
            Doc::Obj(
                members
                    .iter()
                    .map(|(key, item)| Ok((key.clone(), from_json_at(item, depth + 1)?)))
                    .collect::<Result<_, Canon2Error>>()?,
            )
        }
    })
}

/// The canon/2 bytes of a serde_json value: `write(&from_json(value)?)`.
pub fn write_json(value: &serde_json::Value) -> Result<Vec<u8>, Canon2Error> {
    write(&from_json(value)?)
}
