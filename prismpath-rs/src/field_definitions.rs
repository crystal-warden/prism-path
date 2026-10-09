// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Field definitions (SPEC section 4.5): the signed meaning of every value a flow routes on. The
//! Rust twin of `prismpath/kernel/field_definitions.py`, held to the same frozen vectors in
//! `prismpath/portable/conformance/field_definitions.json`.
//!
//! `parse` calls `apply_definitions`, which lowers every decimal literal compared with a `fixed` field
//! to its canonical integer and checks the policy rules. `parse` cannot fail, so a flow that breaks its
//! definitions comes back with `field_error` set and every edge disabled; the engine refuses to run it
//! and the codec refuses to partition it, and a caller that ignores the error still cannot route on an
//! unlowered threshold. `parse_checked` returns the error instead.
//!
//! Everything is exact. Decimal text is read as a mantissa and a power of ten in 128 bit integers,
//! within the bounds the reference shares (28 significant digits, an exponent of at most 30), so the
//! two implementations refuse the same texts and compute the same integers.

use std::collections::{BTreeMap, BTreeSet};

use crate::condition::{error_expr, expr_of, is_deterministic, is_error, is_semantic, tokenize_spanned, Tok, ALWAYS, NEVER};
use crate::level_m::{is_level_m, level_m_atoms};
use crate::parser::Graph;
use crate::value::Value;

pub const FIELD_PREFIX: &str = "field.";
pub const EXACT_INTEGER_LIMIT: i64 = (1i64 << 53) - 1;
pub const MAX_SCALE: i64 = 1_000_000_000;
pub const MAX_DECIMAL_DIGITS: usize = 28;
pub const MAX_DECIMAL_EXPONENT: i64 = 30;
const ENGINE_COUNTERS: [&str; 2] = ["visits", "error_count"];

pub const REFUSAL_MISSING: &str = "missing";
pub const REFUSAL_WRONG_TYPE: &str = "wrong_type";
pub const REFUSAL_UNPARSEABLE_STRING: &str = "unparseable_string";
pub const REFUSAL_FRACTIONAL: &str = "fractional";
pub const REFUSAL_OUT_OF_RANGE: &str = "out_of_range";
pub const REFUSAL_OFF_GRID: &str = "off_grid";
pub const REFUSAL_BINARY_FLOAT: &str = "binary_float";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefinedKind {
    Int,
    Fixed,
    Bool,
    Category,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rounding {
    Floor,
    Ceiling,
    Exact,
}

impl Rounding {
    fn word(self) -> &'static str {
        match self {
            Rounding::Floor => "floor",
            Rounding::Ceiling => "ceiling",
            Rounding::Exact => "exact",
        }
    }

    /// The atoms this rounding mode carries exactly. Each set is closed under negation.
    fn carries(self, op: &str) -> bool {
        match self {
            Rounding::Floor => matches!(op, ">=" | "<"),
            Rounding::Ceiling => matches!(op, ">" | "<="),
            Rounding::Exact => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDefinition {
    pub name: String,
    pub kind: DefinedKind,
    pub scale: Option<i64>,
    pub rounding: Option<Rounding>,
    pub unit: Option<String>,
    pub minimum: i64,
    pub maximum: i64,
    pub absent_allowed: bool,
}

impl FieldDefinition {
    /// The definition written one fixed way, identical to the reference's `canonical_text`.
    pub fn canonical_text(&self) -> String {
        let kind = match self.kind {
            DefinedKind::Int => "int",
            DefinedKind::Fixed => "fixed",
            DefinedKind::Bool => "bool",
            DefinedKind::Category => "category",
        };
        let mut words = vec![kind.to_string()];
        if self.kind == DefinedKind::Fixed {
            words.push(format!("scale={}", self.scale.unwrap_or_default()));
            words.push(format!("rounding={}", self.rounding.map(Rounding::word).unwrap_or_default()));
            if let Some(unit) = &self.unit {
                words.push(format!("unit={unit}"));
            }
        }
        if matches!(self.kind, DefinedKind::Int | DefinedKind::Fixed) {
            words.push(format!("min={}", self.minimum));
            words.push(format!("max={}", self.maximum));
        }
        words.push(if self.absent_allowed { "absent=allowed" } else { "absent=refused" }.to_string());
        words.join(" ")
    }
}

/// A value the conversion or the canonical boundary refuses, with the field and the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalRefusal {
    pub field: String,
    pub reason: &'static str,
}

// ----------------------------------------------------------------- definitions
fn integer_option(name: &str, option: &str, text: &str) -> Result<i64, String> {
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    if digits.is_empty() || !digits.chars().all(|character| character.is_ascii_digit()) {
        return Err(format!("field {name:?}: {option}={text:?} is not an integer"));
    }
    // an integer too long for i64 is far outside every bound below, so it reads as out of range
    Ok(text.parse::<i64>().unwrap_or(if text.starts_with('-') { i64::MIN } else { i64::MAX }))
}

pub fn parse_definition(name: &str, text: &str) -> Result<FieldDefinition, String> {
    let name_ok = name.chars().next().is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && name.chars().all(|character| character.is_ascii_alphanumeric() || character == '_');
    if !name_ok {
        return Err(format!("field {name:?}: not a field name"));
    }
    if ENGINE_COUNTERS.contains(&name) {
        return Err(format!("field {name:?}: the engine supplies this counter, it is not defined"));
    }
    let mut words = text.split_whitespace();
    let kind_word = words.next().ok_or_else(|| format!("field {name:?}: the definition is empty"))?;
    let (kind, allowed): (DefinedKind, &[&str]) = match kind_word {
        "int" => (DefinedKind::Int, &["min", "max", "absent"]),
        "fixed" => (DefinedKind::Fixed, &["scale", "rounding", "unit", "min", "max", "absent"]),
        "bool" => (DefinedKind::Bool, &["absent"]),
        "category" => (DefinedKind::Category, &["absent"]),
        other => return Err(format!("field {name:?}: unknown kind {other:?} (int, fixed, bool, category)")),
    };
    let mut options: BTreeMap<String, String> = BTreeMap::new();
    for word in words {
        let (option, value) = word.split_once('=').unwrap_or((word, ""));
        if value.is_empty() || !word.contains('=') {
            return Err(format!("field {name:?}: {word:?} is not option=value"));
        }
        if !allowed.contains(&option) {
            return Err(format!("field {name:?}: a {kind_word} field takes no {option:?} option"));
        }
        if options.insert(option.to_string(), value.to_string()).is_some() {
            return Err(format!("field {name:?}: {option:?} is given twice"));
        }
    }
    let absent = options.get("absent").map(String::as_str).unwrap_or("refused");
    if absent != "refused" && absent != "allowed" {
        return Err(format!("field {name:?}: absent={absent:?} is neither refused nor allowed"));
    }
    let (mut scale, mut rounding, mut unit) = (None, None, None);
    if kind == DefinedKind::Fixed {
        let (Some(scale_text), Some(rounding_text)) = (options.get("scale"), options.get("rounding")) else {
            return Err(format!("field {name:?}: a fixed field needs both scale and rounding"));
        };
        let scale_value = integer_option(name, "scale", scale_text)?;
        if !(1..=MAX_SCALE).contains(&scale_value) {
            return Err(format!("field {name:?}: scale={scale_value} is outside 1 to {MAX_SCALE}"));
        }
        scale = Some(scale_value);
        rounding = Some(match rounding_text.as_str() {
            "floor" => Rounding::Floor,
            "ceiling" => Rounding::Ceiling,
            "exact" => Rounding::Exact,
            other => return Err(format!("field {name:?}: rounding={other:?} is not floor, ceiling or exact")),
        });
        unit = options.get("unit").cloned();
    }
    let minimum = options.get("min").map(|text| integer_option(name, "min", text)).transpose()?.unwrap_or(-EXACT_INTEGER_LIMIT);
    let maximum = options.get("max").map(|text| integer_option(name, "max", text)).transpose()?.unwrap_or(EXACT_INTEGER_LIMIT);
    if !(-EXACT_INTEGER_LIMIT <= minimum && minimum <= maximum && maximum <= EXACT_INTEGER_LIMIT) {
        return Err(format!("field {name:?}: the range {minimum} to {maximum} is empty or wider than plus or minus 2^53 minus 1"));
    }
    Ok(FieldDefinition { name: name.to_string(), kind, scale, rounding, unit, minimum, maximum, absent_allowed: absent == "allowed" })
}

/// Every field definition in a flow's front matter, keyed by field name.
pub fn definitions_of(meta: &std::collections::HashMap<String, String>) -> Result<BTreeMap<String, FieldDefinition>, String> {
    let mut keys: Vec<&String> = meta.keys().filter(|key| key.starts_with(FIELD_PREFIX)).collect();
    keys.sort();
    keys.into_iter()
        .map(|key| {
            let name = &key[FIELD_PREFIX.len()..];
            parse_definition(name, &meta[key]).map(|definition| (name.to_string(), definition))
        })
        .collect()
}

// ----------------------------------------------------------------- exact decimals
/// An exact decimal: `mantissa * 10^exponent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExactDecimal {
    pub mantissa: i128,
    pub exponent: i64,
}

/// The exact value of decimal text within the shared bounds, or None when it is not such text. The
/// accepted text is the reference's: an optional sign, digits with an optional point (at least one
/// digit on some side), then an optional exponent, and nothing else, not even whitespace.
pub fn decimal_value(text: &str) -> Option<ExactDecimal> {
    let (negative, unsigned) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    let (mantissa_text, exponent_text) = match unsigned.find(['e', 'E']) {
        Some(index) => (&unsigned[..index], Some(&unsigned[index + 1..])),
        None => (unsigned, None),
    };
    let (integer_part, fraction_part) = mantissa_text.split_once('.').unwrap_or((mantissa_text, ""));
    let digits_only = |part: &str| part.bytes().all(|byte| byte.is_ascii_digit());
    if !digits_only(integer_part) || !digits_only(fraction_part) || (integer_part.is_empty() && fraction_part.is_empty()) {
        return None;
    }
    let mut exponent: i64 = 0;
    if let Some(exponent_text) = exponent_text {
        let exponent_digits = exponent_text.strip_prefix(['+', '-']).unwrap_or(exponent_text);
        if exponent_digits.is_empty() || !digits_only(exponent_digits) {
            return None;
        }
        let trimmed = exponent_digits.trim_start_matches('0');
        if trimmed.len() > 3 {
            return None;                                   // far past the bound, and safe from overflow
        }
        exponent = trimmed.parse::<i64>().unwrap_or(0);
        if exponent_text.starts_with('-') {
            exponent = -exponent;
        }
        if exponent.abs() > MAX_DECIMAL_EXPONENT {
            return None;
        }
    }
    let all_digits = format!("{integer_part}{fraction_part}");
    let significant = all_digits.trim_start_matches('0');
    if significant.len() > MAX_DECIMAL_DIGITS {
        return None;
    }
    let magnitude: i128 = if significant.is_empty() { 0 } else { significant.parse().ok()? };
    Some(ExactDecimal { mantissa: if negative { -magnitude } else { magnitude }, exponent: exponent - fraction_part.len() as i64 })
}

/// How an exact value times `scale` becomes an integer.
enum Settle {
    Floor,
    Ceiling,
    WholeOr(&'static str),
}

/// `value * scale` settled to an integer, or the refusal. Overflow only happens far outside every range.
fn settle(value: ExactDecimal, scale: i64, how: Settle) -> Result<i128, &'static str> {
    let numerator = value.mantissa * scale as i128;                  // below 10^28 * 10^9, fits
    if value.exponent >= 0 {
        return 10i128
            .checked_pow(value.exponent as u32)
            .and_then(|power| numerator.checked_mul(power))
            .ok_or(REFUSAL_OUT_OF_RANGE);
    }
    let (quotient, remainder) = match 10i128.checked_pow((-value.exponent) as u32) {
        Some(divisor) => (numerator / divisor, numerator % divisor),
        None => (0, numerator),                                       // the divisor exceeds the numerator
    };
    match how {
        Settle::Floor => Ok(quotient - i128::from(remainder != 0 && numerator < 0)),
        Settle::Ceiling => Ok(quotient + i128::from(remainder != 0 && numerator > 0)),
        Settle::WholeOr(reason) => if remainder == 0 { Ok(quotient) } else { Err(reason) },
    }
}

fn in_range(definition: &FieldDefinition, canonical: i128) -> Result<i64, &'static str> {
    if canonical < definition.minimum as i128 || canonical > definition.maximum as i128 {
        return Err(REFUSAL_OUT_OF_RANGE);
    }
    Ok(canonical as i64)
}

fn exact_to_canonical(definition: &FieldDefinition, exact: ExactDecimal) -> Result<i64, &'static str> {
    let canonical = match definition.kind {
        DefinedKind::Fixed => {
            let how = match definition.rounding {
                Some(Rounding::Floor) => Settle::Floor,
                Some(Rounding::Ceiling) => Settle::Ceiling,
                _ => Settle::WholeOr(REFUSAL_OFF_GRID),
            };
            settle(exact, definition.scale.unwrap_or(1), how)?
        }
        _ => settle(exact, 1, Settle::WholeOr(REFUSAL_FRACTIONAL))?,
    };
    in_range(definition, canonical)
}

// ----------------------------------------------------------------- the shared conversion
/// The canonical value of a source value under its field's signed definition, the twin of the
/// reference's `canonical_value`. A string on a numeric field is decimal text; a number is a double,
/// accepted only when integral, since the decimal a fractional double was printed from is lost.
pub fn canonical_value(definition: &FieldDefinition, raw: &Value) -> Result<Value, CanonicalRefusal> {
    let refuse = |reason: &'static str| CanonicalRefusal { field: definition.name.clone(), reason };
    if matches!(raw, Value::Null) {
        return if definition.absent_allowed { Ok(Value::Null) } else { Err(refuse(REFUSAL_MISSING)) };
    }
    match definition.kind {
        DefinedKind::Bool => return if matches!(raw, Value::Bool(_)) { Ok(raw.clone()) } else { Err(refuse(REFUSAL_WRONG_TYPE)) },
        DefinedKind::Category => return if matches!(raw, Value::Str(_)) { Ok(raw.clone()) } else { Err(refuse(REFUSAL_WRONG_TYPE)) },
        _ => {}
    }
    let exact = match raw {
        Value::Num(number) => {
            if !number.is_finite() {
                return Err(refuse(REFUSAL_OUT_OF_RANGE));
            }
            if number.fract() != 0.0 {
                return Err(refuse(if definition.kind == DefinedKind::Fixed { REFUSAL_BINARY_FLOAT } else { REFUSAL_FRACTIONAL }));
            }
            ExactDecimal { mantissa: *number as i128, exponent: 0 }   // saturates only far out of range
        }
        Value::Str(text) => decimal_value(text).ok_or_else(|| refuse(REFUSAL_UNPARSEABLE_STRING))?,
        _ => return Err(refuse(REFUSAL_WRONG_TYPE)),
    };
    exact_to_canonical(definition, exact).map(|canonical| Value::Num(canonical as f64)).map_err(refuse)
}

/// Ok(value) for a value that is already canonical, or the refusal reason. It converts nothing.
pub fn accept_canonical(definition: &FieldDefinition, value: &Value) -> Result<Value, &'static str> {
    if matches!(value, Value::Null) {
        return if definition.absent_allowed { Ok(Value::Null) } else { Err(REFUSAL_MISSING) };
    }
    match (definition.kind, value) {
        (DefinedKind::Bool, Value::Bool(_)) | (DefinedKind::Category, Value::Str(_)) => Ok(value.clone()),
        (DefinedKind::Int | DefinedKind::Fixed, Value::Num(number)) => {
            if !number.is_finite() {
                return Err(REFUSAL_OUT_OF_RANGE);
            }
            if number.fract() != 0.0 {
                return Err(REFUSAL_FRACTIONAL);
            }
            in_range(definition, *number as i128).map(|integer| Value::Num(integer as f64))
        }
        _ => Err(REFUSAL_WRONG_TYPE),
    }
}

// ----------------------------------------------------------------- lowering
/// The tree lowering needs: names, numeric literals with their spans, lists and comparisons, and
/// everything else only as a container to walk into. It follows `condition::Parser` rule for rule;
/// a grouping parenthesis is transparent, as it is in the reference's syntax tree.
enum LoweringNode {
    Name(String),
    Literal { span: (usize, usize), number_token: usize, negative: bool },
    List(Vec<LoweringNode>),
    Compare { operands: Vec<LoweringNode>, ops: Vec<String> },
    Other(Vec<LoweringNode>),
}

struct LoweringParser<'a> {
    toks: &'a [Tok],
    spans: &'a [(usize, usize)],
    pos: usize,
}

impl LoweringParser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn peek_op(&self, op: &str) -> bool {
        matches!(self.peek(), Some(Tok::Op(found)) if found == op)
    }
    fn peek_name(&self, name: &str) -> bool {
        matches!(self.peek(), Some(Tok::Name(found)) if found == name)
    }
    fn expect(&mut self, op: &str) -> Option<()> {
        if self.peek_op(op) {
            self.pos += 1;
            Some(())
        } else {
            None
        }
    }
    fn joined(&mut self, keyword: &str, next: fn(&mut Self) -> Option<LoweringNode>) -> Option<LoweringNode> {
        let mut values = vec![next(self)?];
        while self.peek_name(keyword) {
            self.pos += 1;
            values.push(next(self)?);
        }
        Some(if values.len() == 1 { values.pop()? } else { LoweringNode::Other(values) })
    }
    fn or_expr(&mut self) -> Option<LoweringNode> {
        self.joined("or", Self::and_expr)
    }
    fn and_expr(&mut self) -> Option<LoweringNode> {
        self.joined("and", Self::not_expr)
    }
    fn not_expr(&mut self) -> Option<LoweringNode> {
        if self.peek_name("not") {
            self.pos += 1;
            return Some(LoweringNode::Other(vec![self.not_expr()?]));
        }
        self.compare()
    }
    fn compare_op(&mut self) -> Option<Option<String>> {
        match self.peek() {
            Some(Tok::Op(op)) if ["==", "!=", "<", "<=", ">", ">="].contains(&op.as_str()) => {
                let found = op.clone();
                self.pos += 1;
                Some(Some(found))
            }
            Some(Tok::Name(name)) if name == "in" => {
                self.pos += 1;
                Some(Some("in".to_string()))
            }
            Some(Tok::Name(name)) if name == "not" => {
                self.pos += 1;
                if self.peek_name("in") {
                    self.pos += 1;
                    Some(Some("not in".to_string()))
                } else {
                    None
                }
            }
            _ => Some(None),
        }
    }
    fn compare(&mut self) -> Option<LoweringNode> {
        let first = self.operand()?;
        let (mut operands, mut ops) = (vec![first], Vec::new());
        while let Some(op) = self.compare_op()? {
            ops.push(op);
            operands.push(self.operand()?);
        }
        if ops.is_empty() {
            return operands.pop();
        }
        Some(LoweringNode::Compare { operands, ops })
    }
    fn sequence(&mut self, close: &str) -> Option<Vec<LoweringNode>> {
        let mut elements = Vec::new();
        if self.peek().is_some() && !self.peek_op(close) {
            elements.push(self.or_expr()?);
            while self.peek_op(",") {
                self.pos += 1;
                if self.peek_op(close) {
                    break;
                }
                elements.push(self.or_expr()?);
            }
        }
        self.expect(close)?;
        Some(elements)
    }
    fn operand(&mut self) -> Option<LoweringNode> {
        let index = self.pos;
        let tok = self.peek()?.clone();
        self.pos += 1;
        match tok {
            Tok::Op(op) if op == "-" || op == "+" => {
                // a sign on any number: the reference lowers `-0.5` on a fixed field, though the
                // predicate language itself only folds a sign onto an integer
                if let Some(Tok::Num(..)) = self.peek() {
                    self.pos += 1;
                    return Some(LoweringNode::Literal { span: (self.spans[index].0, self.spans[index + 1].1), number_token: index + 1, negative: op == "-" });
                }
                None
            }
            Tok::Num(..) => Some(LoweringNode::Literal { span: self.spans[index], number_token: index, negative: false }),
            Tok::Str(_) | Tok::Ellipsis => Some(LoweringNode::Other(Vec::new())),
            Tok::Name(name) => match name.as_str() {
                "True" | "False" | "None" => Some(LoweringNode::Other(Vec::new())),
                "and" | "or" | "not" | "in" => None,
                _ => Some(LoweringNode::Name(name)),
            },
            Tok::Op(op) if op == "[" => self.sequence("]").map(LoweringNode::List),
            Tok::Op(op) if op == "(" => {
                if self.peek_op(")") {
                    self.pos += 1;
                    return Some(LoweringNode::List(Vec::new()));
                }
                let first = self.or_expr()?;
                if self.peek_op(",") {
                    let mut elements = vec![first];
                    while self.peek_op(",") {
                        self.pos += 1;
                        if self.peek_op(")") {
                            break;
                        }
                        elements.push(self.or_expr()?);
                    }
                    self.expect(")")?;
                    return Some(LoweringNode::List(elements));
                }
                self.expect(")")?;
                Some(first)
            }
            Tok::Op(_) => None,
        }
    }
}

/// The exact value of a literal node, read from its own source text.
fn literal_value(chars: &[char], toks: &[Tok], spans: &[(usize, usize)], number_token: usize, negative: bool) -> Result<ExactDecimal, String> {
    let (start, end) = spans[number_token];
    let text: String = chars[start..end].iter().filter(|character| **character != '_').collect();
    let lower = text.to_lowercase();
    let mut exact = if lower.starts_with("0x") || lower.starts_with("0o") || lower.starts_with("0b") {
        let Tok::Num(value, _) = toks[number_token] else { unreachable!("a literal names a number token") };
        ExactDecimal { mantissa: value as i128, exponent: 0 }
    } else {
        decimal_value(&text).ok_or_else(|| format!("the literal {text:?} has more digits than an exact threshold carries"))?
    };
    if negative {
        exact.mantissa = -exact.mantissa;
    }
    Ok(exact)
}

/// The expression with every numeric literal compared with a fixed field replaced by its canonical
/// integer, or the reason a literal cannot be lowered. An expression that does not parse comes back
/// unchanged, as in the reference, and the policy rules then refuse it.
pub fn lower_expression(expr: &str, definitions: &BTreeMap<String, FieldDefinition>) -> Result<String, String> {
    let fixed: BTreeSet<&str> = definitions.iter().filter(|(_, definition)| definition.kind == DefinedKind::Fixed).map(|(name, _)| name.as_str()).collect();
    if fixed.is_empty() {
        return Ok(expr.to_string());
    }
    let Ok((toks, spans)) = tokenize_spanned(expr) else { return Ok(expr.to_string()) };
    let mut parser = LoweringParser { toks: &toks, spans: &spans, pos: 0 };
    let tree = match parser.or_expr() {
        Some(first) if parser.peek_op(",") => {
            let mut elements = vec![first];
            while parser.peek_op(",") {
                parser.pos += 1;
                if parser.peek().is_none() {
                    break;
                }
                match parser.or_expr() {
                    Some(element) => elements.push(element),
                    None => return Ok(expr.to_string()),
                }
            }
            LoweringNode::Other(elements)
        }
        Some(tree) => tree,
        None => return Ok(expr.to_string()),
    };
    if parser.pos != toks.len() {
        return Ok(expr.to_string());
    }
    let chars: Vec<char> = expr.chars().collect();
    let mut replacements: BTreeMap<(usize, usize), (String, i64)> = BTreeMap::new();
    collect_lowering(&tree, &fixed, definitions, &chars, &toks, &spans, &mut replacements)?;
    let mut lowered = chars;
    for ((start, end), (_field, canonical)) in replacements.iter().rev() {
        lowered.splice(*start..*end, canonical.to_string().chars());
    }
    Ok(lowered.into_iter().collect())
}

#[allow(clippy::too_many_arguments)]
fn lower_one(field: &str, node: &LoweringNode, definitions: &BTreeMap<String, FieldDefinition>, chars: &[char], toks: &[Tok], spans: &[(usize, usize)], replacements: &mut BTreeMap<(usize, usize), (String, i64)>) -> Result<(), String> {
    let LoweringNode::Literal { span, number_token, negative } = node else { return Ok(()) };
    let definition = &definitions[field];
    let source: String = chars[span.0..span.1].iter().collect();
    let exact = literal_value(chars, toks, spans, *number_token, *negative)?;
    let canonical = settle(exact, definition.scale.unwrap_or(1), Settle::WholeOr(REFUSAL_OFF_GRID))
        .map_err(|_| format!("field {field:?}: the threshold {source} is not a multiple of 1/{}", definition.scale.unwrap_or(1)))?;
    let canonical = in_range(definition, canonical)
        .map_err(|_| format!("field {field:?}: the threshold {source} is outside {} to {} canonically", definition.minimum, definition.maximum))?;
    if let Some((other, _)) = replacements.get(span) {
        if other != field && definitions[other].scale != definition.scale {
            return Err(format!("the literal {source} sits between two fixed fields of different scales"));
        }
    }
    replacements.insert(*span, (field.to_string(), canonical));
    Ok(())
}

fn collect_lowering(node: &LoweringNode, fixed: &BTreeSet<&str>, definitions: &BTreeMap<String, FieldDefinition>, chars: &[char], toks: &[Tok], spans: &[(usize, usize)], replacements: &mut BTreeMap<(usize, usize), (String, i64)>) -> Result<(), String> {
    let fixed_name = |node: &LoweringNode| match node {
        LoweringNode::Name(name) if fixed.contains(name.as_str()) => Some(name.clone()),
        _ => None,
    };
    match node {
        LoweringNode::Compare { operands, ops } => {
            for (index, op) in ops.iter().enumerate() {
                let (left, right) = (&operands[index], &operands[index + 1]);
                if op == "in" || op == "not in" {
                    if let (Some(field), LoweringNode::List(elements)) = (fixed_name(left), right) {
                        for element in elements {
                            lower_one(&field, element, definitions, chars, toks, spans, replacements)?;
                        }
                    }
                    continue;
                }
                if let Some(field) = fixed_name(left) {
                    lower_one(&field, right, definitions, chars, toks, spans, replacements)?;
                }
                if let Some(field) = fixed_name(right) {
                    lower_one(&field, left, definitions, chars, toks, spans, replacements)?;
                }
            }
            for operand in operands {
                collect_lowering(operand, fixed, definitions, chars, toks, spans, replacements)?;
            }
        }
        LoweringNode::List(children) | LoweringNode::Other(children) => {
            for child in children {
                collect_lowering(child, fixed, definitions, chars, toks, spans, replacements)?;
            }
        }
        LoweringNode::Name(_) | LoweringNode::Literal { .. } => {}
    }
    Ok(())
}

/// A `when` or `on error when` condition with its expression lowered; any other condition as is.
pub fn lower_condition(cond: &str, definitions: &BTreeMap<String, FieldDefinition>) -> Result<String, String> {
    let expr = if is_deterministic(cond) {
        expr_of(cond)
    } else if is_error(cond) && error_expr(cond).to_lowercase().starts_with("when ") {
        expr_of(&error_expr(cond))
    } else {
        return Ok(cond.to_string());
    };
    let low = expr.to_lowercase();
    if ALWAYS.contains(&low.as_str()) || NEVER.contains(&low.as_str()) {
        return Ok(cond.to_string());
    }
    let stripped = cond.trim_end();
    if !stripped.ends_with(expr.as_str()) {
        return Ok(cond.to_string());
    }
    let lowered = lower_expression(&expr, definitions)?;
    Ok(format!("{}{}", &stripped[..stripped.len() - expr.len()], lowered))
}

// ----------------------------------------------------------------- the policy rules
fn atom_problem(definition: &FieldDefinition, op: &str, constant: &Value) -> Option<String> {
    let name = &definition.name;
    let members: Vec<&Value> = match (op, constant) {
        ("in" | "not in", Value::List(elements)) => elements.iter().collect(),
        _ => vec![constant],
    };
    if (op == "in" || op == "not in") && members.iter().any(|member| matches!(member, Value::Null)) {
        return Some(format!("field {name:?}: None may not appear in a list"));
    }
    if op != "truthy" && matches!(constant, Value::Null) {
        if op != "==" && op != "!=" {
            return Some(format!("field {name:?}: None is compared only by == or !="));
        }
        if !definition.absent_allowed {
            return Some(format!("field {name:?}: compared with None, but its definition refuses absence"));
        }
        return None;
    }
    match definition.kind {
        DefinedKind::Bool => {
            if op == "truthy" || ((op == "==" || op == "!=") && matches!(constant, Value::Bool(_))) {
                return None;
            }
            return Some(format!("field {name:?}: a bool field is tested by truthiness or == and != with True or False"));
        }
        DefinedKind::Category => {
            if op == "truthy" || (matches!(op, "==" | "!=" | "in" | "not in") && members.iter().all(|member| matches!(member, Value::Str(_)))) {
                return None;
            }
            return Some(format!("field {name:?}: a category field is compared with strings by ==, !=, in and not in"));
        }
        DefinedKind::Int | DefinedKind::Fixed => {}
    }
    if op != "truthy" && !members.iter().all(|member| matches!(member, Value::Num(_))) {
        return Some(format!("field {name:?}: a field of this kind is compared only with numbers"));
    }
    if let (DefinedKind::Fixed, Some(rounding)) = (definition.kind, definition.rounding) {
        if !rounding.carries(op) {
            return Some(format!("field {name:?}: rounding={} does not carry {op:?}", rounding.word()));
        }
    }
    if op != "truthy" {
        for member in members {
            if let Value::Num(number) = member {
                if *number < definition.minimum as f64 || *number > definition.maximum as f64 {
                    return Some(format!("field {name:?}: the constant {number} is outside its range {} to {}", definition.minimum, definition.maximum));
                }
            }
        }
    }
    None
}

/// Every way the flow breaks the rules of SPEC section 4.5; empty when it obeys them.
pub fn policy_problems(graph: &Graph, definitions: &BTreeMap<String, FieldDefinition>) -> Vec<String> {
    let mut problems = Vec::new();
    let mut tested_for_absence: BTreeSet<String> = BTreeSet::new();
    let mut names: Vec<&String> = graph.nodes.keys().collect();
    names.sort();
    for name in names {
        for (_target, cond) in &graph.nodes[name].edges {
            if !is_deterministic(cond) || is_semantic(cond) {
                continue;
            }
            let (member, reason) = is_level_m(cond);
            if !member {
                problems.push(format!("{name}: {cond:?} is outside Level M ({})", reason.unwrap_or_default()));
                continue;
            }
            let Ok(atoms) = level_m_atoms(cond) else { continue };
            for atom in atoms {
                if ENGINE_COUNTERS.contains(&atom.field.as_str()) {
                    continue;
                }
                let Some(definition) = definitions.get(&atom.field) else {
                    problems.push(format!("{name}: {cond:?} reads {:?}, which the flow does not define", atom.field));
                    continue;
                };
                if let Some(problem) = atom_problem(definition, &atom.op, &atom.constant) {
                    problems.push(format!("{name}: {cond:?}: {problem}"));
                }
                if matches!(atom.constant, Value::Null) && (atom.op == "==" || atom.op == "!=") {
                    tested_for_absence.insert(atom.field.clone());
                }
            }
        }
    }
    for (field, definition) in definitions {
        if definition.absent_allowed && !tested_for_absence.contains(field) {
            problems.push(format!("field {field:?} allows absence but no edge tests it with == None or != None"));
        }
    }
    problems
}

/// Parse the flow's definitions, lower its conditions, and check the rules. A flow that breaks them
/// keeps the reason in `field_error` and has every edge disabled.
pub fn apply_definitions(graph: &mut Graph) {
    let outcome = definitions_of(&graph.meta).and_then(|definitions| {
        graph.fields = definitions.clone();
        if definitions.is_empty() {
            return Ok(());
        }
        let mut names: Vec<String> = graph.nodes.keys().cloned().collect();
        names.sort();
        for name in names {
            let node = graph.nodes.get_mut(&name).expect("a listed node");
            let mut lowered = Vec::with_capacity(node.edges.len());
            for (target, cond) in &node.edges {
                lowered.push((target.clone(), lower_condition(cond, &definitions)?));
            }
            node.edges = lowered;
        }
        let problems = policy_problems(graph, &definitions);
        if problems.is_empty() { Ok(()) } else { Err(format!("the flow breaks its field definitions: {}", problems.join("; "))) }
    });
    if let Err(reason) = outcome {
        graph.field_error = Some(reason);
        for node in graph.nodes.values_mut() {
            for edge in node.edges.iter_mut() {
                edge.1 = "never".to_string();
            }
        }
    }
}
