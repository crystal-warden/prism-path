// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The worker output contract, derived from the flow itself: a port of `prismpath/kernel/contract.py`.
//!
//! The deterministic edges say what a node's worker must emit: `when tests_pass` implies a boolean
//! `tests_pass`, `when action == "contain"` an `action` whose value space includes "contain". This module
//! walks the graph, reads each node's `when` predicates and extracts the per node schema, which the engine's
//! type gate (`RunOpts::type_gate`) then holds a worker's output to.
//!
//! Python reads the predicates with `ast.parse`, which accepts all of Python's expression syntax, so this
//! module has its own reader of that syntax (`PNode`) rather than the sandbox grammar of `condition.rs`:
//! the sandbox folds `-5` into a constant and refuses calls, attributes and arithmetic, and the contract
//! must see `-5` as the unary minus Python's tree holds (so `x == -5` types nothing) and must still read
//! the fields of `x > 3 and f(y)`. The reader covers Python's expression grammar except the `\N{name}`
//! string escape, a lone surrogate escape, comprehension and lambda bodies (read as one opaque value),
//! and NFKC normalisation of identifiers; a predicate it cannot read is skipped, as one Python cannot
//! parse is. Nesting past `MAX_NEST` is skipped too, where Python's own parser stops at 200 brackets.
//!
//! One refusal where Python has none: a literal that becomes a routed value must be exactly representable,
//! so an integer beyond plus or minus 2^53 minus 1 and a float with no finite double (`1e999`) make
//! `derive_contract` fail with a `ContractError` instead of becoming a rounded or infinite value.

use std::collections::HashMap;

use serde_json::json;

use crate::condition::{expr_of, is_deterministic, ALWAYS, NEVER, PY_KEYWORDS};
use crate::parser::{Graph, Node};
use crate::value::Value;

/// Names supplied by the engine, not the worker: excluded from the worker's output contract.
pub const ENGINE_FIELDS: [&str; 5] = ["visits", "error_count", "error", "error_type", "error_message"];

/// The largest integer every engine holds exactly, 2^53 minus 1.
const MAX_SAFE_INT: i64 = 9_007_199_254_740_991;

/// The deepest nesting of brackets, `not` and unary operators the reader follows.
pub const MAX_NEST: usize = 120;

/// A contract that cannot be derived exactly.
#[derive(Debug, Clone, PartialEq)]
pub struct ContractError(pub String);

impl std::fmt::Display for ContractError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.0)
    }
}
impl std::error::Error for ContractError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    Unknown,
    Boolean,
    Number,
    Enum,
}

impl FieldType {
    pub fn as_str(self) -> &'static str {
        match self {
            FieldType::Unknown => "unknown",
            FieldType::Boolean => "boolean",
            FieldType::Number => "number",
            FieldType::Enum => "enum",
        }
    }
}

/// A literal the flow routes on. Integers and floats are told apart because Python prints them differently.
#[derive(Debug, Clone, PartialEq)]
pub enum Lit {
    Int(i64),
    Float(f64),
    Str(String),
}

impl Lit {
    /// Python's `==` between two set members: an integer equals the float of the same value.
    fn py_eq(&self, other: &Lit) -> bool {
        match (self, other) {
            (Lit::Str(left), Lit::Str(right)) => left == right,
            (Lit::Str(_), _) | (_, Lit::Str(_)) => false,
            (left, right) => left.as_f64() == right.as_f64(),
        }
    }

    fn as_f64(&self) -> f64 {
        match self {
            Lit::Int(int_val) => *int_val as f64,
            Lit::Float(float_val) => *float_val,
            Lit::Str(_) => f64::NAN,
        }
    }

    /// The sort key Python uses, `(str(type(val)), val)`: floats, then ints, then strings.
    fn type_rank(&self) -> u8 {
        match self {
            Lit::Float(_) => 0,
            Lit::Int(_) => 1,
            Lit::Str(_) => 2,
        }
    }

    fn cmp_key(&self, other: &Lit) -> std::cmp::Ordering {
        self.type_rank().cmp(&other.type_rank()).then_with(|| match (self, other) {
            (Lit::Str(left), Lit::Str(right)) => left.cmp(right),
            (Lit::Int(left), Lit::Int(right)) => left.cmp(right),
            (left, right) => left.as_f64().partial_cmp(&right.as_f64()).unwrap_or(std::cmp::Ordering::Equal),
        })
    }

    /// Python `repr`.
    pub fn py_repr(&self) -> String {
        match self {
            Lit::Int(int_val) => int_val.to_string(),
            Lit::Float(float_val) => py_float_repr(*float_val),
            Lit::Str(str_val) => py_str_repr(str_val),
        }
    }

    /// Python `str`.
    fn py_str(&self) -> String {
        match self {
            Lit::Str(str_val) => str_val.clone(),
            other => other.py_repr(),
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Lit::Int(int_val) => json!(*int_val),
            Lit::Float(float_val) => serde_json::Number::from_f64(*float_val)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null),
            Lit::Str(str_val) => json!(str_val),
        }
    }
}

/// The inferred type of one worker output field, accumulated across a node's edges.
#[derive(Debug, Clone)]
pub struct FieldSpec {
    pub field_type: FieldType,
    /// The literals the flow routes on, in the order first seen (Python holds a set).
    values: Vec<Lit>,
    /// Compared with an ordering operator: a genuine number with no closed value set.
    ranged: bool,
    pub conflict: Option<String>,
}

impl FieldSpec {
    fn new() -> FieldSpec {
        FieldSpec { field_type: FieldType::Unknown, values: Vec::new(), ranged: false, conflict: None }
    }

    fn add(&mut self, field_type: FieldType, values: Vec<Lit>, ranged: bool) {
        for lit in values {
            if !self.values.iter().any(|seen| seen.py_eq(&lit)) {
                self.values.push(lit);
            }
        }
        if ranged {
            self.ranged = true;
        }
        if field_type == FieldType::Unknown {
            return;
        }
        if self.field_type == FieldType::Unknown {
            self.field_type = field_type;
        } else if self.field_type != field_type && self.conflict.is_none() {
            self.conflict = Some(format!("used as both {} and {}", self.field_type.as_str(), field_type.as_str()));
        }
    }

    /// The closed value set to expose, or `None` (booleans, ranged numbers, or no literals), sorted as Python sorts it.
    pub fn routed_values(&self) -> Option<Vec<Lit>> {
        if !matches!(self.field_type, FieldType::Enum | FieldType::Number) || self.ranged || self.values.is_empty() {
            return None;
        }
        let mut sorted = self.values.clone();
        sorted.sort_by(|left, right| left.cmp_key(right));
        Some(sorted)
    }

    pub fn to_json(&self) -> serde_json::Value {
        let mut map_obj = serde_json::Map::new();
        map_obj.insert("type".to_string(), json!(self.field_type.as_str()));
        if let Some(values) = self.routed_values() {
            map_obj.insert("values".to_string(), serde_json::Value::Array(values.iter().map(Lit::to_json).collect()));
        }
        if let Some(conflict) = &self.conflict {
            map_obj.insert("conflict".to_string(), json!(conflict));
        }
        serde_json::Value::Object(map_obj)
    }
}

/// The fields one node's worker must emit, in the order the node's edges first read them.
pub type NodeContract = Vec<(String, FieldSpec)>;

/// `{node: {field: spec}}` for a whole flow, nodes in document order.
#[derive(Debug, Clone, Default)]
pub struct Contract {
    order: Vec<String>,
    by_node: HashMap<String, NodeContract>,
}

impl Contract {
    pub fn get(&self, node: &str) -> Option<&NodeContract> {
        self.by_node.get(node)
    }

    pub fn nodes(&self) -> impl Iterator<Item = (&String, &NodeContract)> {
        self.order.iter().filter_map(|name| self.by_node.get(name).map(|contract| (name, contract)))
    }

    pub fn to_json(&self) -> serde_json::Value {
        let mut map_obj = serde_json::Map::new();
        for (name, node_contract) in self.nodes() {
            map_obj.insert(name.clone(), node_contract_to_json(node_contract));
        }
        serde_json::Value::Object(map_obj)
    }
}

pub fn node_contract_to_json(node_contract: &[(String, FieldSpec)]) -> serde_json::Value {
    let mut map_obj = serde_json::Map::new();
    for (field, spec) in node_contract {
        map_obj.insert(field.clone(), spec.to_json());
    }
    serde_json::Value::Object(map_obj)
}

// ----------------------------------------------------------------------------------------------
// Python's expression tree, as far as the contract reads it

#[derive(Debug, Clone, PartialEq)]
enum PConst {
    Bool(bool),
    None,
    Ellipsis,
    /// An integer literal; `None` when it does not fit an `i64`.
    Int(Option<i64>),
    Float(f64),
    Str(String),
    /// bytes and complex literals: a Constant that types nothing.
    Other,
}

impl PConst {
    fn type_of(&self) -> Option<FieldType> {
        match self {
            PConst::Bool(_) => Some(FieldType::Boolean),
            PConst::Int(_) | PConst::Float(_) => Some(FieldType::Number),
            PConst::Str(_) => Some(FieldType::Enum),
            _ => None,
        }
    }

    /// The routed value, refusing one that cannot be held exactly.
    fn lit(&self) -> Result<Option<Lit>, ContractError> {
        match self {
            PConst::Int(Some(int_val)) if int_val.abs() <= MAX_SAFE_INT => Ok(Some(Lit::Int(*int_val))),
            PConst::Int(_) => Err(ContractError(
                "an integer literal beyond plus or minus 2^53 minus 1 is refused, not rounded".to_string(),
            )),
            PConst::Float(float_val) if float_val.is_finite() => Ok(Some(Lit::Float(*float_val))),
            PConst::Float(_) => Err(ContractError("a float literal beyond the double range is refused, not read as infinity".to_string())),
            PConst::Str(str_val) => Ok(Some(Lit::Str(str_val.clone()))),
            _ => Ok(None),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum COp {
    Eq,
    NotEq,
    Lt,
    LtE,
    Gt,
    GtE,
    In,
    NotIn,
    Is,
    IsNot,
}

#[derive(Debug, Clone, PartialEq)]
enum PNode {
    Name(String),
    Const(PConst),
    BoolOp(Vec<PNode>),
    Not(Box<PNode>),
    Compare { left: Box<PNode>, ops: Vec<COp>, comps: Vec<PNode> },
    /// A list or tuple display.
    Seq(Vec<PNode>),
    /// Any other expression: a call, an attribute, arithmetic, a unary minus, a conditional, a lambda.
    Other,
}

#[derive(Debug, Clone, PartialEq)]
enum PTok {
    Name(String),
    Num(PConst),
    Str { text: String, bytes: bool, fstr: bool },
    Op(String),
}

/// A syntax error, which the contract answers by skipping the predicate.
struct Syn;

type Lexed<T> = Result<T, Syn>;

fn is_ident_start(ch: char) -> bool {
    ch.is_alphabetic() || ch == '_'
}

fn is_ident_char(ch: char) -> bool {
    ch.is_alphanumeric() || ch == '_'
}

fn lex(src: &str) -> Lexed<Vec<PTok>> {
    let chars: Vec<char> = src.chars().collect();
    let len = chars.len();
    let mut toks: Vec<PTok> = Vec::new();
    let mut pos = 0usize;
    let mut brackets = 0usize;
    while pos < len {
        let ch = chars[pos];
        match ch {
            ' ' | '\t' | '\u{c}' => {
                pos += 1;
                continue;
            }
            '\n' | '\r' if brackets > 0 => {
                pos += 1;
                continue;
            }
            '#' => break,
            _ => {}
        }
        if is_ident_start(ch) {
            let mut scan = pos + 1;
            while scan < len && is_ident_char(chars[scan]) {
                scan += 1;
            }
            let word: String = chars[pos..scan].iter().collect();
            if scan < len && (chars[scan] == '\'' || chars[scan] == '"') {
                let prefix = word.to_lowercase();
                if matches!(prefix.as_str(), "r" | "u" | "b" | "f" | "br" | "rb" | "fr" | "rf") {
                    let (tok, next) = lex_string(&chars, scan, prefix.contains('r'), prefix.contains('b'), prefix.contains('f'))?;
                    toks.push(tok);
                    pos = next;
                    continue;
                }
            }
            toks.push(PTok::Name(word));
            pos = scan;
            continue;
        }
        if ch.is_ascii_digit() || (ch == '.' && pos + 1 < len && chars[pos + 1].is_ascii_digit()) {
            let (konst, next) = lex_number(&chars, pos)?;
            toks.push(PTok::Num(konst));
            pos = next;
            continue;
        }
        if ch == '\'' || ch == '"' {
            let (tok, next) = lex_string(&chars, pos, false, false, false)?;
            toks.push(tok);
            pos = next;
            continue;
        }
        if chars[pos..].starts_with(&['.', '.', '.']) {
            toks.push(PTok::Op("...".to_string()));
            pos += 3;
            continue;
        }
        if pos + 1 < len {
            let two: String = chars[pos..pos + 2].iter().collect();
            if matches!(
                two.as_str(),
                "**" | "//" | "<<" | ">>" | "<=" | ">=" | "==" | "!=" | ":=" | "->" | "+=" | "-=" | "*=" | "/=" | "%=" | "&=" | "|=" | "^=" | "@="
            ) {
                toks.push(PTok::Op(two));
                pos += 2;
                continue;
            }
        }
        match ch {
            '(' | '[' | '{' => {
                brackets += 1;
                if brackets > 200 {
                    return Err(Syn);
                }
            }
            ')' | ']' | '}' => brackets = brackets.saturating_sub(1),
            '+' | '-' | '*' | '/' | '%' | '@' | '&' | '|' | '^' | '~' | '<' | '>' | ',' | ':' | '.' | ';' | '=' => {}
            _ => return Err(Syn),
        }
        toks.push(PTok::Op(ch.to_string()));
        pos += 1;
    }
    Ok(toks)
}

/// `[0-9]+(_[0-9]+)*` or the hex, octal and binary forms; returns the end of the digits.
fn scan_digits(chars: &[char], start: usize, radix: u32) -> Lexed<usize> {
    let mut scan = start;
    let mut prev_digit = false;
    while scan < chars.len() {
        let ch = chars[scan];
        if ch.is_digit(radix) && ch.is_ascii() {
            prev_digit = true;
        } else if ch == '_' {
            if !prev_digit {
                return Err(Syn);
            }
            prev_digit = false;
        } else {
            break;
        }
        scan += 1;
    }
    if scan > start && !prev_digit {
        return Err(Syn);
    }
    Ok(scan)
}

fn int_of(digits: &str, radix: u32) -> Option<i64> {
    let mut acc: i128 = 0;
    for ch in digits.chars().filter(|ch| *ch != '_') {
        acc = acc.checked_mul(radix as i128)?.checked_add(ch.to_digit(radix)? as i128)?;
        if acc > i64::MAX as i128 {
            return None;
        }
    }
    Some(acc as i64)
}

fn lex_number(chars: &[char], pos: usize) -> Lexed<(PConst, usize)> {
    let len = chars.len();
    let ch = chars[pos];
    if ch == '0' && pos + 1 < len && matches!(chars[pos + 1], 'x' | 'X' | 'o' | 'O' | 'b' | 'B') {
        let radix = match chars[pos + 1] {
            'x' | 'X' => 16,
            'o' | 'O' => 8,
            _ => 2,
        };
        let mut start = pos + 2;
        if start < len && chars[start] == '_' {
            start += 1;
        }
        let end = scan_digits(chars, start, radix)?;
        if end == start || (end < len && is_ident_char(chars[end])) {
            return Err(Syn);
        }
        let digits: String = chars[start..end].iter().collect();
        return Ok((PConst::Int(int_of(&digits, radix)), end));
    }
    let mut scan = pos;
    let int_end = scan_digits(chars, scan, 10)?;
    let mut is_float = false;
    scan = int_end;
    if scan < len && chars[scan] == '.' {
        is_float = true;
        scan += 1;
        scan = scan_digits(chars, scan, 10)?;
    }
    if scan < len && (chars[scan] == 'e' || chars[scan] == 'E') {
        let mut exp_scan = scan + 1;
        if exp_scan < len && (chars[exp_scan] == '+' || chars[exp_scan] == '-') {
            exp_scan += 1;
        }
        if exp_scan < len && chars[exp_scan].is_ascii_digit() {
            is_float = true;
            scan = scan_digits(chars, exp_scan, 10)?;
        }
    }
    let imaginary = scan < len && (chars[scan] == 'j' || chars[scan] == 'J');
    if imaginary {
        scan += 1;
    }
    if scan < len && is_ident_char(chars[scan]) {
        return Err(Syn);
    }
    let text: String = chars[pos..if imaginary { scan - 1 } else { scan }].iter().filter(|ch| **ch != '_').collect();
    if imaginary {
        return Ok((PConst::Other, scan));
    }
    if is_float {
        return Ok((PConst::Float(text.parse::<f64>().map_err(|_| Syn)?), scan));
    }
    // `0` followed by more digits is not a decimal integer unless every digit is zero
    if text.len() > 1 && text.starts_with('0') && text.chars().any(|digit| digit != '0') {
        return Err(Syn);
    }
    Ok((PConst::Int(int_of(&text, 10)), scan))
}

fn lex_string(chars: &[char], quote_pos: usize, raw: bool, bytes: bool, fstr: bool) -> Lexed<(PTok, usize)> {
    let len = chars.len();
    let quote = chars[quote_pos];
    let triple = quote_pos + 2 < len && chars[quote_pos + 1] == quote && chars[quote_pos + 2] == quote;
    let mut scan = quote_pos + if triple { 3 } else { 1 };
    let mut text = String::new();
    loop {
        if scan >= len {
            return Err(Syn);
        }
        let ch = chars[scan];
        if triple {
            if ch == quote && chars.get(scan + 1) == Some(&quote) && chars.get(scan + 2) == Some(&quote) {
                scan += 3;
                break;
            }
        } else if ch == quote {
            scan += 1;
            break;
        } else if ch == '\n' || ch == '\r' {
            return Err(Syn);
        }
        if ch == '\\' {
            if scan + 1 >= len {
                return Err(Syn);
            }
            let esc = chars[scan + 1];
            if raw {
                text.push('\\');
                text.push(esc);
                scan += 2;
                continue;
            }
            scan += 2;
            match esc {
                '\n' => {}
                '\r' => {
                    if chars.get(scan) == Some(&'\n') {
                        scan += 1;
                    }
                }
                '\\' | '\'' | '"' => text.push(esc),
                'a' => text.push('\u{7}'),
                'b' => text.push('\u{8}'),
                'f' => text.push('\u{c}'),
                'n' => text.push('\n'),
                'r' => text.push('\r'),
                't' => text.push('\t'),
                'v' => text.push('\u{b}'),
                '0'..='7' => {
                    let mut code = esc.to_digit(8).unwrap_or(0);
                    for _ in 0..2 {
                        match chars.get(scan).and_then(|digit| digit.to_digit(8)) {
                            Some(next_digit) => {
                                code = code * 8 + next_digit;
                                scan += 1;
                            }
                            None => break,
                        }
                    }
                    text.push(char::from_u32(code).ok_or(Syn)?);
                }
                'x' | 'u' | 'U' if !bytes || esc == 'x' => {
                    let width = match esc {
                        'x' => 2,
                        'u' => 4,
                        _ => 8,
                    };
                    let hex: String = chars.get(scan..scan + width).ok_or(Syn)?.iter().collect();
                    if !hex.chars().all(|digit| digit.is_ascii_hexdigit()) {
                        return Err(Syn);
                    }
                    let code = u32::from_str_radix(&hex, 16).map_err(|_| Syn)?;
                    text.push(char::from_u32(code).ok_or(Syn)?);
                    scan += width;
                }
                'N' if !bytes => return Err(Syn),
                other => {
                    text.push('\\');
                    text.push(other);
                }
            }
            continue;
        }
        text.push(ch);
        scan += 1;
    }
    Ok((PTok::Str { text, bytes, fstr }, scan))
}

struct Reader {
    toks: Vec<PTok>,
    pos: usize,
    nest: usize,
}

type Parsed = Result<PNode, Syn>;

impl Reader {
    fn peek(&self) -> Option<&PTok> {
        self.toks.get(self.pos)
    }

    fn peek_at(&self, offset: usize) -> Option<&PTok> {
        self.toks.get(self.pos + offset)
    }

    fn is_op(&self, op: &str) -> bool {
        matches!(self.peek(), Some(PTok::Op(found)) if found == op)
    }

    fn is_name(&self, word: &str) -> bool {
        matches!(self.peek(), Some(PTok::Name(found)) if found == word)
    }

    fn eat_op(&mut self, op: &str) -> bool {
        if self.is_op(op) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn eat_name(&mut self, word: &str) -> bool {
        if self.is_name(word) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect_op(&mut self, op: &str) -> Lexed<()> {
        if self.eat_op(op) {
            Ok(())
        } else {
            Err(Syn)
        }
    }

    fn guard(&mut self, inner: fn(&mut Reader) -> Parsed) -> Parsed {
        self.nest += 1;
        if self.nest > MAX_NEST {
            return Err(Syn);
        }
        let out = inner(self);
        self.nest -= 1;
        out
    }

    /// `star_expressions`: the whole predicate, a bare comma list being a tuple.
    fn star_expressions(&mut self) -> Parsed {
        let first = self.star_or_expression()?;
        if !self.is_op(",") {
            return Ok(first);
        }
        let mut elts = vec![first];
        while self.eat_op(",") {
            if self.at_end() {
                break;
            }
            elts.push(self.star_or_expression()?);
        }
        Ok(PNode::Seq(elts))
    }

    fn at_end(&self) -> bool {
        self.pos >= self.toks.len()
    }

    fn star_or_expression(&mut self) -> Parsed {
        if self.eat_op("*") {
            self.bitor()?;
            return Ok(PNode::Other);
        }
        self.expression()
    }

    fn expression(&mut self) -> Parsed {
        self.guard(Reader::expression_inner)
    }

    fn expression_inner(&mut self) -> Parsed {
        if self.eat_name("lambda") {
            // parameters up to the colon that is not inside brackets, then the body
            let mut level = 0usize;
            loop {
                match self.peek() {
                    None => return Err(Syn),
                    Some(PTok::Op(op)) if matches!(op.as_str(), "(" | "[" | "{") => level += 1,
                    Some(PTok::Op(op)) if matches!(op.as_str(), ")" | "]" | "}") => {
                        if level == 0 {
                            return Err(Syn);
                        }
                        level -= 1;
                    }
                    Some(PTok::Op(op)) if op == ":" && level == 0 => {
                        self.pos += 1;
                        break;
                    }
                    _ => {}
                }
                self.pos += 1;
            }
            self.expression()?;
            return Ok(PNode::Other);
        }
        let cond = self.disjunction()?;
        if self.eat_name("if") {
            self.disjunction()?;
            if !self.eat_name("else") {
                return Err(Syn);
            }
            self.expression()?;
            return Ok(PNode::Other);
        }
        Ok(cond)
    }

    fn disjunction(&mut self) -> Parsed {
        let first = self.conjunction()?;
        if !self.is_name("or") {
            return Ok(first);
        }
        let mut vals = vec![first];
        while self.eat_name("or") {
            vals.push(self.conjunction()?);
        }
        Ok(PNode::BoolOp(vals))
    }

    fn conjunction(&mut self) -> Parsed {
        let first = self.inversion()?;
        if !self.is_name("and") {
            return Ok(first);
        }
        let mut vals = vec![first];
        while self.eat_name("and") {
            vals.push(self.inversion()?);
        }
        Ok(PNode::BoolOp(vals))
    }

    fn inversion(&mut self) -> Parsed {
        if self.eat_name("not") {
            return Ok(PNode::Not(Box::new(self.guard(Reader::inversion)?)));
        }
        self.comparison()
    }

    fn compare_op(&mut self) -> Option<COp> {
        let op = match self.peek()? {
            PTok::Op(op) => match op.as_str() {
                "==" => COp::Eq,
                "!=" => COp::NotEq,
                "<" => COp::Lt,
                "<=" => COp::LtE,
                ">" => COp::Gt,
                ">=" => COp::GtE,
                _ => return None,
            },
            PTok::Name(word) => match word.as_str() {
                "in" => COp::In,
                "is" => {
                    if matches!(self.peek_at(1), Some(PTok::Name(next)) if next == "not") {
                        self.pos += 1;
                        COp::IsNot
                    } else {
                        COp::Is
                    }
                }
                "not" if matches!(self.peek_at(1), Some(PTok::Name(next)) if next == "in") => {
                    self.pos += 1;
                    COp::NotIn
                }
                _ => return None,
            },
            _ => return None,
        };
        self.pos += 1;
        Some(op)
    }

    fn comparison(&mut self) -> Parsed {
        let left = self.bitor()?;
        let mut ops = Vec::new();
        let mut comps = Vec::new();
        while let Some(op) = self.compare_op() {
            ops.push(op);
            comps.push(self.bitor()?);
        }
        if ops.is_empty() {
            return Ok(left);
        }
        Ok(PNode::Compare { left: Box::new(left), ops, comps })
    }

    /// One precedence level of the binary operators `| ^ & << >> + - * / // % @`; any operator makes the
    /// whole an opaque value.
    fn binary(&mut self, level: usize) -> Parsed {
        const LEVELS: [&[&str]; 6] = [&["|"], &["^"], &["&"], &["<<", ">>"], &["+", "-"], &["*", "/", "//", "%", "@"]];
        if level == LEVELS.len() {
            return self.factor();
        }
        let first = self.binary(level + 1)?;
        let mut combined = false;
        loop {
            let matched = matches!(self.peek(), Some(PTok::Op(op)) if LEVELS[level].contains(&op.as_str()));
            if !matched {
                break;
            }
            self.pos += 1;
            self.binary(level + 1)?;
            combined = true;
        }
        Ok(if combined { PNode::Other } else { first })
    }

    fn bitor(&mut self) -> Parsed {
        self.binary(0)
    }

    fn factor(&mut self) -> Parsed {
        if matches!(self.peek(), Some(PTok::Op(op)) if matches!(op.as_str(), "+" | "-" | "~")) {
            self.pos += 1;
            self.guard(Reader::factor)?;
            return Ok(PNode::Other);
        }
        let base = if self.eat_name("await") {
            self.primary()?;
            PNode::Other
        } else {
            self.primary()?
        };
        if self.eat_op("**") {
            self.guard(Reader::factor)?;
            return Ok(PNode::Other);
        }
        Ok(base)
    }

    fn primary(&mut self) -> Parsed {
        let mut node = self.atom()?;
        loop {
            if self.eat_op(".") {
                match self.peek() {
                    Some(PTok::Name(word)) if !PY_KEYWORDS.contains(&word.as_str()) => self.pos += 1,
                    _ => return Err(Syn),
                }
                node = PNode::Other;
            } else if self.eat_op("(") {
                self.call_args()?;
                node = PNode::Other;
            } else if self.eat_op("[") {
                self.slices()?;
                node = PNode::Other;
            } else {
                return Ok(node);
            }
        }
    }

    fn call_args(&mut self) -> Lexed<()> {
        loop {
            if self.eat_op(")") {
                return Ok(());
            }
            if self.eat_op("*") || self.eat_op("**") {
                self.bitor()?;
            } else if matches!(self.peek(), Some(PTok::Name(_))) && matches!(self.peek_at(1), Some(PTok::Op(op)) if op == "=") {
                self.pos += 2;
                self.expression()?;
            } else {
                self.named_or_star()?;
                if self.is_name("for") || self.is_name("async") {
                    self.skip_comprehension()?;
                }
            }
            if !self.eat_op(",") {
                return self.expect_op(")");
            }
        }
    }

    fn slices(&mut self) -> Lexed<()> {
        loop {
            // one slice: [expr] [: [expr] [: [expr]]]
            let starts_value = !self.is_op(":") && !self.is_op(",") && !self.is_op("]");
            if starts_value {
                self.named_or_star()?;
            }
            if self.eat_op(":") {
                if !self.is_op(":") && !self.is_op(",") && !self.is_op("]") {
                    self.expression()?;
                }
                if self.eat_op(":") && !self.is_op(",") && !self.is_op("]") {
                    self.expression()?;
                }
            } else if !starts_value {
                return Err(Syn);
            }
            if !self.eat_op(",") {
                return self.expect_op("]");
            }
            if self.eat_op("]") {
                return Ok(());
            }
        }
    }

    fn named_or_star(&mut self) -> Parsed {
        if self.eat_op("*") {
            self.bitor()?;
            return Ok(PNode::Other);
        }
        let node = self.expression()?;
        if matches!(node, PNode::Name(_)) && self.eat_op(":=") {
            self.expression()?;
            return Ok(PNode::Other);
        }
        Ok(node)
    }

    /// A comprehension's clauses, read as nothing: skip to the bracket that closes it.
    fn skip_comprehension(&mut self) -> Lexed<()> {
        let mut level = 0usize;
        loop {
            match self.peek() {
                None => return Err(Syn),
                Some(PTok::Op(op)) if matches!(op.as_str(), "(" | "[" | "{") => level += 1,
                Some(PTok::Op(op)) if matches!(op.as_str(), ")" | "]" | "}") => {
                    if level == 0 {
                        return Ok(());
                    }
                    level -= 1;
                }
                _ => {}
            }
            self.pos += 1;
        }
    }

    fn atom(&mut self) -> Parsed {
        let tok = self.peek().cloned().ok_or(Syn)?;
        match tok {
            PTok::Name(word) => {
                self.pos += 1;
                match word.as_str() {
                    "True" => Ok(PNode::Const(PConst::Bool(true))),
                    "False" => Ok(PNode::Const(PConst::Bool(false))),
                    "None" => Ok(PNode::Const(PConst::None)),
                    "and" | "or" | "not" | "in" | "lambda" | "await" => Err(Syn),
                    _ if PY_KEYWORDS.contains(&word.as_str()) => Err(Syn),
                    _ => Ok(PNode::Name(word)),
                }
            }
            PTok::Num(konst) => {
                self.pos += 1;
                Ok(PNode::Const(konst))
            }
            PTok::Str { .. } => self.strings(),
            PTok::Op(op) => match op.as_str() {
                "..." => {
                    self.pos += 1;
                    Ok(PNode::Const(PConst::Ellipsis))
                }
                "(" => {
                    self.pos += 1;
                    self.group()
                }
                "[" => {
                    self.pos += 1;
                    self.display("]", true)
                }
                "{" => {
                    self.pos += 1;
                    self.braces()
                }
                _ => Err(Syn),
            },
        }
    }

    /// Adjacent string literals are one constant.
    fn strings(&mut self) -> Parsed {
        let mut joined = String::new();
        let (mut any_bytes, mut any_text, mut any_f) = (false, false, false);
        while let Some(PTok::Str { text, bytes, fstr }) = self.peek() {
            joined.push_str(text);
            any_bytes |= *bytes;
            any_text |= !*bytes;
            any_f |= *fstr;
            self.pos += 1;
        }
        if any_bytes && any_text {
            return Err(Syn);
        }
        Ok(if any_f {
            PNode::Other
        } else if any_bytes {
            PNode::Const(PConst::Other)
        } else {
            PNode::Const(PConst::Str(joined))
        })
    }

    fn group(&mut self) -> Parsed {
        if self.eat_op(")") {
            return Ok(PNode::Seq(Vec::new()));
        }
        let first = self.named_or_star()?;
        if self.is_name("for") || self.is_name("async") {
            self.skip_comprehension()?;
            self.expect_op(")")?;
            return Ok(PNode::Other);
        }
        if self.is_op(",") {
            let mut elts = vec![first];
            while self.eat_op(",") {
                if self.is_op(")") {
                    break;
                }
                elts.push(self.named_or_star()?);
            }
            self.expect_op(")")?;
            return Ok(PNode::Seq(elts));
        }
        self.expect_op(")")?;
        Ok(first)
    }

    fn display(&mut self, close: &str, is_seq: bool) -> Parsed {
        let mut elts = Vec::new();
        loop {
            if self.eat_op(close) {
                return Ok(if is_seq { PNode::Seq(elts) } else { PNode::Other });
            }
            elts.push(self.named_or_star()?);
            if self.is_name("for") || self.is_name("async") {
                self.skip_comprehension()?;
                self.expect_op(close)?;
                return Ok(PNode::Other);
            }
            if !self.eat_op(",") {
                self.expect_op(close)?;
                return Ok(if is_seq { PNode::Seq(elts) } else { PNode::Other });
            }
        }
    }

    /// A dict or set display, opaque to the contract.
    fn braces(&mut self) -> Parsed {
        loop {
            if self.eat_op("}") {
                return Ok(PNode::Other);
            }
            if self.eat_op("**") {
                self.bitor()?;
            } else {
                self.named_or_star()?;
                if self.eat_op(":") {
                    self.expression()?;
                }
                if self.is_name("for") || self.is_name("async") {
                    self.skip_comprehension()?;
                    self.expect_op("}")?;
                    return Ok(PNode::Other);
                }
            }
            if !self.eat_op(",") {
                self.expect_op("}")?;
                return Ok(PNode::Other);
            }
        }
    }
}

/// `ast.parse(expr, mode="eval").body` as far as the contract reads it, or `None` for a predicate that
/// does not parse (Python raises `SyntaxError` or `ValueError` there and the contract skips it).
fn parse_python_expression(src: &str) -> Option<PNode> {
    let toks = lex(src).ok()?;
    let mut reader = Reader { toks, pos: 0, nest: 0 };
    let node = reader.star_expressions().ok()?;
    if reader.at_end() {
        Some(node)
    } else {
        None
    }
}

// ----------------------------------------------------------------------------------------------
// derivation

struct Fields {
    order: Vec<(String, FieldSpec)>,
    index: HashMap<String, usize>,
}

impl Fields {
    fn spec(&mut self, name: &str) -> &mut FieldSpec {
        let slot = match self.index.get(name) {
            Some(slot) => *slot,
            None => {
                self.order.push((name.to_string(), FieldSpec::new()));
                self.index.insert(name.to_string(), self.order.len() - 1);
                self.order.len() - 1
            }
        };
        &mut self.order[slot].1
    }
}

fn compare_fields(left: &PNode, ops: &[COp], comps: &[PNode], fields: &mut Fields) -> Result<(), ContractError> {
    let operands: Vec<&PNode> = std::iter::once(left).chain(comps.iter()).collect();
    for (index, op) in ops.iter().enumerate() {
        let (lhs, rhs) = (operands[index], operands[index + 1]);
        let (name, other) = match (lhs, rhs) {
            (PNode::Name(name), other) => (name, other),
            (other, PNode::Name(name)) => (name, other),
            _ => continue,
        };
        let spec = fields.spec(name);
        match op {
            COp::Lt | COp::LtE | COp::Gt | COp::GtE => spec.add(FieldType::Number, Vec::new(), true),
            COp::Eq | COp::NotEq => {
                let (lit_type, values) = match other {
                    PNode::Const(konst) => match konst.type_of() {
                        Some(kind @ (FieldType::Enum | FieldType::Number)) => {
                            (Some(kind), konst.lit()?.into_iter().collect())
                        }
                        kind => (kind, Vec::new()),
                    },
                    _ => (None, Vec::new()),
                };
                spec.add(lit_type.unwrap_or(FieldType::Unknown), values, false);
            }
            COp::In | COp::NotIn => {
                if let PNode::Seq(elts) = other {
                    let consts: Vec<&PConst> = elts.iter().filter_map(|elt| if let PNode::Const(konst) = elt { Some(konst) } else { None }).collect();
                    let all_const = consts.len() == elts.len();
                    let mut kinds: Vec<Option<FieldType>> = Vec::new();
                    for konst in &consts {
                        if !kinds.contains(&konst.type_of()) {
                            kinds.push(konst.type_of());
                        }
                    }
                    if !all_const || consts.is_empty() || kinds.len() != 1 {
                        spec.add(FieldType::Unknown, Vec::new(), false);
                    } else {
                        match kinds[0] {
                            Some(kind @ (FieldType::Enum | FieldType::Number)) => {
                                let mut lits = Vec::new();
                                for konst in &consts {
                                    lits.extend(konst.lit()?);
                                }
                                spec.add(kind, lits, false);
                            }
                            Some(FieldType::Boolean) => spec.add(FieldType::Boolean, Vec::new(), false),
                            _ => {}
                        }
                    }
                }
            }
            COp::Is | COp::IsNot => {}
        }
    }
    Ok(())
}

/// Populate `fields` from one predicate tree. `bool_ctx` marks the positions where a bare name is used
/// as a boolean: a `BoolOp` or `not` operand, or the whole predicate.
fn walk(node: &PNode, fields: &mut Fields, bool_ctx: bool) -> Result<(), ContractError> {
    match node {
        PNode::BoolOp(vals) => {
            for val in vals {
                walk(val, fields, true)?;
            }
        }
        PNode::Not(operand) => walk(operand, fields, true)?,
        PNode::Compare { left, ops, comps } => compare_fields(left, ops, comps, fields)?,
        PNode::Name(name) if bool_ctx => fields.spec(name).add(FieldType::Boolean, Vec::new(), false),
        _ => {}
    }
    Ok(())
}

fn node_contract(node: &Node) -> Result<NodeContract, ContractError> {
    let mut fields = Fields { order: Vec::new(), index: HashMap::new() };
    for (_target, condition) in &node.edges {
        if !is_deterministic(condition) {
            continue;
        }
        let expr = expr_of(condition);
        let low = expr.to_lowercase();
        if ALWAYS.contains(&low.as_str()) || NEVER.contains(&low.as_str()) {
            continue;
        }
        let Some(tree) = parse_python_expression(&expr) else { continue };
        walk(&tree, &mut fields, true)?;
    }
    Ok(fields.order.into_iter().filter(|(name, _)| !ENGINE_FIELDS.contains(&name.as_str())).collect())
}

/// `{node: {field: spec}}`: the output fields each node's worker must emit for its deterministic edges to
/// route, with inferred types. A node whose out-edges are all semantic, error or event has an empty contract.
pub fn derive_contract(graph: &Graph) -> Result<Contract, ContractError> {
    let mut out = Contract::default();
    for name in &graph.order {
        let Some(node) = graph.nodes.get(name) else { continue };
        let derived = node_contract(node).map_err(|error| ContractError(format!("node {name:?}: {error}")))?;
        out.order.push(name.clone());
        out.by_node.insert(name.clone(), derived);
    }
    Ok(out)
}

/// A JSON Schema for the node's worker output: the constrained decoding grammar an LLM worker can be
/// forced to obey. Every derived field is `required`.
pub fn to_json_schema(node_contract: &[(String, FieldSpec)]) -> serde_json::Value {
    let mut props = serde_json::Map::new();
    for (field, spec) in node_contract {
        let json_type = match spec.field_type {
            FieldType::Boolean => "boolean",
            FieldType::Number => "number",
            FieldType::Enum | FieldType::Unknown => "string",
        };
        let mut prop = serde_json::Map::new();
        prop.insert("type".to_string(), json!(json_type));
        if let Some(values) = spec.routed_values() {
            prop.insert("enum".to_string(), serde_json::Value::Array(values.iter().map(Lit::to_json).collect()));
        }
        props.insert(field.clone(), serde_json::Value::Object(prop));
    }
    let mut required: Vec<&String> = node_contract.iter().map(|(field, _)| field).collect();
    required.sort();
    json!({"type": "object", "properties": props, "required": required})
}

fn type_ok(spec_type: FieldType, value: &Value) -> bool {
    if matches!(value, Value::Null) {
        return true;
    }
    match spec_type {
        FieldType::Boolean => matches!(value, Value::Bool(_)),
        FieldType::Number => matches!(value, Value::Num(_)),
        FieldType::Enum => matches!(value, Value::Str(_)),
        FieldType::Unknown => true,
    }
}

/// Type gate: the problems where an emitted field's value contradicts the derived contract. A missing
/// contract field is a soft `missing:` note, an unrouted value a `note:`, and a present field of the wrong
/// type a hard `type:` problem, which is the only kind the engine stops on.
pub fn validate_output(node_contract: &[(String, FieldSpec)], fields: &[(String, Value)]) -> Vec<String> {
    let mut problems = Vec::new();
    for (field, spec) in node_contract {
        let Some(value) = Value::obj_get(fields, field) else {
            problems.push(format!("missing: worker did not emit {} (read by a `when` edge)", py_str_repr(field)));
            continue;
        };
        if !type_ok(spec.field_type, value) {
            problems.push(format!(
                "type: {} should be {} but worker emitted {} ({})",
                py_str_repr(field),
                spec.field_type.as_str(),
                py_type_name(value),
                py_value_repr(value)
            ));
        } else if let Some(routed) = spec.routed_values() {
            let hit = match spec.field_type {
                FieldType::Enum => {
                    let shown = match value {
                        Value::Str(text) => text.clone(),
                        other => py_value_repr(other),
                    };
                    routed.iter().any(|lit| lit.py_eq(&Lit::Str(shown.clone())))
                }
                _ => match value {
                    Value::Num(num) => routed.iter().any(|lit| !matches!(lit, Lit::Str(_)) && lit.as_f64() == *num),
                    _ => false,
                },
            };
            if !hit {
                let listed: Vec<String> = routed.iter().map(Lit::py_repr).collect();
                problems.push(format!(
                    "note: {}={} is not one of the routed values [{}] (will fall through the deterministic tier)",
                    py_str_repr(field),
                    py_value_repr(value),
                    listed.join(", ")
                ));
            }
        }
    }
    problems
}

/// The field names a node declares its worker emits, via `@emits(field, field2=type, ...)`, or `None` when the
/// node has no `@emits` (declarations are opt-in).
pub fn declared_emits(node: &Node) -> Option<Vec<String>> {
    node.annotations.get("emits").map(|args| {
        let mut names: Vec<String> = args.keys().cloned().collect();
        names.sort();
        names
    })
}

/// Human readable rendering for `prismpath contract`.
pub fn describe(contract: &Contract) -> String {
    let mut names: Vec<&String> = contract.order.iter().collect();
    names.sort();
    let mut lines: Vec<String> = Vec::new();
    for name in names {
        let Some(fields) = contract.by_node.get(name) else { continue };
        if fields.is_empty() {
            continue;
        }
        lines.push(format!("## {name}"));
        let mut sorted: Vec<&(String, FieldSpec)> = fields.iter().collect();
        sorted.sort_by(|left, right| left.0.cmp(&right.0));
        for (field_name, spec) in sorted {
            let mut shown = spec.field_type.as_str().to_string();
            if let Some(values) = spec.routed_values() {
                let listed: Vec<String> = values.iter().map(Lit::py_str).collect();
                shown = format!("{shown}{{{}}}", listed.join(", "));
            }
            let flag = spec.conflict.as_ref().map(|text| format!("   \u{26a0} {text}")).unwrap_or_default();
            lines.push(format!("    {field_name}: {shown}{flag}"));
        }
    }
    if lines.is_empty() {
        "(no deterministic edges - nothing to constrain)".to_string()
    } else {
        lines.join("\n")
    }
}

// ----------------------------------------------------------------------------------------------
// Python's repr, for the messages

/// `type(val).__name__`. A JSON number has no integer or float distinction here, so an integral value is
/// `int`, as a worker's `5` is; a worker's `5.0` is told as `int (5)`, the one place this differs.
pub fn py_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Num(num) if num.is_finite() && num.fract() == 0.0 && num.abs() < 9.2e18 => "int",
        Value::Num(_) => "float",
        Value::Str(_) => "str",
        Value::List(_) => "list",
        Value::Obj(_) => "dict",
        Value::Ellipsis => "ellipsis",
    }
}

/// Python `repr` of a JSON value.
pub fn py_value_repr(value: &Value) -> String {
    match value {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Num(num) if num.is_finite() && num.fract() == 0.0 && num.abs() < 1e16 => format!("{}", *num as i64),
        Value::Num(num) => py_float_repr(*num),
        Value::Str(text) => py_str_repr(text),
        Value::List(items) => format!("[{}]", items.iter().map(py_value_repr).collect::<Vec<_>>().join(", ")),
        Value::Obj(entries) => format!(
            "{{{}}}",
            entries.iter().map(|(key, item)| format!("{}: {}", py_str_repr(key), py_value_repr(item))).collect::<Vec<_>>().join(", ")
        ),
        Value::Ellipsis => "Ellipsis".to_string(),
    }
}

/// Python `repr(float)`: the shortest digits that round trip, in fixed form between 1e-4 and 1e16.
pub fn py_float_repr(num: f64) -> String {
    if num.is_nan() {
        return "nan".to_string();
    }
    if num.is_infinite() {
        return if num > 0.0 { "inf" } else { "-inf" }.to_string();
    }
    if num == 0.0 {
        return if num.is_sign_negative() { "-0.0" } else { "0.0" }.to_string();
    }
    let sign = if num < 0.0 { "-" } else { "" };
    let sci = format!("{:e}", num.abs());
    let (mantissa, exp_text) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp_text.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(|ch| *ch != '.').collect();
    let point = exp + 1;
    if (-4..16).contains(&exp) {
        if point <= 0 {
            format!("{sign}0.{}{digits}", "0".repeat((-point) as usize))
        } else if point as usize >= digits.len() {
            format!("{sign}{digits}{}.0", "0".repeat(point as usize - digits.len()))
        } else {
            format!("{sign}{}.{}", &digits[..point as usize], &digits[point as usize..])
        }
    } else {
        let head = if digits.len() > 1 { format!("{}.{}", &digits[..1], &digits[1..]) } else { digits.clone() };
        format!("{sign}{head}e{}{:02}", if exp < 0 { "-" } else { "+" }, exp.abs())
    }
}

/// Whether Python's `str.isprintable` holds for a character. Exact for ASCII and for the control, space,
/// format and private use characters listed; a character Unicode leaves unassigned is taken as printable.
fn py_printable(ch: char) -> bool {
    if ch.is_ascii() {
        return (' '..='~').contains(&ch);
    }
    if ch.is_control() {
        return false;
    }
    !matches!(ch,
        '\u{a0}' | '\u{ad}' | '\u{600}'..='\u{605}' | '\u{61c}' | '\u{6dd}' | '\u{70f}' | '\u{890}'..='\u{891}' | '\u{8e2}'
        | '\u{1680}' | '\u{180e}' | '\u{2000}'..='\u{200f}' | '\u{2028}'..='\u{202f}' | '\u{205f}'..='\u{206f}'
        | '\u{3000}' | '\u{e000}'..='\u{f8ff}' | '\u{fdd0}'..='\u{fdef}' | '\u{feff}' | '\u{fff9}'..='\u{fffb}'
        | '\u{fffe}' | '\u{ffff}' | '\u{110bd}' | '\u{110cd}' | '\u{13430}'..='\u{1343f}' | '\u{1bca0}'..='\u{1bca3}'
        | '\u{1d173}'..='\u{1d17a}' | '\u{e0001}' | '\u{e0020}'..='\u{e007f}' | '\u{f0000}'..='\u{ffffd}'
        | '\u{100000}'..='\u{10fffd}')
}

/// Python `repr(str)`: single quotes unless the text holds a single quote and no double quote.
pub fn py_str_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') { '"' } else { '\'' };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch == quote => {
                out.push('\\');
                out.push(ch);
            }
            ch if py_printable(ch) => out.push(ch),
            ch => {
                let code = ch as u32;
                if code < 0x100 {
                    out.push_str(&format!("\\x{code:02x}"));
                } else if code < 0x10000 {
                    out.push_str(&format!("\\u{code:04x}"));
                } else {
                    out.push_str(&format!("\\U{code:08x}"));
                }
            }
        }
    }
    out.push(quote);
    out
}
