// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Condition classification and predicate evaluation.

use std::collections::HashMap;

use crate::value::{perr, PredicateError, Value, CMP_DEPTH, MAX_DEPTH};

// Three DIFFERENT whitespace vocabularies are in play, and conflating them changes routing:
//   * the tokenizer skips exactly " \t\n\r";
//   * JS \s / String.trim(): what the flow-document regexes use;
//   * Python str.strip(): JS \s PLUS \x85 \x1c-\x1f: what classifies conditions.

/// JS \s (the regex class, which String.trim also uses).
pub(crate) fn is_js_ws(ch: char) -> bool {
    matches!(ch,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}'
        | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}'
        | '\u{3000}' | '\u{feff}')
}

pub(crate) fn js_trim(text: &str) -> &str {
    text.trim_matches(is_js_ws)
}

/// Python str.strip() whitespace: wider than JS trim (for example U+0085 NEL). The tier a condition
/// lands in must be identical across engines, so classification uses THIS, never str::trim.
fn is_py_ws(ch: char) -> bool {
    is_js_ws(ch) || matches!(ch, '\u{85}' | '\u{1c}' | '\u{1d}' | '\u{1e}' | '\u{1f}')
}

pub fn py_trim(text: &str) -> &str {
    text.trim_matches(is_py_ws)
}

/// Python str.splitlines() boundaries. A bare split('\n') hides edges behind \r or NEL:
/// a CR-only or U+2028 document must parse to the same node/edge sets on every engine.
pub(crate) fn split_lines_py(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let text_chars: Vec<(usize, char)> = text.char_indices().collect();
    let mut start_pos = 0usize;
    let mut pos = 0usize;
    while pos < text_chars.len() {
        let (char_idx, ch) = text_chars[pos];
        let is_break = matches!(ch,
            '\n' | '\r' | '\u{b}' | '\u{c}' | '\u{1c}' | '\u{1d}' | '\u{1e}' | '\u{85}'
            | '\u{2028}' | '\u{2029}');
        if is_break {
            out.push(&text[start_pos..char_idx]);
            // \r\n is one boundary, not two
            if ch == '\r' && pos + 1 < text_chars.len() && text_chars[pos + 1].1 == '\n' {
                pos += 1;
            }
            start_pos = if pos + 1 < text_chars.len() { text_chars[pos + 1].0 } else { text.len() };
        }
        pos += 1;
    }
    out.push(&text[start_pos..]);
    out
}

const ALWAYS: [&str; 6] = ["always", "true", "else", "otherwise", "default", "_"];
const NEVER: [&str; 2] = ["false", "never"];

// Python HARD keywords (minus True/False/None, which are constants, and and/or/not/in, which are
// operators here). Python's ast.parse REJECTS these as names: when class == "phish" is a
// PredicateError there, so it must be one here too, or the edge routes differently across engines.
// Soft keywords (match/case/type) are ordinary Names in both.
const PY_KEYWORDS: [&str; 28] = [
    "as", "assert", "async", "await", "break", "class", "continue", "def", "del", "elif", "else",
    "except", "finally", "for", "from", "global", "if", "import", "is", "lambda", "nonlocal",
    "pass", "raise", "return", "try", "while", "with", "yield",
];

pub fn is_deterministic(condition: &str) -> bool {
    let cond_text = py_trim(condition).to_lowercase();
    cond_text.starts_with("when ") || ALWAYS.contains(&cond_text.as_str()) || NEVER.contains(&cond_text.as_str())
}

pub fn is_error(condition: &str) -> bool {
    py_trim(condition).to_lowercase().starts_with("on error")
}

pub fn is_event(condition: &str) -> bool {
    let cond_text = py_trim(condition).to_lowercase();
    cond_text.starts_with("on event") || cond_text.starts_with("on timeout")
}

pub fn is_catchall(condition: &str) -> bool {
    let cond_text = py_trim(condition);
    let expr = if cond_text.to_lowercase().starts_with("when ") {
        py_trim(&cond_text[5..])
    } else {
        cond_text
    };
    ALWAYS.contains(&expr.to_lowercase().as_str())
}

pub fn event_name(condition: &str) -> String {
    let cond_text = py_trim(condition);
    if cond_text.to_lowercase().starts_with("on timeout") {
        return "__timeout__".to_string();
    }
    let tail: String = cond_text.chars().skip("on event".chars().count()).collect();
    py_trim(&tail).to_string()
}

pub fn is_semantic(condition: &str) -> bool {
    !is_deterministic(condition) && !is_error(condition) && !is_event(condition)
}

pub fn error_expr(condition: &str) -> String {
    let cond_text = py_trim(condition);
    let tail: String = cond_text.chars().skip("on error".chars().count()).collect();
    py_trim(&tail).to_string()
}

/// The expression under a condition: when X -> X (sliced from the CASE-PRESERVED text: only
/// the prefix test is case-folded), anything else verbatim.
pub(crate) fn expr_of(condition: &str) -> String {
    let cond_text = py_trim(condition);
    if cond_text.to_lowercase().starts_with("when ") {
        let tail: String = cond_text.chars().skip(5).collect();
        py_trim(&tail).to_string()
    } else {
        cond_text.to_string()
    }
}

// Expression parsing
// Grammar (the Python ast subset the sandbox allows):
//   expr    := or ;  or := and ("or" and)* ;  and := not ("and" not)*
//   not     := "not" not | cmp
//   cmp     := operand ((==|!=|<|<=|>|>=|in|not in) operand)*
//   operand := number | string | True | False | None | name | "[" args "]" | "(" tuple-or-group ")"
// No calls, attributes, subscripts, arithmetic, or unary minus: anything else throws.

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Name(String),
    Num(f64, bool), // value, is_float: the flag lets -<int> fold while -<float> stays rejected
    Str(String),
    Ellipsis,
    Op(String),
}

fn tokenize(src: &str) -> Result<Vec<Tok>, PredicateError> {
    let chars: Vec<char> = src.chars().collect();
    let len = chars.len();
    let mut toks = Vec::new();
    let mut pos = 0usize;

    while pos < len {
        let ch = chars[pos];
        // the tokenizer's own whitespace is EXACTLY " \t\n\r": narrower than either trim set
        if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
            pos += 1;
            continue;
        }
        if ch.is_ascii_alphabetic() || ch == '_' {
            // raw-string prefix: r'...' / R"..." is a plain Constant in Python (no escape processing)
            if (ch == 'r' || ch == 'R') && pos + 1 < len && (chars[pos + 1] == '\'' || chars[pos + 1] == '"') {
                let quote = chars[pos + 1];
                let mut scan = pos + 2;
                let mut out = String::new();
                while scan < len && chars[scan] != quote {
                    out.push(chars[scan]);
                    scan += 1;
                }
                if scan >= len {
                    return perr("unterminated string in predicate");
                }
                toks.push(Tok::Str(out));
                pos = scan + 1;
                continue;
            }
            if (ch == 'b' || ch == 'B') && pos + 1 < len && (chars[pos + 1] == '\'' || chars[pos + 1] == '"') {
                return perr("bytes literals are not supported in predicates");
            }
            let mut scan = pos + 1;
            while scan < len && (chars[scan].is_ascii_alphanumeric() || chars[scan] == '_') {
                scan += 1;
            }
            toks.push(Tok::Name(chars[pos..scan].iter().collect()));
            pos = scan;
            continue;
        }
        if ch.is_ascii_digit() || (ch == '.' && pos + 1 < len && chars[pos + 1].is_ascii_digit()) {
            // Python numeric literal spellings: 0x/0o/0b radixes and _ separators are legal; a
            // trailing j (complex) is a hard reject on both sides for parity's sake.
            let radix2: String = chars[pos..(pos + 2).min(len)].iter().collect::<String>().to_lowercase();
            if ch == '0' && (radix2 == "0x" || radix2 == "0o" || radix2 == "0b") {
                let mut scan = pos + 2;
                let digit_ok: fn(char) -> bool = match radix2.as_str() {
                    "0x" => |c_val| c_val.is_ascii_hexdigit() || c_val == '_',
                    "0o" => |c_val| ('0'..='7').contains(&c_val) || c_val == '_',
                    _ => |c_val| c_val == '0' || c_val == '1' || c_val == '_',
                };
                while scan < len && digit_ok(chars[scan]) {
                    scan += 1;
                }
                let body: String = chars[pos + 2..scan].iter().filter(|c_val| **c_val != '_').collect();
                if body.is_empty() {
                    return perr("malformed numeric literal in predicate");
                }
                let radix = match radix2.as_str() { "0x" => 16, "0o" => 8, _ => 2 };
                // accumulate in f64: the same rounding parseInt's result carries downstream
                let mut val = 0f64;
                for c_val in body.chars() {
                    val = val * radix as f64 + c_val.to_digit(radix).expect("digit valid for radix") as f64;
                }
                toks.push(Tok::Num(val, false)); // radix literal: always integer
                pos = scan;
                continue;
            }
            let mut scan = pos;
            while scan < len && (chars[scan].is_ascii_digit() || chars[scan] == '_') {
                scan += 1;
            }
            if scan < len && chars[scan] == '.' {
                scan += 1;
                while scan < len && (chars[scan].is_ascii_digit() || chars[scan] == '_') {
                    scan += 1;
                }
            }
            if scan < len && (chars[scan] == 'e' || chars[scan] == 'E') {
                let mut exp_scan = scan + 1;
                if exp_scan < len && (chars[exp_scan] == '+' || chars[exp_scan] == '-') {
                    exp_scan += 1;
                }
                if exp_scan < len && chars[exp_scan].is_ascii_digit() {
                    exp_scan += 1;
                    while exp_scan < len && (chars[exp_scan].is_ascii_digit() || chars[exp_scan] == '_') {
                        exp_scan += 1;
                    }
                    scan = exp_scan;
                }
            }
            if scan < len && (chars[scan] == 'j' || chars[scan] == 'J') {
                return perr("complex literals are not supported in predicates");
            }
            let text: String = chars[pos..scan].iter().filter(|c_val| **c_val != '_').collect();
            // JS Number() and Rust f64 parsing are both correctly rounded; "1." parses as 1
            let val = text.parse::<f64>().unwrap_or(f64::NAN);
            let is_float = text.contains('.') || text.contains('e') || text.contains('E');
            toks.push(Tok::Num(val, is_float));
            pos = scan;
            continue;
        }
        if ch == '"' || ch == '\'' {
            let mut scan = pos + 1;
            let mut out = String::new();
            while scan < len && chars[scan] != ch {
                if chars[scan] == '\\' && scan + 1 < len {
                    let esc = chars[scan + 1];
                    // Python's escape table; an UNKNOWN escape keeps the backslash (Python
                    // semantics), it is not silently dropped.
                    match esc {
                        'n' => out.push('\n'),
                        't' => out.push('\t'),
                        'r' => out.push('\r'),
                        '0' => out.push('\0'),
                        'a' => out.push('\u{7}'),
                        'b' => out.push('\u{8}'),
                        'f' => out.push('\u{c}'),
                        'v' => out.push('\u{b}'),
                        '\\' | '\'' | '"' => out.push(esc),
                        'x' if scan + 3 < len
                            && chars[scan + 2].is_ascii_hexdigit()
                            && chars[scan + 3].is_ascii_hexdigit() =>
                        {
                            let code: String = chars[scan + 2..scan + 4].iter().collect();
                            let val_code = u32::from_str_radix(&code, 16).expect("two guarded hex digits");
                            out.push(char::from_u32(val_code).unwrap_or('\u{fffd}'));
                            scan += 2;
                        }
                        'u' if scan + 5 < len && chars[scan + 2..scan + 6].iter().all(|c_val| c_val.is_ascii_hexdigit()) => {
                            let code: String = chars[scan + 2..scan + 6].iter().collect();
                            let val_code = u32::from_str_radix(&code, 16).expect("four guarded hex digits");
                            out.push(char::from_u32(val_code).unwrap_or('\u{fffd}'));
                            scan += 4;
                        }
                        _ => {
                            out.push('\\');
                            out.push(esc);
                        }
                    }
                    scan += 2;
                } else {
                    out.push(chars[scan]);
                    scan += 1;
                }
            }
            if scan >= len {
                return perr("unterminated string in predicate");
            }
            toks.push(Tok::Str(out));
            pos = scan + 1;
            continue;
        }
        if pos + 3 <= len && chars[pos..pos + 3] == ['.', '.', '.'] {
            toks.push(Tok::Ellipsis);
            pos += 3;
            continue;
        }
        if pos + 2 <= len {
            let two: String = chars[pos..pos + 2].iter().collect();
            if two == "==" || two == "!=" || two == "<=" || two == ">=" {
                toks.push(Tok::Op(two));
                pos += 2;
                continue;
            }
        }
        if "<>[](),".contains(ch) {
            toks.push(Tok::Op(ch.to_string()));
            pos += 1;
            continue;
        }
        if ch == '-' || ch == '+' {
            toks.push(Tok::Op(ch.to_string())); // sign; folded onto an int literal in operand()
            pos += 1;
            continue;
        }
        let near: String = chars[pos..(pos + 8).min(len)].iter().collect();
        return perr(format!("predicate uses disallowed syntax near {near:?}"));
    }
    Ok(toks)
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Ast {
    // is_float (2nd field) is carried only for the proof layer: the Level M i32 fragment excludes
    // float literals, and Value::Num(f64) alone cannot tell 1 from 1.0.
    Const(Value, bool),
    Name(String),
    And(Vec<Ast>),
    Or(Vec<Ast>),
    Not(Box<Ast>),
    List(Vec<Ast>),
    Cmp { left: Box<Ast>, ops: Vec<String>, rights: Vec<Ast> },
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn next_tok(&mut self) -> Option<Tok> {
        let tok = self.toks.get(self.pos).cloned();
        if tok.is_some() {
            self.pos += 1;
        }
        tok
    }
    fn peek_op(&self, expected_op: &str) -> bool {
        matches!(self.peek(), Some(Tok::Op(op)) if op == expected_op)
    }
    fn peek_name(&self, expected_name: &str) -> bool {
        matches!(self.peek(), Some(Tok::Name(nm)) if nm == expected_name)
    }
    fn expect(&mut self, expected_op: &str) -> Result<(), PredicateError> {
        match self.next_tok() {
            Some(Tok::Op(op)) if op == expected_op => Ok(()),
            _ => perr(format!("expected {expected_op:?} in predicate")),
        }
    }

    fn or_expr(&mut self, depth: usize) -> Result<Ast, PredicateError> {
        if depth > MAX_DEPTH {
            return perr("predicate nested too deeply");
        }
        let mut vals = vec![self.and_expr(depth)?];
        while self.peek_name("or") {
            self.next_tok();
            vals.push(self.and_expr(depth + 1)?);
        }
        Ok(if vals.len() == 1 { vals.pop().expect("len == 1") } else { Ast::Or(vals) })
    }

    fn and_expr(&mut self, depth: usize) -> Result<Ast, PredicateError> {
        if depth > MAX_DEPTH {
            return perr("predicate nested too deeply");
        }
        let mut vals = vec![self.not_expr(depth)?];
        while self.peek_name("and") {
            self.next_tok();
            vals.push(self.not_expr(depth + 1)?);
        }
        Ok(if vals.len() == 1 { vals.pop().expect("len == 1") } else { Ast::And(vals) })
    }

    fn not_expr(&mut self, depth: usize) -> Result<Ast, PredicateError> {
        if depth > MAX_DEPTH {
            return perr("predicate nested too deeply");
        }
        if self.peek_name("not") {
            self.next_tok();
            return Ok(Ast::Not(Box::new(self.not_expr(depth + 1)?)));
        }
        self.cmp_expr(depth)
    }

    fn cmp_op(&mut self) -> Result<Option<String>, PredicateError> {
        match self.peek() {
            Some(Tok::Op(op)) if ["==", "!=", "<", "<=", ">", ">="].contains(&op.as_str()) => {
                let op_str = op.clone();
                self.next_tok();
                Ok(Some(op_str))
            }
            Some(Tok::Name(nm)) if nm == "in" => {
                self.next_tok();
                Ok(Some("in".to_string()))
            }
            Some(Tok::Name(nm)) if nm == "not" => {
                self.next_tok();
                match self.next_tok() {
                    Some(Tok::Name(nx)) if nx == "in" => Ok(Some("not in".to_string())),
                    _ => perr("expected `in` after `not`"),
                }
            }
            _ => Ok(None),
        }
    }

    fn cmp_expr(&mut self, depth: usize) -> Result<Ast, PredicateError> {
        if depth > MAX_DEPTH {
            return perr("predicate nested too deeply");
        }
        let left = self.operand(depth)?;
        let mut ops = Vec::new();
        let mut rights = Vec::new();
        while let Some(op) = self.cmp_op()? {
            ops.push(op);
            rights.push(self.operand(depth + 1)?);
        }
        if ops.is_empty() {
            return Ok(left);
        }
        Ok(Ast::Cmp { left: Box::new(left), ops, rights })
    }

    fn operand(&mut self, depth: usize) -> Result<Ast, PredicateError> {
        if depth > MAX_DEPTH {
            return perr("predicate nested too deeply");
        }
        let tok = match self.next_tok() {
            Some(t_val) => t_val,
            None => return perr("unexpected end of predicate"),
        };
        if let Tok::Op(ref op_str) = tok {
            if op_str == "-" || op_str == "+" {
                if let Some(Tok::Num(val_num, false)) = self.peek().cloned() {
                    self.next_tok();
                    let signed = if op_str == "-" { -val_num } else { val_num };
                    return Ok(Ast::Const(Value::Num(signed), false));
                }
                return perr(format!("predicate uses disallowed syntax (unary {op_str})"));
            }
        }
        match tok {
            Tok::Num(val_num, is_float) => Ok(Ast::Const(Value::Num(val_num), is_float)),
            Tok::Str(val_str) => Ok(Ast::Const(Value::Str(val_str), false)),
            Tok::Ellipsis => Ok(Ast::Const(Value::Ellipsis, false)),
            Tok::Name(nm) => {
                match nm.as_str() {
                    "True" => Ok(Ast::Const(Value::Bool(true), false)),
                    "False" => Ok(Ast::Const(Value::Bool(false), false)),
                    "None" => Ok(Ast::Const(Value::Null, false)),
                    "and" | "or" | "not" | "in" => {
                        perr(format!("unexpected keyword {nm} in predicate"))
                    }
                    _ if PY_KEYWORDS.contains(&nm.as_str()) => {
                        perr(format!("predicate uses a Python keyword as a name: {nm}"))
                    }
                    _ => Ok(Ast::Name(nm)),
                }
            }
            Tok::Op(op_str) if op_str == "[" => {
                let mut elts = Vec::new();
                if self.peek().is_some() && !self.peek_op("]") {
                    elts.push(self.or_expr(depth + 1)?);
                    while self.peek_op(",") {
                        self.next_tok();
                        if self.peek_op("]") {
                            break;
                        }
                        elts.push(self.or_expr(depth + 1)?);
                    }
                }
                self.expect("]")?;
                Ok(Ast::List(elts))
            }
            Tok::Op(op_str) if op_str == "(" => {
                if self.peek_op(")") {
                    self.next_tok();
                    return Ok(Ast::List(Vec::new()));
                }
                let first = self.or_expr(depth + 1)?;
                if self.peek_op(",") {
                    let mut elts = vec![first];
                    while self.peek_op(",") {
                        self.next_tok();
                        if self.peek_op(")") {
                            break;
                        }
                        elts.push(self.or_expr(depth + 1)?);
                    }
                    self.expect(")")?;
                    return Ok(Ast::List(elts));
                }
                self.expect(")")?;
                Ok(first)
            }
            Tok::Op(op_str) => perr(format!("predicate uses disallowed syntax ({op_str})")),
        }
    }
}

pub(crate) fn parse_expr(src: &str) -> Result<Ast, PredicateError> {
    let toks = tokenize(src)?;
    let mut parser = Parser { toks, pos: 0 };
    let mut tree = parser.or_expr(0)?;
    if parser.peek_op(",") {
        let mut elts = vec![tree];
        while parser.peek_op(",") {
            parser.next_tok();
            if parser.peek().is_none() {
                break;
            }
            elts.push(parser.or_expr(1)?);
        }
        tree = Ast::List(elts);
    }
    if parser.pos != parser.toks.len() {
        return perr("trailing tokens in predicate");
    }
    Ok(tree)
}

/// Python truthiness for JSON-ish values: null, false, 0, -0, "", [], {} are falsy. NaN is
/// TRUTHY (as in Python). Ellipsis is truthy.
pub fn py_truthy(val: &Value) -> bool {
    match val {
        Value::Null => false,
        Value::Bool(bool_val) => *bool_val,
        Value::Num(num_val) => *num_val != 0.0,
        Value::Str(str_val) => !str_val.is_empty(),
        Value::List(arr_val) => !arr_val.is_empty(),
        Value::Obj(obj_val) => !obj_val.is_empty(),
        Value::Ellipsis => true,
    }
}

fn as_num(val: &Value) -> Option<f64> {
    match val {
        Value::Num(num_val) => Some(*num_val),
        Value::Bool(bool_val) => Some(if *bool_val { 1.0 } else { 0.0 }),
        _ => None,
    }
}

pub(crate) fn py_eq(left: &Value, right: &Value, depth: usize) -> Option<bool> {
    if depth > CMP_DEPTH {
        return None;
    }
    if let (Some(num_left), Some(num_right)) = (as_num(left), as_num(right)) {
        return Some(num_left == num_right);
    }
    match (left, right) {
        (Value::Str(str_left), Value::Str(str_right)) => Some(str_left == str_right),
        (Value::Null, Value::Null) => Some(true),
        (Value::Null, _) | (_, Value::Null) => Some(false),
        (Value::List(items_left), Value::List(items_right)) => {
            if items_left.len() != items_right.len() {
                return Some(false);
            }
            for (item_left, item_right) in items_left.iter().zip(items_right) {
                if !py_eq(item_left, item_right, depth + 1)? {
                    return Some(false);
                }
            }
            Some(true)
        }
        (Value::Obj(entries_left), Value::Obj(entries_right)) => {
            if entries_left.len() != entries_right.len() {
                return Some(false);
            }
            for (key, val_left) in entries_left {
                match Value::obj_get(entries_right, key) {
                    Some(val_right) => {
                        if !py_eq(val_left, val_right, depth + 1)? {
                            return Some(false);
                        }
                    }
                    None => return Some(false),
                }
            }
            Some(true)
        }
        _ => Some(false),
    }
}

pub(crate) fn py_order(left: &Value, right: &Value, depth: usize) -> Option<i8> {
    if depth > CMP_DEPTH {
        return None;
    }
    if let (Some(num_left), Some(num_right)) = (as_num(left), as_num(right)) {
        if num_left.is_nan() || num_right.is_nan() {
            return None;
        }
        return Some(if num_left < num_right { -1 } else if num_left > num_right { 1 } else { 0 });
    }
    match (left, right) {
        (Value::Str(str_left), Value::Str(str_right)) => {
            let chars_left: Vec<char> = str_left.chars().collect();
            let chars_right: Vec<char> = str_right.chars().collect();
            for char_idx in 0..chars_left.len().min(chars_right.len()) {
                if chars_left[char_idx] != chars_right[char_idx] {
                    return Some(if (chars_left[char_idx] as u32) < (chars_right[char_idx] as u32) { -1 } else { 1 });
                }
            }
            Some(match chars_left.len().cmp(&chars_right.len()) {
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            })
        }
        (Value::List(items_left), Value::List(items_right)) => {
            for item_idx in 0..items_left.len().min(items_right.len()) {
                if py_eq(&items_left[item_idx], &items_right[item_idx], depth + 1)? {
                    continue;
                }
                return py_order(&items_left[item_idx], &items_right[item_idx], depth + 1);
            }
            Some(match items_left.len().cmp(&items_right.len()) {
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            })
        }
        _ => None,
    }
}

fn py_in(left: &Value, right: &Value, depth: usize) -> Option<bool> {
    if depth > CMP_DEPTH {
        return None;
    }
    match right {
        Value::Str(haystack) => match left {
            Value::Str(needle) => Some(haystack.contains(needle.as_str())),
            _ => None,
        },
        Value::List(items) => {
            for item in items {
                match py_eq(left, item, depth + 1) {
                    Some(true) => return Some(true),
                    Some(false) => continue,
                    None => return None,
                }
            }
            Some(false)
        }
        Value::Obj(entries) => match left {
            Value::Str(key) => Some(Value::obj_get(entries, key).is_some()),
            _ => None,
        },
        _ => None,
    }
}

fn compare_op(op: &str, left: &Value, right: &Value) -> bool {
    match op {
        "==" => py_eq(left, right, 0).unwrap_or(false),
        "!=" => py_eq(left, right, 0).map(|res_bool| !res_bool).unwrap_or(false),
        "<" | "<=" | ">" | ">=" => match py_order(left, right, 0) {
            None => false,
            Some(order_val) => match op {
                "<" => order_val < 0,
                "<=" => order_val <= 0,
                ">" => order_val > 0,
                _ => order_val >= 0,
            },
        },
        "in" => py_in(left, right, 0).unwrap_or(false),
        "not in" => py_in(left, right, 0).map(|res_bool| !res_bool).unwrap_or(true),
        _ => false,
    }
}

fn ev_node(node: &Ast, ctx: &HashMap<String, Value>, depth: usize) -> Result<Value, PredicateError> {
    if depth > MAX_DEPTH {
        return perr("predicate nested too deeply");
    }
    match node {
        Ast::Const(val, _) => Ok(val.clone()),
        Ast::Name(nm) => Ok(ctx.get(nm).cloned().unwrap_or(Value::Null)),
        Ast::And(vals) => {
            let evaluated_vals: Vec<Value> =
                vals.iter().map(|item| ev_node(item, ctx, depth + 1)).collect::<Result<_, _>>()?;
            Ok(Value::Bool(evaluated_vals.iter().all(py_truthy)))
        }
        Ast::Or(vals) => {
            let evaluated_vals: Vec<Value> =
                vals.iter().map(|item| ev_node(item, ctx, depth + 1)).collect::<Result<_, _>>()?;
            Ok(Value::Bool(evaluated_vals.iter().any(py_truthy)))
        }
        Ast::Not(val) => Ok(Value::Bool(!py_truthy(&ev_node(val, ctx, depth + 1)?))),
        Ast::List(elements) => Ok(Value::List(
            elements.iter().map(|elem| ev_node(elem, ctx, depth + 1)).collect::<Result<_, _>>()?,
        )),
        Ast::Cmp { left, ops, rights } => {
            let mut left_val = ev_node(left, ctx, depth + 1)?;
            for (op_str, right_node) in ops.iter().zip(rights) {
                let right_val = ev_node(right_node, ctx, depth + 1)?;
                if !compare_op(op_str, &left_val, &right_val) {
                    return Ok(Value::Bool(false));
                }
                left_val = right_val;
            }
            Ok(Value::Bool(true))
        }
    }
}

pub fn eval_condition(condition: &str, ctx: &HashMap<String, Value>) -> Result<bool, PredicateError> {
    let expr = expr_of(condition);
    let low = expr.to_lowercase();
    if ALWAYS.contains(&low.as_str()) {
        return Ok(true);
    }
    if NEVER.contains(&low.as_str()) {
        return Ok(false);
    }
    Ok(py_truthy(&ev_node(&parse_expr(&expr)?, ctx, 0)?))
}

pub fn check_predicate(condition: &str) -> Vec<String> {
    if !is_deterministic(condition) {
        return Vec::new();
    }
    let expr = expr_of(condition);
    let low = expr.to_lowercase();
    if ALWAYS.contains(&low.as_str()) || NEVER.contains(&low.as_str()) {
        return Vec::new();
    }
    if expr.is_empty() {
        return vec![format!("empty `when` predicate in {condition:?}")];
    }
    if let Err(err) = parse_expr(&expr) {
        return vec![format!("unparseable/unsafe predicate {condition:?}: {}", err.0)];
    }
    Vec::new()
}
