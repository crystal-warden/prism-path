//! prismpath-rs — the portable PrismPath kernel, in Rust.
//!
//! A faithful port of `portable/prismpath.mjs` (itself a certified port of the Python reference:
//! 1067/1067 predicates, 27/27 flows). The conformance corpus in `../prismpath/portable/conformance`
//! IS the specification, and this crate's only claim to correctness is passing it bit-for-bit:
//!
//! ```text
//! cargo run --bin conformance -- ../prismpath/portable/conformance
//! ```
//!
//! PORTING DISCIPLINE. Where Python/JS semantics are subtle, this file mirrors the .mjs decision —
//! including the ones that look wrong at first sight — because the corpus is the judge and the .mjs
//! is the implementation that passes it. The subtleties are commented at the site where each one
//! bites; most were originally found by a 61,700-comparison differential fuzz and each has a vector
//! in `predicates.json` pinning it. Highlights:
//!
//!   * `True`/`False`/`None` are constants; lowercase `true`/`false` are FIELD NAMES.
//!   * booleans compare numerically (`flag == 1` is true for flag=true).
//!   * a failed or type-impossible comparison is UNSATISFIED, never a crash — except `not in`,
//!     whose failure is SATISFIED ("unknown -> falsy").
//!   * chained comparisons, substring `in`, membership with loose `==`, Python truthiness.
//!   * Python hard keywords are rejected as names; soft keywords are ordinary names.
//!   * Python's `str.strip()` whitespace and `str.splitlines()` boundaries are both WIDER than
//!     their JS/Rust counterparts, and condition classification must agree across engines.
//!
//! No `eval` of any kind: predicates go through a hand-rolled tokenizer + recursive-descent parser
//! onto a tiny AST, exactly mirroring the Python sandbox.

use std::collections::HashMap;

pub const MAX_DEPTH: usize = 50;

/// The comparison-recursion cap standing in for the .mjs `catch` in `compareOp`. JS absorbs an
/// engine-level recursion overflow on absurdly nested contexts into "unsatisfied"; Rust has no
/// catchable stack overflow, so the same protection must be an explicit depth budget. Generous —
/// no legitimate context comes close — and running out behaves exactly like the .mjs catch.
const CMP_DEPTH: usize = 200;

// ------------------------------------------------------------------------------- values

/// The evaluator's value domain: JSON plus Python's `...`.
///
/// Ellipsis has to live INSIDE the recursive type, not beside it, because predicate source can put
/// it anywhere a literal goes (`when x in [..., 1]`). All numbers are f64, mirroring the .mjs (and
/// JSON itself): the corpus cannot distinguish 3 from 3.0 or the certified port would not pass.
#[derive(Debug, Clone, PartialEq)]
pub enum V {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    List(Vec<V>),
    /// Insertion-ordered, like a JS object / Python dict — ordering is observable through
    /// `py_str`, which renders dict outcomes into `text` that predicates then route on.
    Obj(Vec<(String, V)>),
    Ellipsis,
}

impl V {
    pub fn from_json(v: &serde_json::Value) -> V {
        match v {
            serde_json::Value::Null => V::Null,
            serde_json::Value::Bool(b) => V::Bool(*b),
            serde_json::Value::Number(n) => V::Num(n.as_f64().unwrap_or(0.0)),
            serde_json::Value::String(s) => V::Str(s.clone()),
            serde_json::Value::Array(a) => V::List(a.iter().map(V::from_json).collect()),
            serde_json::Value::Object(o) => {
                V::Obj(o.iter().map(|(k, x)| (k.clone(), V::from_json(x))).collect())
            }
        }
    }

    fn obj_get<'a>(entries: &'a [(String, V)], key: &str) -> Option<&'a V> {
        entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }
}

#[derive(Debug, Clone)]
pub struct PredicateError(pub String);

impl std::fmt::Display for PredicateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for PredicateError {}

fn perr<T>(msg: impl Into<String>) -> Result<T, PredicateError> {
    Err(PredicateError(msg.into()))
}

// -------------------------------------------------------------------------- whitespace
// Three DIFFERENT whitespace vocabularies are in play, and conflating them changes routing:
//   * the tokenizer skips exactly " \t\n\r";
//   * JS `\s` / `String.trim()` — what the flow-document regexes use;
//   * Python `str.strip()` — JS `\s` PLUS \x85 \x1c-\x1f — what classifies conditions.

/// JS `\s` (the regex class, which String.trim also uses).
fn is_js_ws(c: char) -> bool {
    matches!(c,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}'
        | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}'
        | '\u{3000}' | '\u{feff}')
}

fn js_trim(s: &str) -> &str {
    s.trim_matches(is_js_ws)
}

/// Python `str.strip()` whitespace — wider than JS trim (e.g. U+0085 NEL). The tier a condition
/// lands in must be identical across engines, so classification uses THIS, never `str::trim`.
fn is_py_ws(c: char) -> bool {
    is_js_ws(c) || matches!(c, '\u{85}' | '\u{1c}' | '\u{1d}' | '\u{1e}' | '\u{1f}')
}

pub fn py_trim(s: &str) -> &str {
    s.trim_matches(is_py_ws)
}

/// Python `str.splitlines()` boundaries. A bare `split('\n')` hides edges behind \r or NEL —
/// a CR-only or U+2028 document must parse to the same node/edge sets on every engine.
fn split_lines_py(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < chars.len() {
        let (pos, c) = chars[i];
        let is_break = matches!(c,
            '\n' | '\r' | '\u{b}' | '\u{c}' | '\u{1c}' | '\u{1d}' | '\u{1e}' | '\u{85}'
            | '\u{2028}' | '\u{2029}');
        if is_break {
            out.push(&text[start..pos]);
            // \r\n is one boundary, not two
            if c == '\r' && i + 1 < chars.len() && chars[i + 1].1 == '\n' {
                i += 1;
            }
            start = if i + 1 < chars.len() { chars[i + 1].0 } else { text.len() };
        }
        i += 1;
    }
    out.push(&text[start..]);
    out
}

// ------------------------------------------------------------------------- conditions

const ALWAYS: [&str; 6] = ["always", "true", "else", "otherwise", "default", "_"];
const NEVER: [&str; 2] = ["false", "never"];

// Python HARD keywords (minus True/False/None, which are constants, and and/or/not/in, which are
// operators here). Python's ast.parse REJECTS these as names — `when class == "phish"` is a
// PredicateError there, so it must be one here too, or the edge routes differently across engines.
// Soft keywords (match/case/type) are ordinary Names in both.
const PY_KEYWORDS: [&str; 28] = [
    "as", "assert", "async", "await", "break", "class", "continue", "def", "del", "elif", "else",
    "except", "finally", "for", "from", "global", "if", "import", "is", "lambda", "nonlocal",
    "pass", "raise", "return", "try", "while", "with", "yield",
];

pub fn is_deterministic(condition: &str) -> bool {
    let c = py_trim(condition).to_lowercase();
    c.starts_with("when ") || ALWAYS.contains(&c.as_str()) || NEVER.contains(&c.as_str())
}

pub fn is_error(condition: &str) -> bool {
    py_trim(condition).to_lowercase().starts_with("on error")
}

pub fn is_event(condition: &str) -> bool {
    let c = py_trim(condition).to_lowercase();
    c.starts_with("on event") || c.starts_with("on timeout")
}

pub fn event_name(condition: &str) -> String {
    let c = py_trim(condition);
    if c.to_lowercase().starts_with("on timeout") {
        return "__timeout__".to_string();
    }
    let tail: String = c.chars().skip("on event".chars().count()).collect();
    py_trim(&tail).to_string()
}

pub fn is_semantic(condition: &str) -> bool {
    !is_deterministic(condition) && !is_error(condition) && !is_event(condition)
}

pub fn error_expr(condition: &str) -> String {
    let c = py_trim(condition);
    let tail: String = c.chars().skip("on error".chars().count()).collect();
    py_trim(&tail).to_string()
}

/// The expression under a condition: `when X` -> X (sliced from the CASE-PRESERVED text — only
/// the prefix test is case-folded), anything else verbatim.
fn expr_of(condition: &str) -> String {
    let c = py_trim(condition);
    if c.to_lowercase().starts_with("when ") {
        let tail: String = c.chars().skip(5).collect();
        py_trim(&tail).to_string()
    } else {
        c.to_string()
    }
}

// ------------------------------------------------------------------- expression parsing
// Grammar (== the Python ast subset the sandbox allows):
//   expr    := or ;  or := and ("or" and)* ;  and := not ("and" not)*
//   not     := "not" not | cmp
//   cmp     := operand ((==|!=|<|<=|>|>=|in|not in) operand)*
//   operand := number | string | True | False | None | name | "[" args "]" | "(" tuple-or-group ")"
// No calls, attributes, subscripts, arithmetic, or unary minus — anything else throws.

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Name(String),
    Num(f64),
    Str(String),
    Ellipsis,
    Op(String),
}

fn tokenize(src: &str) -> Result<Vec<Tok>, PredicateError> {
    let s: Vec<char> = src.chars().collect();
    let n = s.len();
    let mut toks = Vec::new();
    let mut i = 0usize;

    while i < n {
        let ch = s[i];
        // the tokenizer's own whitespace is EXACTLY " \t\n\r" — narrower than either trim set
        if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
            i += 1;
            continue;
        }
        if ch.is_ascii_alphabetic() || ch == '_' {
            // raw-string prefix: r'…' / R"…" is a plain Constant in Python (no escape processing)
            if (ch == 'r' || ch == 'R') && i + 1 < n && (s[i + 1] == '\'' || s[i + 1] == '"') {
                let q = s[i + 1];
                let mut j = i + 2;
                let mut out = String::new();
                while j < n && s[j] != q {
                    out.push(s[j]);
                    j += 1;
                }
                if j >= n {
                    return perr("unterminated string in predicate");
                }
                toks.push(Tok::Str(out));
                i = j + 1;
                continue;
            }
            if (ch == 'b' || ch == 'B') && i + 1 < n && (s[i + 1] == '\'' || s[i + 1] == '"') {
                return perr("bytes literals are not supported in predicates");
            }
            let mut j = i + 1;
            while j < n && (s[j].is_ascii_alphanumeric() || s[j] == '_') {
                j += 1;
            }
            toks.push(Tok::Name(s[i..j].iter().collect()));
            i = j;
            continue;
        }
        if ch.is_ascii_digit() || (ch == '.' && i + 1 < n && s[i + 1].is_ascii_digit()) {
            // Python numeric literal spellings: 0x/0o/0b radixes and _ separators are legal; a
            // trailing j (complex) is a hard reject on both sides for parity's sake.
            let radix2: String = s[i..(i + 2).min(n)].iter().collect::<String>().to_lowercase();
            if ch == '0' && (radix2 == "0x" || radix2 == "0o" || radix2 == "0b") {
                let mut j = i + 2;
                let digit_ok: fn(char) -> bool = match radix2.as_str() {
                    "0x" => |c| c.is_ascii_hexdigit() || c == '_',
                    "0o" => |c| ('0'..='7').contains(&c) || c == '_',
                    _ => |c| c == '0' || c == '1' || c == '_',
                };
                while j < n && digit_ok(s[j]) {
                    j += 1;
                }
                let body: String = s[i + 2..j].iter().filter(|c| **c != '_').collect();
                if body.is_empty() {
                    return perr("malformed numeric literal in predicate");
                }
                let radix = match radix2.as_str() { "0x" => 16, "0o" => 8, _ => 2 };
                // accumulate in f64 — the same rounding parseInt's result carries downstream
                let mut val = 0f64;
                for c in body.chars() {
                    // every char in `body` passed digit_ok for this radix (and '_' was filtered), so
                    // to_digit(radix) is always Some.
                    val = val * radix as f64 + c.to_digit(radix).expect("digit valid for radix") as f64;
                }
                toks.push(Tok::Num(val));
                i = j;
                continue;
            }
            let mut j = i;
            while j < n && (s[j].is_ascii_digit() || s[j] == '_') {
                j += 1;
            }
            if j < n && s[j] == '.' {
                j += 1;
                while j < n && (s[j].is_ascii_digit() || s[j] == '_') {
                    j += 1;
                }
            }
            if j < n && (s[j] == 'e' || s[j] == 'E') {
                let mut k = j + 1;
                if k < n && (s[k] == '+' || s[k] == '-') {
                    k += 1;
                }
                if k < n && s[k].is_ascii_digit() {
                    k += 1;
                    while k < n && (s[k].is_ascii_digit() || s[k] == '_') {
                        k += 1;
                    }
                    j = k;
                }
            }
            if j < n && (s[j] == 'j' || s[j] == 'J') {
                return perr("complex literals are not supported in predicates");
            }
            let text: String = s[i..j].iter().filter(|c| **c != '_').collect();
            // JS Number() and Rust f64 parsing are both correctly rounded; "1." parses as 1
            let val = text.parse::<f64>().unwrap_or(f64::NAN);
            toks.push(Tok::Num(val));
            i = j;
            continue;
        }
        if ch == '"' || ch == '\'' {
            let mut j = i + 1;
            let mut out = String::new();
            while j < n && s[j] != ch {
                if s[j] == '\\' && j + 1 < n {
                    let e = s[j + 1];
                    // Python's escape table; an UNKNOWN escape keeps the backslash (Python
                    // semantics), it is not silently dropped.
                    match e {
                        'n' => out.push('\n'),
                        't' => out.push('\t'),
                        'r' => out.push('\r'),
                        '0' => out.push('\0'),
                        'a' => out.push('\u{7}'),
                        'b' => out.push('\u{8}'),
                        'f' => out.push('\u{c}'),
                        'v' => out.push('\u{b}'),
                        '\\' | '\'' | '"' => out.push(e),
                        'x' if j + 3 < n
                            && s[j + 2].is_ascii_hexdigit()
                            && s[j + 3].is_ascii_hexdigit() =>
                        {
                            let code: String = s[j + 2..j + 4].iter().collect();
                            let v = u32::from_str_radix(&code, 16).expect("two guarded hex digits"); // 0x00..0xff
                            out.push(char::from_u32(v).unwrap_or('\u{fffd}'));
                            j += 2;
                        }
                        'u' if j + 5 < n && s[j + 2..j + 6].iter().all(|c| c.is_ascii_hexdigit()) => {
                            let code: String = s[j + 2..j + 6].iter().collect();
                            let v = u32::from_str_radix(&code, 16).expect("four guarded hex digits"); // 0x0000..0xffff
                            // String.fromCharCode is a UTF-16 unit; a lone surrogate cannot live
                            // in a Rust String, so it degrades to U+FFFD. No corpus vector uses
                            // one — if that ever changes, the gate will say so.
                            out.push(char::from_u32(v).unwrap_or('\u{fffd}'));
                            j += 4;
                        }
                        _ => {
                            out.push('\\');
                            out.push(e);
                        }
                    }
                    j += 2;
                } else {
                    out.push(s[j]);
                    j += 1;
                }
            }
            if j >= n {
                return perr("unterminated string in predicate");
            }
            toks.push(Tok::Str(out));
            i = j + 1;
            continue;
        }
        if i + 3 <= n && s[i..i + 3] == ['.', '.', '.'] {
            toks.push(Tok::Ellipsis);
            i += 3;
            continue;
        }
        if i + 2 <= n {
            let two: String = s[i..i + 2].iter().collect();
            if two == "==" || two == "!=" || two == "<=" || two == ">=" {
                toks.push(Tok::Op(two));
                i += 2;
                continue;
            }
        }
        if "<>[](),".contains(ch) {
            toks.push(Tok::Op(ch.to_string()));
            i += 1;
            continue;
        }
        let near: String = s[i..(i + 8).min(n)].iter().collect();
        return perr(format!("predicate uses disallowed syntax near {near:?}"));
    }
    Ok(toks)
}

#[derive(Debug, Clone)]
enum Ast {
    Const(V),
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
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }
    fn peek_op(&self, v: &str) -> bool {
        matches!(self.peek(), Some(Tok::Op(o)) if o == v)
    }
    fn peek_name(&self, v: &str) -> bool {
        matches!(self.peek(), Some(Tok::Name(nm)) if nm == v)
    }
    fn expect(&mut self, v: &str) -> Result<(), PredicateError> {
        match self.next_tok() {
            Some(Tok::Op(o)) if o == v => Ok(()),
            _ => perr(format!("expected {v:?} in predicate")),
        }
    }

    // Depth accounting mirrors PYTHON AST DEPTH: only structural nesting (a boolean/comparison
    // node, `not`, a collection, a grouped expression) deepens — the precedence CASCADE itself
    // adds nothing, else `((((((((((x))))))))))` would burn ~5 levels per paren and reject
    // expressions Python accepts.
    fn or_expr(&mut self, d: usize) -> Result<Ast, PredicateError> {
        if d > MAX_DEPTH {
            return perr("predicate nested too deeply");
        }
        let mut vals = vec![self.and_expr(d)?];
        while self.peek_name("or") {
            self.next_tok();
            vals.push(self.and_expr(d + 1)?);
        }
        Ok(if vals.len() == 1 { vals.pop().expect("len == 1") } else { Ast::Or(vals) })
    }

    fn and_expr(&mut self, d: usize) -> Result<Ast, PredicateError> {
        if d > MAX_DEPTH {
            return perr("predicate nested too deeply");
        }
        let mut vals = vec![self.not_expr(d)?];
        while self.peek_name("and") {
            self.next_tok();
            vals.push(self.not_expr(d + 1)?);
        }
        Ok(if vals.len() == 1 { vals.pop().expect("len == 1") } else { Ast::And(vals) })
    }

    fn not_expr(&mut self, d: usize) -> Result<Ast, PredicateError> {
        if d > MAX_DEPTH {
            return perr("predicate nested too deeply");
        }
        if self.peek_name("not") {
            self.next_tok();
            return Ok(Ast::Not(Box::new(self.not_expr(d + 1)?)));
        }
        self.cmp_expr(d)
    }

    fn cmp_op(&mut self) -> Result<Option<String>, PredicateError> {
        match self.peek() {
            Some(Tok::Op(o)) if ["==", "!=", "<", "<=", ">", ">="].contains(&o.as_str()) => {
                let op = o.clone();
                self.next_tok();
                Ok(Some(op))
            }
            Some(Tok::Name(nm)) if nm == "in" => {
                self.next_tok();
                Ok(Some("in".to_string()))
            }
            Some(Tok::Name(nm)) if nm == "not" => {
                // in comparison position, `not` must begin `not in` (`a not b` is a SyntaxError)
                self.next_tok();
                match self.next_tok() {
                    Some(Tok::Name(nx)) if nx == "in" => Ok(Some("not in".to_string())),
                    _ => perr("expected `in` after `not`"),
                }
            }
            _ => Ok(None),
        }
    }

    fn cmp_expr(&mut self, d: usize) -> Result<Ast, PredicateError> {
        if d > MAX_DEPTH {
            return perr("predicate nested too deeply");
        }
        let left = self.operand(d)?;
        let mut ops = Vec::new();
        let mut rights = Vec::new();
        while let Some(op) = self.cmp_op()? {
            ops.push(op);
            rights.push(self.operand(d + 1)?);
        }
        if ops.is_empty() {
            return Ok(left);
        }
        Ok(Ast::Cmp { left: Box::new(left), ops, rights })
    }

    fn operand(&mut self, d: usize) -> Result<Ast, PredicateError> {
        if d > MAX_DEPTH {
            return perr("predicate nested too deeply");
        }
        let tk = match self.next_tok() {
            Some(t) => t,
            None => return perr("unexpected end of predicate"),
        };
        match tk {
            Tok::Num(v) => Ok(Ast::Const(V::Num(v))),
            Tok::Str(v) => Ok(Ast::Const(V::Str(v))),
            Tok::Ellipsis => Ok(Ast::Const(V::Ellipsis)), // `...` is a truthy Constant
            Tok::Name(nm) => {
                // Python-exact: True/False/None are constants; anything else (incl. lowercase
                // true) is a Name that reads the context.
                match nm.as_str() {
                    "True" => Ok(Ast::Const(V::Bool(true))),
                    "False" => Ok(Ast::Const(V::Bool(false))),
                    "None" => Ok(Ast::Const(V::Null)),
                    "and" | "or" | "not" | "in" => {
                        perr(format!("unexpected keyword {nm} in predicate"))
                    }
                    _ if PY_KEYWORDS.contains(&nm.as_str()) => {
                        perr(format!("predicate uses a Python keyword as a name: {nm}"))
                    }
                    _ => Ok(Ast::Name(nm)),
                }
            }
            Tok::Op(o) if o == "[" => {
                let mut elts = Vec::new();
                if self.peek().is_some() && !self.peek_op("]") {
                    elts.push(self.or_expr(d + 1)?);
                    while self.peek_op(",") {
                        self.next_tok();
                        if self.peek_op("]") {
                            break;
                        }
                        elts.push(self.or_expr(d + 1)?);
                    }
                }
                self.expect("]")?;
                Ok(Ast::List(elts))
            }
            Tok::Op(o) if o == "(" => {
                if self.peek_op(")") {
                    self.next_tok();
                    return Ok(Ast::List(Vec::new())); // ()
                }
                let first = self.or_expr(d + 1)?;
                if self.peek_op(",") {
                    // a tuple literal, e.g. (1, 2)
                    let mut elts = vec![first];
                    while self.peek_op(",") {
                        self.next_tok();
                        if self.peek_op(")") {
                            break;
                        }
                        elts.push(self.or_expr(d + 1)?);
                    }
                    self.expect(")")?;
                    return Ok(Ast::List(elts));
                }
                self.expect(")")?;
                Ok(first) // a grouped expression
            }
            Tok::Op(o) => perr(format!("predicate uses disallowed syntax ({o})")),
        }
    }
}

fn parse_expr(src: &str) -> Result<Ast, PredicateError> {
    let toks = tokenize(src)?;
    let mut p = Parser { toks, pos: 0 };
    let mut tree = p.or_expr(0)?;
    // a TOP-LEVEL comma is a bare tuple in Python — `when done, verified` parses (and, being a
    // non-empty tuple, is ALWAYS truthy: a real authoring trap, but parity comes first)
    if p.peek_op(",") {
        let mut elts = vec![tree];
        while p.peek_op(",") {
            p.next_tok();
            if p.peek().is_none() {
                break; // trailing comma: (x,) style
            }
            elts.push(p.or_expr(1)?);
        }
        tree = Ast::List(elts);
    }
    if p.pos != p.toks.len() {
        return perr("trailing tokens in predicate");
    }
    Ok(tree)
}

// ------------------------------------------------------------------------- evaluation

/// Python truthiness for JSON-ish values: null, false, 0, -0, "", [], {} are falsy. NaN is
/// TRUTHY (as in Python). Ellipsis is truthy.
pub fn py_truthy(v: &V) -> bool {
    match v {
        V::Null => false,
        V::Bool(b) => *b,
        V::Num(n) => *n != 0.0, // NaN != 0 -> truthy, matching Python; -0.0 == 0.0 -> falsy
        V::Str(s) => !s.is_empty(),
        V::List(a) => !a.is_empty(),
        V::Obj(o) => !o.is_empty(),
        V::Ellipsis => true,
    }
}

fn as_num(v: &V) -> Option<f64> {
    match v {
        V::Num(n) => Some(*n),
        V::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        _ => None,
    }
}

/// Python `==` over JSON values: booleans compare numerically with numbers (True == 1);
/// lists/objects compare structurally; cross-type otherwise is False (never an error).
///
/// Depth-budgeted (see `CMP_DEPTH`): overrunning reports None, which `compare_op` absorbs the
/// same way the .mjs catch does. Note Ellipsis equals NOTHING here, itself included — that is
/// what the certified .mjs does (a Symbol falls through every branch), and the corpus is the
/// judge, so the port mirrors it rather than Python's `... == ...`.
fn py_eq(a: &V, b: &V, d: usize) -> Option<bool> {
    if d > CMP_DEPTH {
        return None;
    }
    if let (Some(na), Some(nb)) = (as_num(a), as_num(b)) {
        return Some(na == nb); // NaN == NaN is false in both languages
    }
    match (a, b) {
        (V::Str(x), V::Str(y)) => Some(x == y),
        (V::Null, V::Null) => Some(true),
        (V::Null, _) | (_, V::Null) => Some(false),
        (V::List(x), V::List(y)) => {
            if x.len() != y.len() {
                return Some(false);
            }
            for (xi, yi) in x.iter().zip(y) {
                if !py_eq(xi, yi, d + 1)? {
                    return Some(false);
                }
            }
            Some(true)
        }
        (V::Obj(x), V::Obj(y)) => {
            if x.len() != y.len() {
                return Some(false);
            }
            for (k, xv) in x {
                match V::obj_get(y, k) {
                    Some(yv) => {
                        if !py_eq(xv, yv, d + 1)? {
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

/// Python ordering, total-ized: Some(-1/0/1), or None for an incomparable pair (which the
/// comparison layer treats as UNSATISFIED). Strings compare by CODE POINT (Rust chars already
/// are); lists compare lexicographically, element-wise.
fn py_order(a: &V, b: &V, d: usize) -> Option<i8> {
    if d > CMP_DEPTH {
        return None;
    }
    if let (Some(na), Some(nb)) = (as_num(a), as_num(b)) {
        if na.is_nan() || nb.is_nan() {
            return None; // Python nan comparisons are all False
        }
        return Some(if na < nb { -1 } else if na > nb { 1 } else { 0 });
    }
    match (a, b) {
        (V::Str(x), V::Str(y)) => {
            let xa: Vec<char> = x.chars().collect();
            let ya: Vec<char> = y.chars().collect();
            for i in 0..xa.len().min(ya.len()) {
                if xa[i] != ya[i] {
                    return Some(if (xa[i] as u32) < (ya[i] as u32) { -1 } else { 1 });
                }
            }
            Some(match xa.len().cmp(&ya.len()) {
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            })
        }
        (V::List(x), V::List(y)) => {
            for i in 0..x.len().min(y.len()) {
                // Python list comparison steps past ==-EQUAL elements even when they are
                // unorderable ([None, 1] > [None] is True: None == None, then length decides) —
                // so test equality first and only demand an ordering when the elements differ.
                if py_eq(&x[i], &y[i], d + 1)? {
                    continue;
                }
                return py_order(&x[i], &y[i], d + 1);
            }
            Some(match x.len().cmp(&y.len()) {
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            })
        }
        _ => None, // mixed / null / objects: incomparable
    }
}

/// Python `a in b`: substring on strings, membership (loose ==) on lists, key test on
/// objects; anything else is a "type error" -> None (unsatisfied; `not in` satisfied).
fn py_in(a: &V, b: &V, d: usize) -> Option<bool> {
    if d > CMP_DEPTH {
        return None;
    }
    match b {
        V::Str(hay) => match a {
            V::Str(needle) => Some(hay.contains(needle.as_str())),
            _ => None,
        },
        V::List(items) => {
            for x in items {
                match py_eq(a, x, d + 1) {
                    Some(true) => return Some(true),
                    Some(false) => continue,
                    None => return None,
                }
            }
            Some(false)
        }
        V::Obj(entries) => match a {
            V::Str(key) => Some(V::obj_get(entries, key).is_some()),
            _ => None,
        },
        _ => None,
    }
}

/// One pairwise comparison, made TOTAL exactly like the reference's `_compare`: a failed or
/// impossible test is unsatisfied — except `not in`, which is then satisfied ("unknown ->
/// falsy"). The depth budget stands in for the .mjs blanket catch: ANY internal failure is
/// unsatisfied, never a crash out of run().
fn compare_op(op: &str, left: &V, right: &V) -> bool {
    match op {
        "==" => py_eq(left, right, 0).unwrap_or(false),
        "!=" => py_eq(left, right, 0).map(|b| !b).unwrap_or(false),
        "<" | "<=" | ">" | ">=" => match py_order(left, right, 0) {
            None => false,
            Some(o) => match op {
                "<" => o < 0,
                "<=" => o <= 0,
                ">" => o > 0,
                _ => o >= 0,
            },
        },
        "in" => py_in(left, right, 0).unwrap_or(false),
        "not in" => py_in(left, right, 0).map(|b| !b).unwrap_or(true), // failure satisfies
        // The parser only emits the operators handled above, so this is unreachable in practice.
        // We return `false` rather than panic so eval stays TOTAL: SECURITY.md §1 makes any
        // non-PredicateError crash through eval_condition a critical sandbox finding.
        _ => false,
    }
}

fn ev_node(node: &Ast, ctx: &HashMap<String, V>, depth: usize) -> Result<V, PredicateError> {
    if depth > MAX_DEPTH {
        return perr("predicate nested too deeply");
    }
    match node {
        Ast::Const(v) => Ok(v.clone()),
        Ast::Name(nm) => Ok(ctx.get(nm).cloned().unwrap_or(V::Null)),
        Ast::And(vals) => {
            // NB: evaluate ALL operands first, like the reference's `.map` — no short-circuit,
            // so a PredicateError in a later operand surfaces even when an earlier one is false.
            let evs: Vec<V> =
                vals.iter().map(|v| ev_node(v, ctx, depth + 1)).collect::<Result<_, _>>()?;
            Ok(V::Bool(evs.iter().all(py_truthy)))
        }
        Ast::Or(vals) => {
            let evs: Vec<V> =
                vals.iter().map(|v| ev_node(v, ctx, depth + 1)).collect::<Result<_, _>>()?;
            Ok(V::Bool(evs.iter().any(py_truthy)))
        }
        Ast::Not(v) => Ok(V::Bool(!py_truthy(&ev_node(v, ctx, depth + 1)?))),
        Ast::List(elts) => Ok(V::List(
            elts.iter().map(|e| ev_node(e, ctx, depth + 1)).collect::<Result<_, _>>()?,
        )),
        Ast::Cmp { left, ops, rights } => {
            let mut lv = ev_node(left, ctx, depth + 1)?;
            for (op, rnode) in ops.iter().zip(rights) {
                let rv = ev_node(rnode, ctx, depth + 1)?;
                if !compare_op(op, &lv, &rv) {
                    return Ok(V::Bool(false));
                }
                lv = rv;
            }
            Ok(V::Bool(true))
        }
    }
}

/// Evaluate a deterministic condition against a context — the reference's `eval_condition`.
pub fn eval_condition(condition: &str, ctx: &HashMap<String, V>) -> Result<bool, PredicateError> {
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

/// Static safety check — the reference's `check_predicate`. Empty vec means safe AND parseable.
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
    if let Err(e) = parse_expr(&expr) {
        return vec![format!("unparseable/unsafe predicate {condition:?}: {}", e.0)];
    }
    Vec::new()
}

// ---------------------------------------------------------------------------- parsing

#[derive(Debug, Clone, Default)]
pub struct Node {
    pub name: String,
    pub instruction: String,
    pub edges: Vec<(String, String)>,
    pub annotations: HashMap<String, HashMap<String, Option<String>>>,
}

#[derive(Debug, Clone, Default)]
pub struct Graph {
    pub name: String,
    pub start: String,
    pub nodes: HashMap<String, Node>,
}

/// `-> target: condition` (optionally as a `-` bullet) — EDGE_RE.
fn match_edge(line: &str) -> Option<(String, String)> {
    let s: Vec<char> = line.chars().collect();
    let mut i = 0;
    while i < s.len() && is_js_ws(s[i]) {
        i += 1;
    }
    // the optional bullet `-` (the regex's `-?` also lets `-->` through: '-' then "->")
    if i < s.len() && s[i] == '-' && !(i + 1 < s.len() && s[i + 1] == '>') {
        i += 1;
        while i < s.len() && is_js_ws(s[i]) {
            i += 1;
        }
    }
    if !(i + 1 < s.len() && s[i] == '-' && s[i + 1] == '>') {
        return None;
    }
    i += 2;
    while i < s.len() && is_js_ws(s[i]) {
        i += 1;
    }
    let t0 = i;
    while i < s.len() && (s[i].is_ascii_alphanumeric() || s[i] == '_' || s[i] == '-') {
        i += 1;
    }
    if i == t0 {
        return None;
    }
    let target: String = s[t0..i].iter().collect();
    while i < s.len() && is_js_ws(s[i]) {
        i += 1;
    }
    if i >= s.len() || s[i] != ':' {
        return None;
    }
    i += 1;
    let rest: String = s[i..].iter().collect();
    if rest.is_empty() {
        return None; // the regex's `.+?` demands at least one character after the colon
    }
    Some((target, js_trim(&rest).to_string()))
}

/// `## heading` — HEAD_RE: `^\s*##\s+(.+?)\s*$`. At least one whitespace char must separate `##`
/// from the name, and at least one character must follow that separator.
fn match_head(line: &str) -> Option<String> {
    let s: Vec<char> = line.chars().collect();
    let mut i = 0;
    while i < s.len() && is_js_ws(s[i]) {
        i += 1;
    }
    if !(i + 1 < s.len() && s[i] == '#' && s[i + 1] == '#') {
        return None;
    }
    i += 2;
    if i >= s.len() || !is_js_ws(s[i]) {
        return None; // `##name` fails the `\s+`
    }
    // `\s+(.+?)`: one separator char minimum, then the group needs one more character — which
    // may itself be whitespace the group then absorbs ("##  " matches with an empty trim).
    if i + 1 >= s.len() {
        return None;
    }
    let rest: String = s[i + 1..].iter().collect();
    Some(js_trim(&rest).to_string())
}

/// `@name(args)` — ANNO_RE. `\w` is Unicode in Python, so the name class is too.
fn match_anno(line: &str) -> Option<(String, String)> {
    let s: Vec<char> = line.chars().collect();
    let mut i = 0;
    while i < s.len() && is_js_ws(s[i]) {
        i += 1;
    }
    if i >= s.len() || s[i] != '@' {
        return None;
    }
    i += 1;
    let n0 = i;
    while i < s.len() && (s[i].is_alphanumeric() || s[i] == '_') {
        i += 1;
    }
    if i == n0 || i >= s.len() || s[i] != '(' {
        return None;
    }
    let name: String = s[n0..i].iter().collect();
    // greedy `(.*)\)` with `\s*$`: the LAST ')' followed only by whitespace closes the args
    let mut close = None;
    for j in (i + 1..s.len()).rev() {
        if s[j] == ')' && s[j + 1..].iter().all(|c| is_js_ws(*c)) {
            close = Some(j);
            break;
        }
    }
    let close = close?;
    let args: String = s[i + 1..close].iter().collect();
    Some((name, args))
}

fn parse_anno_args(argstr: &str) -> Vec<(String, Option<String>)> {
    let mut args = Vec::new();
    for part in argstr.split(',') {
        let part = js_trim(part);
        if part.is_empty() {
            continue;
        }
        match part.find('=') {
            Some(eq) => {
                let k = js_trim(&part[..eq]);
                if !k.is_empty() {
                    args.push((k.to_string(), Some(js_trim(&part[eq + 1..]).to_string())));
                }
            }
            None => args.push((part.to_string(), None)),
        }
    }
    args
}

/// Split off YAML frontmatter, mirroring `/^---\s*\n([\s\S]*?)\n---\s*\n([\s\S]*)$/`.
///
/// The greedy `\s*\n` means: after a `---`, the delimiter consumes the whitespace run up to and
/// including its LAST newline. Hand-rolled because the two regex dialects disagree about `\s`
/// itself, and this is a routing-relevant parser — better thirty explicit lines than an imported
/// engine with slightly different semantics.
fn split_frontmatter(text: &str) -> Option<(String, String)> {
    let s: Vec<char> = text.chars().collect();
    if s.len() < 3 || s[0] != '-' || s[1] != '-' || s[2] != '-' {
        return None;
    }
    let mut i = 3;
    let mut last_nl = None;
    while i < s.len() && is_js_ws(s[i]) {
        if s[i] == '\n' {
            last_nl = Some(i);
        }
        i += 1;
    }
    let body_start = last_nl? + 1;
    // the closing "\n---" whose trailing whitespace run contains a '\n' (lazy group -> first one)
    let mut j = body_start;
    while j + 3 < s.len() {
        if s[j] == '\n' && s[j + 1] == '-' && s[j + 2] == '-' && s[j + 3] == '-' {
            let mut k = j + 4;
            let mut nl2 = None;
            while k < s.len() && is_js_ws(s[k]) {
                if s[k] == '\n' {
                    nl2 = Some(k);
                }
                k += 1;
            }
            if let Some(nl2) = nl2 {
                let meta: String = s[body_start..j].iter().collect();
                let rest: String = s[nl2 + 1..].iter().collect();
                return Some((meta, rest));
            }
        }
        j += 1;
    }
    None
}

/// Markdown -> Graph — a faithful port of the reference `parse`. A node with no edges is terminal.
pub fn parse(text: &str) -> Graph {
    let mut meta: HashMap<String, String> = HashMap::new();
    let body = match split_frontmatter(text) {
        Some((fm, body)) => {
            for line in split_lines_py(&fm) {
                if let Some(c) = line.find(':') {
                    meta.insert(
                        js_trim(&line[..c]).to_string(),
                        js_trim(&line[c + 1..]).to_string(),
                    );
                }
            }
            body
        }
        None => text.to_string(),
    };

    let mut nodes: HashMap<String, Node> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    let mut cur: Option<String> = None;
    let mut instr: Vec<String> = Vec::new();

    fn flush(cur: &Option<String>, instr: &[String], nodes: &mut HashMap<String, Node>) {
        if let Some(name) = cur {
            if let Some(node) = nodes.get_mut(name) {
                node.instruction = js_trim(&instr.join("\n")).to_string();
            }
        }
    }

    for line in split_lines_py(&body) {
        if let Some(h) = match_head(line) {
            flush(&cur, &instr, &mut nodes);
            // JS: h[1].trim().toLowerCase().replace(/ /g, "_") — only the SPACE char becomes _
            let name = h.to_lowercase().replace(' ', "_");
            nodes.insert(name.clone(), Node { name: name.clone(), ..Default::default() });
            if !order.contains(&name) {
                order.push(name.clone());
            }
            cur = Some(name);
            instr = Vec::new();
            continue;
        }
        let Some(cur_name) = &cur else { continue };
        // cur is Some(cur_name) only after a heading inserted cur_name into `nodes` (never removed).
        if let Some((target, cond)) = match_edge(line) {
            nodes.get_mut(cur_name).expect("cur names an inserted node").edges.push((target, cond));
        } else if let Some((nm, argstr)) = match_anno(line) {
            let node = nodes.get_mut(cur_name).expect("cur names an inserted node");
            let entry = node.annotations.entry(nm).or_default();
            for (k, v) in parse_anno_args(&argstr) {
                entry.insert(k, v);
            }
        } else {
            instr.push(line.to_string());
        }
    }
    flush(&cur, &instr, &mut nodes);

    let start = match meta.get("start") {
        Some(st) if !st.is_empty() => st.clone(), // JS `meta.start ||` — empty falls through
        _ => order.first().cloned().unwrap_or_default(),
    };
    // JS `meta.name !== undefined ? meta.name : "flow"` — an EMPTY name is kept
    let name = meta.get("name").cloned().unwrap_or_else(|| "flow".to_string());
    Graph { name, start, nodes }
}

// ---------------------------------------------------------------------- portability gate

fn reachable(graph: &Graph) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    let mut stack = vec![graph.start.clone()];
    while let Some(cur) = stack.pop() {
        if seen.contains(&cur) || !graph.nodes.contains_key(&cur) {
            continue;
        }
        seen.push(cur.clone());
        for (t, _) in &graph.nodes[&cur].edges {
            if graph.nodes.contains_key(t) && !seen.contains(t) {
                stack.push(t.clone());
            }
        }
    }
    seen
}

#[derive(Debug, Clone)]
pub struct Violation {
    pub node: String,
    pub target: String,
    pub condition: String,
}

/// Every semantic edge on a reachable node — empty means the flow is in the portable subset.
pub fn portability_violations(graph: &Graph) -> Vec<Violation> {
    let mut names = reachable(graph);
    names.sort();
    let mut out = Vec::new();
    for name in names {
        let Some(node) = graph.nodes.get(&name) else { continue };
        for (t, c) in &node.edges {
            if is_semantic(c) {
                out.push(Violation { node: name.clone(), target: t.clone(), condition: c.clone() });
            }
        }
    }
    out
}

// -------------------------------------------------------------------------- the engine

/// Python `str()` for the JSON value kinds a worker can return — differential fuzzing showed
/// naive stringification diverges on exactly the values that then ROUTE differently:
/// true -> "True" (not "true"), null -> "None", [1,2] -> "[1, 2]".
pub fn py_str(v: &V) -> String {
    match v {
        V::Bool(true) => "True".to_string(),
        V::Bool(false) => "False".to_string(),
        V::Null => "None".to_string(),
        V::Str(s) => s.clone(),
        V::List(a) => {
            let inner: Vec<String> = a.iter().map(py_repr).collect();
            format!("[{}]", inner.join(", "))
        }
        V::Obj(o) => {
            let inner: Vec<String> =
                o.iter().map(|(k, x)| format!("'{}': {}", k, py_repr(x))).collect();
            format!("{{{}}}", inner.join(", "))
        }
        V::Num(n) => js_number_string(*n),
        V::Ellipsis => "Ellipsis".to_string(), // never reachable from worker outcomes
    }
}

fn py_repr(v: &V) -> String {
    match v {
        V::Str(s) => format!("'{s}'"),
        _ => py_str(v),
    }
}

/// JS `String(number)`: no trailing ".0" on integral values; exponent form only past 1e21.
/// (The reference notes floats that JSON collapses to integers are inherently ambiguous
/// cross-language "and stay as JS renders them" — so JS rendering is the contract.)
fn js_number_string(n: f64) -> String {
    if n.is_nan() {
        return "NaN".to_string();
    }
    if n.is_infinite() {
        return if n > 0.0 { "Infinity" } else { "-Infinity" }.to_string();
    }
    if n.fract() == 0.0 && n.abs() < 1e21 {
        return format!("{}", n as i128);
    }
    if n.abs() >= 1e21 {
        // JS switches to exponential with an explicit '+': 1e21 -> "1e+21"
        let s = format!("{n:e}");
        return if s.contains("e-") { s } else { s.replace('e', "e+") };
    }
    format!("{n}")
}

/// `str(outcome.get("text", ""))` + the fields dict — a PRESENT-but-null text is "None",
/// an absent one is "".
fn normalize(outcome: &V) -> (String, Vec<(String, V)>) {
    if let V::Obj(entries) = outcome {
        let text = match V::obj_get(entries, "text") {
            Some(t) => py_str(t),
            None => String::new(),
        };
        return (text, entries.clone());
    }
    let t = py_str(outcome);
    (t.clone(), vec![("text".to_string(), V::Str(t))])
}

/// First matching deterministic edge, document order. An unsafe/unparseable predicate is
/// non-matching, never a crash.
pub fn first_deterministic<'a>(
    edges: &'a [(String, String)],
    ctx: &HashMap<String, V>,
) -> Option<(&'a str, &'a str)> {
    for (t, c) in edges {
        if !is_deterministic(c) {
            continue;
        }
        if let Ok(true) = eval_condition(c, ctx) {
            return Some((t, c));
        }
    }
    None
}

/// The resume target for a delivered event ('__timeout__' for a timeout). None if the node has
/// no such edge.
pub fn event_target<'a>(graph: &'a Graph, node: &str, event: &str) -> Option<&'a str> {
    let n = graph.nodes.get(node)?;
    for (t, c) in &n.edges {
        if is_event(c) && event_name(c) == event {
            return Some(t);
        }
    }
    None
}

#[derive(Debug, Clone, Default)]
pub struct RunState {
    pub visits: HashMap<String, i64>,
    pub transcript: Vec<V>,
    pub errors: HashMap<String, i64>,
    pub outcomes: HashMap<String, Vec<(String, V)>>,
    /// Host-supplied state fields the engine itself never reads, carried through untouched.
    pub extra: HashMap<String, V>,
}

impl RunState {
    /// Ingest a host-provided initial state (the `state` option): `visits` and `transcript` are
    /// the engine's own fields and are adopted; everything else rides along in `extra`.
    pub fn from_v(v: &V) -> RunState {
        let mut st = RunState::default();
        if let V::Obj(entries) = v {
            for (k, val) in entries {
                match (k.as_str(), val) {
                    ("visits", V::Obj(vs)) => {
                        for (node, count) in vs {
                            if let Some(n) = as_num(count) {
                                st.visits.insert(node.clone(), n as i64);
                            }
                        }
                    }
                    ("transcript", V::List(items)) => st.transcript = items.clone(),
                    _ => {
                        st.extra.insert(k.clone(), val.clone());
                    }
                }
            }
        }
        st
    }
}

#[derive(Debug, Clone)]
pub struct Pending {
    pub node: String,
    pub wait: bool,
    pub reason: Option<String>,
    pub awaiting: Vec<String>,
    pub timeout_s: Option<V>,
    pub candidates: Vec<(String, String)>,
    pub spawn: Option<V>,
    pub would_pick: Option<String>,
    pub scored_candidates: Option<Vec<(String, String, f64)>>,
}

#[derive(Debug, Clone)]
pub struct Step {
    pub node: String,
    pub outcome: String,
    pub target: String,
    pub used: String,
    pub cond: Option<String>,
    pub score: Option<f64>,
    pub margin: Option<f64>,
    pub sims: Option<HashMap<String, f64>>,
    pub locked: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct RunResult {
    pub path: Vec<String>,
    pub steps: Vec<Step>,
    pub stopped: String,
    pub pending: Option<Pending>,
    pub state: RunState,
}

#[derive(Debug, Clone)]
pub enum EngineError {
    /// A reachable semantic edge: the flow needs the embedding/LLM tier and this kernel REFUSES
    /// to guess at it (mirroring the reference's up-front rejection).
    NotPortable(Violation),
    /// The agent raised and no error edge on the node matched — the error propagates.
    Unhandled(String),
    /// A route led to a node the document does not define. The JS kernel crashes here
    /// (`graph.nodes[node]` is undefined); an explicit error is the Rust spelling of that.
    MissingNode(String),
    /// A semantic condition is not covered by the lockfile.
    LockMissing(String),
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineError::NotPortable(v) => write!(
                f,
                "flow is not portable: semantic edge [{}] -> {} ({:?}) needs the embedding/LLM \
                 tier — run it on the Python engine, or rewrite the edge as a `when` predicate",
                v.node, v.target, v.condition
            ),
            EngineError::Unhandled(msg) => write!(f, "{msg}"),
            EngineError::MissingNode(n) => write!(f, "flow routes to undefined node {n:?}"),
            EngineError::LockMissing(c) => write!(
                f,
                "condition not in lock: {c:?} \u{2014} the flow changed; re-run `prismpath lock`"
            ),
        }
    }
}
impl std::error::Error for EngineError {}

pub struct RunOpts {
    pub max_steps: usize,
    pub start: Option<String>,
    pub state: Option<V>,
    pub human_floor: Option<f64>,
}

impl Default for RunOpts {
    fn default() -> Self {
        RunOpts { max_steps: 25, start: None, state: None, human_floor: None }
    }
}

// ----------------------------------------------------------------- P1: locked routing

#[derive(Debug, Clone)]
pub struct CentroidPin {
    pub vec: Vec<f32>,
    pub n: usize,
}

#[derive(Debug, Clone)]
pub struct Lock {
    pub conditions: HashMap<String, Vec<f32>>,
    pub centroids: Option<HashMap<String, CentroidPin>>,
    pub dim: usize,
}

impl Lock {
    pub fn condition_vec(&self, condition: &str) -> Option<&[f32]> {
        self.centroids
            .as_ref()
            .and_then(|c| c.get(condition).map(|p| p.vec.as_slice()))
            .or_else(|| self.conditions.get(condition).map(|v| v.as_slice()))
    }

    pub fn from_json(v: &serde_json::Value) -> Result<Lock, String> {
        let obj = v.as_object().ok_or("lock must be an object")?;
        let dim = obj
            .get("embedder")
            .and_then(|e| e.get("dim"))
            .and_then(|d| d.as_u64())
            .ok_or("lock.embedder.dim is required")? as usize;

        let conds_obj = obj
            .get("conditions")
            .and_then(|c| c.as_object())
            .ok_or("lock.conditions is required")?;
        let mut conditions = HashMap::new();
        for (k, val) in conds_obj {
            let b64 = val.as_str().ok_or_else(|| format!("condition {k:?}: expected base64 string"))?;
            conditions.insert(k.clone(), decode_b64_f32(b64)?);
        }

        let centroids = if let Some(cen_val) = obj.get("centroids") {
            let cen_obj = cen_val.as_object().ok_or("lock.centroids must be an object")?;
            let mut map = HashMap::new();
            for (k, val) in cen_obj {
                let pin_obj = val.as_object().ok_or_else(|| format!("centroid {k:?}: expected object"))?;
                let vec_b64 = pin_obj
                    .get("vec")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| format!("centroid {k:?}: missing vec"))?;
                let n = pin_obj.get("n").and_then(|n| n.as_u64()).unwrap_or(1) as usize;
                map.insert(k.clone(), CentroidPin { vec: decode_b64_f32(vec_b64)?, n });
            }
            Some(map)
        } else {
            None
        };

        Ok(Lock { conditions, centroids, dim })
    }
}

pub fn decode_b64_f32(b64: &str) -> Result<Vec<f32>, String> {
    const LUT: [u8; 256] = {
        let mut t = [255u8; 256];
        let mut i = 0u8;
        while i < 26 { t[(b'A' + i) as usize] = i; i += 1; }
        i = 0;
        while i < 26 { t[(b'a' + i) as usize] = 26 + i; i += 1; }
        i = 0;
        while i < 10 { t[(b'0' + i) as usize] = 52 + i; i += 1; }
        t[b'+' as usize] = 62;
        t[b'/' as usize] = 63;
        t
    };
    let input = b64.as_bytes();
    let len = input.len();
    let pad = if len >= 2 && input[len - 1] == b'=' {
        if input[len - 2] == b'=' { 2 } else { 1 }
    } else {
        0
    };
    let out_len = len / 4 * 3 - pad;
    let mut bytes = Vec::with_capacity(out_len);
    let mut i = 0;
    while i + 3 < len {
        let (a, b, c, d) = (LUT[input[i] as usize], LUT[input[i + 1] as usize],
                            LUT[input[i + 2] as usize], LUT[input[i + 3] as usize]);
        bytes.push((a << 2) | (b >> 4));
        if bytes.len() < out_len { bytes.push((b << 4) | (c >> 2)); }
        if bytes.len() < out_len { bytes.push((c << 6) | d); }
        i += 4;
    }
    if bytes.len() % 4 != 0 {
        return Err(format!("base64 decoded to {} bytes, not a multiple of 4 (f32)", bytes.len()));
    }
    let floats: Vec<f32> = bytes
        .chunks_exact(4)
        .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect();
    Ok(floats)
}

fn cosine_sim(a: &[f32], b: &[f32]) -> f64 {
    a.iter().zip(b).map(|(x, y)| (*x as f64) * (*y as f64)).sum()
}

/// One locked-routing decision. Public for consumers building suggestion layers — parity with
/// the Python reference's standalone `lockfile.locked_router` surface.
#[derive(Debug, Clone)]
pub struct RouteDecision {
    pub target: String,
    pub score: f64,
    pub margin: f64,
    pub sims: HashMap<String, f64>,
}

/// Route one text against a node's semantic edges using the lock's pinned vectors — the
/// single-step form of what `run_locked` does per step. EXPORTED for suggestion-layer
/// consumers; behavior unchanged (the engine calls this internally).
pub fn locked_route(
    text: &str,
    sem_edges: &[(String, String)],
    lock: &Lock,
    embed: &mut dyn FnMut(&str) -> Vec<f32>,
) -> Result<RouteDecision, EngineError> {
    let query_vec = embed(text);
    let mut scores = Vec::with_capacity(sem_edges.len());
    let mut sims_map = HashMap::new();
    for (t, c) in sem_edges {
        let cond_vec = lock
            .condition_vec(c)
            .ok_or_else(|| EngineError::LockMissing(c.clone()))?;
        let sim = cosine_sim(&query_vec, cond_vec);
        scores.push(sim);
        sims_map.insert(t.clone(), sim);
    }
    let mut order: Vec<usize> = (0..scores.len()).collect();
    order.sort_by(|a, b| scores[*b].partial_cmp(&scores[*a]).unwrap_or(std::cmp::Ordering::Equal));
    let top1 = order[0];
    let margin = if order.len() > 1 { scores[order[0]] - scores[order[1]] } else { 1.0 };
    Ok(RouteDecision {
        target: sem_edges[top1].0.clone(),
        score: scores[top1],
        margin,
        sims: sims_map,
    })
}

// -------------------------------------------------------------------------- the engine

/// JS truthiness — used in exactly one reference spot (`fields.reason || text`), where the
/// semantics genuinely are JS's and not Python's: [] and {} are TRUTHY here.
fn js_truthy(v: &V) -> bool {
    match v {
        V::Null => false,
        V::Bool(b) => *b,
        V::Num(n) => *n != 0.0 && !n.is_nan(),
        V::Str(s) => !s.is_empty(),
        V::List(_) | V::Obj(_) | V::Ellipsis => true,
    }
}

/// Run a PORTABLE flow — a faithful port of the reference `run` for the ML-free subset.
///
/// `agent(node, instruction, state)` returns a worker outcome (`Ok`) or raises (`Err`) — the Err
/// arm feeds the error tier exactly like a thrown exception does in the reference. Returns
/// `{path, steps, stopped, state, pending}`; REFUSES a non-portable flow up front.
pub fn run<F>(graph: &Graph, agent: F, opts: RunOpts) -> Result<RunResult, EngineError>
where
    F: FnMut(&str, &str, &RunState) -> Result<V, String>,
{
    run_observed(graph, agent, opts, |_, _, _| {})
}

/// `run` with the reference's `onStep` hook: called at every checkpoint the .mjs kernel calls its
/// `checkpoint()` — before each worker, and at terminal / needs_human / waiting / stuck.
///
/// This is the OBSERVATION SEAM, and it is deliberately part of the kernel's public surface on
/// both implementations: telemetry, audit trails, progress UIs and the like belong to the HOST,
/// watching through this hook — never inside the kernel, where a capability grown on one
/// implementation and not the other would quietly fork the spec the conformance corpus froze.
pub fn run_observed<F, O>(
    graph: &Graph,
    mut agent: F,
    opts: RunOpts,
    on_step: O,
) -> Result<RunResult, EngineError>
where
    F: FnMut(&str, &str, &RunState) -> Result<V, String>,
    O: FnMut(&RunResult, &RunState, Option<&str>),
{
    run_core(graph, &mut agent, None, opts, on_step)
}

/// Run a P1 flow: semantic edges are allowed if `lock` covers them. The `embed` callback
/// produces a unit-normalized vector for the worker's outcome text; cosine similarity against
/// the lock's pre-baked condition vectors picks the route.
pub fn run_locked<F, E>(
    graph: &Graph,
    agent: F,
    embed: E,
    lock: &Lock,
    opts: RunOpts,
) -> Result<RunResult, EngineError>
where
    F: FnMut(&str, &str, &RunState) -> Result<V, String>,
    E: FnMut(&str) -> Vec<f32>,
{
    run_locked_observed(graph, agent, embed, lock, opts, |_, _, _| {})
}

/// `run_locked` with the observation seam.
pub fn run_locked_observed<F, E, O>(
    graph: &Graph,
    mut agent: F,
    mut embed: E,
    lock: &Lock,
    opts: RunOpts,
    on_step: O,
) -> Result<RunResult, EngineError>
where
    F: FnMut(&str, &str, &RunState) -> Result<V, String>,
    E: FnMut(&str) -> Vec<f32>,
    O: FnMut(&RunResult, &RunState, Option<&str>),
{
    run_core(graph, &mut agent, Some((lock, &mut embed as &mut dyn FnMut(&str) -> Vec<f32>)), opts, on_step)
}

fn run_core<F, O>(
    graph: &Graph,
    agent: &mut F,
    mut semantic_ctx: Option<(&Lock, &mut dyn FnMut(&str) -> Vec<f32>)>,
    opts: RunOpts,
    mut on_step: O,
) -> Result<RunResult, EngineError>
where
    F: FnMut(&str, &str, &RunState) -> Result<V, String>,
    O: FnMut(&RunResult, &RunState, Option<&str>),
{
    let violations = portability_violations(graph);
    if !violations.is_empty() {
        if let Some((ref lock, _)) = semantic_ctx {
            for v in &violations {
                if lock.condition_vec(&v.condition).is_none() {
                    return Err(EngineError::LockMissing(v.condition.clone()));
                }
            }
        } else {
            return Err(EngineError::NotPortable(
                violations.into_iter().next().expect("violations non-empty (checked above)"),
            ));
        }
    }

    let mut node = opts.start.clone().unwrap_or_else(|| graph.start.clone());
    let mut state = match &opts.state {
        Some(v) => RunState::from_v(v),
        None => RunState::default(),
    };
    let mut res = RunResult { path: vec![node.clone()], ..Default::default() };

    for _step in 0..opts.max_steps {
        let n = graph
            .nodes
            .get(&node)
            .ok_or_else(|| EngineError::MissingNode(node.clone()))?
            .clone();

        if n.edges.is_empty() {
            res.stopped = "terminal".to_string(); // a node with no edges is terminal
            on_step(&res, &state, None);
            break;
        }
        on_step(&res, &state, Some(&node));
        *state.visits.entry(node.clone()).or_insert(0) += 1;

        let outcome = match agent(&node, &n.instruction, &state) {
            Ok(o) => o,
            Err(msg) => {
                // ------------------------------------------------------------- error tier
                let count = {
                    let c = state.errors.entry(node.clone()).or_insert(0);
                    *c += 1;
                    *c
                };
                // error_type is "Error" — what a scripted throw's constructor is named in the
                // certified JS port. The corpus never routes on the type name (it could not:
                // Python and JS already disagree about it).
                let err_ctx: HashMap<String, V> = [
                    ("error".to_string(), V::Bool(true)),
                    ("error_type".to_string(), V::Str("Error".to_string())),
                    ("error_message".to_string(), V::Str(msg.clone())),
                    ("error_count".to_string(), V::Num(count as f64)),
                    ("visits".to_string(), V::Num(state.visits[&node] as f64)),
                ]
                .into_iter()
                .collect();

                let mut etarget: Option<&str> = None;
                for (t, c) in &n.edges {
                    if !is_error(c) {
                        continue;
                    }
                    let expr = error_expr(c);
                    if expr.is_empty() {
                        etarget = Some(t);
                        break;
                    }
                    if let Ok(true) = eval_condition(&expr, &err_ctx) {
                        etarget = Some(t);
                        break;
                    }
                }
                let Some(etarget) = etarget else {
                    return Err(EngineError::Unhandled(msg)); // no handler -> propagate
                };
                let etext = format!("[error: Error: {msg}]");
                state.transcript.push(V::Obj(vec![
                    ("node".to_string(), V::Str(node.clone())),
                    ("outcome".to_string(), V::Str(etext.clone())),
                    ("error".to_string(), V::Bool(true)),
                ]));
                res.steps.push(Step {
                    node: node.clone(),
                    outcome: etext,
                    target: etarget.to_string(),
                    used: "error".to_string(),
                    cond: None, score: None, margin: None, sims: None, locked: None,
                });
                node = etarget.to_string();
                res.path.push(node.clone());
                continue;
            }
        };

        let (text, fields) = normalize(&outcome);
        state.transcript.push(V::Obj(vec![
            ("node".to_string(), V::Str(node.clone())),
            ("outcome".to_string(), V::Str(text.clone())),
        ]));
        state.outcomes.insert(node.clone(), fields.clone());

        // ------------------------------------------------------------------ human handoff
        if V::obj_get(&fields, "needs_human").is_some_and(py_truthy) {
            res.stopped = "needs_human".to_string();
            let reason = match V::obj_get(&fields, "reason") {
                Some(r) if js_truthy(r) => py_str(r), // JS `||`: falsy reason falls back to text
                _ => text.clone(),
            };
            res.pending = Some(Pending {
                node: node.clone(),
                wait: false,
                reason: Some(reason),
                awaiting: Vec::new(),
                timeout_s: None,
                candidates: n.edges.clone(),
                spawn: None,
                would_pick: None,
                scored_candidates: None,
            });
            on_step(&res, &state, Some(&node));
            break;
        }

        // ----------------------------------------------------------- wait / fan-out suspend
        let spawn = V::obj_get(&fields, "spawn").filter(|v| !matches!(v, V::Null)); // JS `!= null`
        if V::obj_get(&fields, "wait").is_some_and(py_truthy) || spawn.is_some() {
            let events: Vec<&(String, String)> =
                n.edges.iter().filter(|(_, c)| is_event(c)).collect();
            res.stopped = "waiting".to_string();
            res.pending = Some(Pending {
                node: node.clone(),
                wait: true,
                reason: None,
                awaiting: events.iter().map(|(_, c)| event_name(c)).collect(),
                timeout_s: V::obj_get(&fields, "timeout_s").cloned(),
                candidates: events.iter().map(|e| (*e).clone()).collect(),
                spawn: spawn.cloned(),
                would_pick: None,
                scored_candidates: None,
            });
            on_step(&res, &state, Some(&node));
            break;
        }

        // -------------------------------------------------------------------- routing
        let mut ctx: HashMap<String, V> = fields.iter().cloned().collect();
        ctx.insert("visits".to_string(), V::Num(state.visits[&node] as f64));

        let mut target: Option<String> = None;
        let mut step_used = String::new();
        let mut step_cond: Option<String> = None;
        let mut step_score: Option<f64> = None;
        let mut step_margin: Option<f64> = None;
        let mut step_sims: Option<HashMap<String, f64>> = None;
        let mut step_locked: Option<bool> = None;

        if let Some((dt, dc)) = first_deterministic(&n.edges, &ctx) {
            target = Some(dt.to_string());
            step_used = format!("deterministic: {dc}");
            step_cond = Some(dc.to_string());
        }

        if target.is_none() {
            if let Some((ref lock, ref mut embed_fn)) = semantic_ctx {
                let sem: Vec<(String, String)> = n.edges.iter()
                    .filter(|(_, c)| is_semantic(c))
                    .cloned()
                    .collect();
                if !sem.is_empty() {
                    let d = locked_route(&text, &sem, lock, *embed_fn)?;
                    if let Some(floor) = opts.human_floor {
                        if d.score < floor {
                            res.stopped = "needs_human".to_string();
                            res.pending = Some(Pending {
                                node: node.clone(),
                                wait: false,
                                reason: Some(format!(
                                    "router confidence {:.3} < human_floor {floor}",
                                    d.score
                                )),
                                awaiting: Vec::new(),
                                timeout_s: None,
                                candidates: sem.clone(),
                                spawn: None,
                                would_pick: Some(d.target.clone()),
                                scored_candidates: Some(
                                    sem.iter()
                                        .map(|(t, c)| {
                                            let s = d.sims.get(t).copied().unwrap_or(0.0);
                                            (t.clone(), c.clone(), s)
                                        })
                                        .collect(),
                                ),
                            });
                            on_step(&res, &state, Some(&node));
                            break;
                        }
                    }
                    target = Some(d.target);
                    step_used = "locked".to_string();
                    step_score = Some(d.score);
                    step_margin = Some(d.margin);
                    step_sims = Some(d.sims);
                    step_locked = Some(true);
                }
            }
        }

        let Some(tgt) = target else {
            res.stopped = "stuck".to_string();
            on_step(&res, &state, None);
            break;
        };
        res.steps.push(Step {
            node: node.clone(),
            outcome: text,
            target: tgt.clone(),
            used: step_used,
            cond: step_cond,
            score: step_score,
            margin: step_margin,
            sims: step_sims,
            locked: step_locked,
        });
        node = tgt;
        res.path.push(node.clone());
    }

    if res.stopped.is_empty() {
        res.stopped = "max_steps".to_string();
    }
    res.state = state;
    Ok(res)
}

// ------------------------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(pairs: &[(&str, V)]) -> HashMap<String, V> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    #[test]
    fn locked_route_exported_matches_the_frozen_p1_fixture() {
        // The exported single-step surface must give the same decision run_locked gives per
        // step — parity with the JS export test and with the Python reference's standalone
        // locked_router. Driven off the frozen P1 corpus so the answer is spec-pinned.
        let raw = std::fs::read_to_string("../prismpath/portable/conformance/locked_flows.json")
            .expect("locked_flows.json");
        let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let cases = doc["cases"].as_array().unwrap();
        let fx = cases
            .iter()
            .find(|c| c["name"] == "locked_basic_route")
            .unwrap_or(&cases[0]);
        let graph = parse(fx["flow"].as_str().unwrap());
        let lock = Lock::from_json(&fx["lock"]).unwrap();
        let start = fx.get("start").and_then(|s| s.as_str()).unwrap_or(&graph.start).to_string();
        let sem_edges: Vec<(String, String)> = graph.nodes[&start]
            .edges
            .iter()
            .filter(|(_, c)| is_semantic(c))
            .cloned()
            .collect();
        let embed_map = fx["embedMap"].as_object().cloned().unwrap_or_default();
        let dim = lock.dim;
        let text = embed_map.keys().next().cloned().unwrap_or_default();
        let mut embed = |s: &str| -> Vec<f32> {
            embed_map
                .get(s)
                .and_then(|v| v.as_str())
                .map(|b64| decode_b64_f32(b64).unwrap())
                .unwrap_or_else(|| vec![0.0f32; dim])
        };
        let d = locked_route(&text, &sem_edges, &lock, &mut embed).unwrap();
        let expected_target = fx["expect"]["path"][1].as_str().unwrap();
        assert_eq!(d.target, expected_target);
        assert!(d.score > 0.0);
    }

    #[test]
    fn chained_comparison_and_membership() {
        let c = ctx(&[("x", V::Num(3.0))]);
        assert!(eval_condition("when 1 < x < 5", &c).unwrap());
        assert!(!eval_condition("when 1 < x < 3", &c).unwrap());
        let c = ctx(&[("a", V::Str("watch".into()))]);
        assert!(eval_condition("when a in (\"contain\", \"watch\")", &c).unwrap());
        assert!(eval_condition("when a not in [\"contain\"]", &c).unwrap());
    }

    #[test]
    fn python_constants_vs_field_names() {
        // `True` is the constant; lowercase `true` reads ctx["true"]
        let c = ctx(&[("x", V::Bool(true))]);
        assert!(eval_condition("when x == True", &c).unwrap());
        // both missing -> None == None -> true (the documented trap the fixtures guard against)
        assert!(eval_condition("when x == true", &ctx(&[])).unwrap());
    }

    #[test]
    fn eval_never_panics_on_adversarial_input() {
        // SECURITY.md §1: eval_condition must never CRASH — only Ok/Err(PredicateError). The same
        // tokenizer/parser backs check_predicate and is_deterministic, so all three must be total.
        let c = ctx(&[("x", V::Num(3.0)), ("s", V::Str("hi".into()))]);
        let nasty = [
            "", "when", "when ", "when (", "when )))", "when 1 <", "when < 3", "when x ==",
            "when \"\\x\"", "when \"\\u12\"", "when \"\\", "when 0x", "when 0o", "when 0b",
            "when 1 < x < < 5", "when x in", "when x not", "when and or not",
            "when 999999999999999999999999999 > x", "when x == 'unterminated", "when \\uffffffff",
            "when x in in in", "when 1j > 0", "when x.y.z == 1", "when [1,2,3] == x",
            "when x == \"\\U0001F600\"", "when x == \"\\uD800\"",
        ];
        for cond in nasty {
            let _ = eval_condition(cond, &c); // must return, never panic
            let _ = check_predicate(cond);
            let _ = is_deterministic(cond);
        }
        // deep nesting is bounded by MAX_DEPTH -> a clean error, not a stack overflow.
        let deep = format!("when {}x{}", "(".repeat(500), ")".repeat(500));
        assert!(eval_condition(&deep, &c).is_err());
    }

    #[test]
    fn booleans_compare_numerically() {
        let c = ctx(&[("flag", V::Bool(true))]);
        assert!(eval_condition("when flag == 1", &c).unwrap());
    }

    #[test]
    fn keywords_and_disallowed_syntax_are_errors() {
        for cond in ["when class == \"phish\"", "when f(x)", "when x + 1 > 2", "when -1 < x"] {
            assert!(eval_condition(cond, &ctx(&[])).is_err(), "{cond} must be a PredicateError");
        }
    }

    #[test]
    fn failed_comparisons_are_unsatisfied_not_crashes() {
        let c = ctx(&[("x", V::Str("s".into()))]);
        assert!(!eval_condition("when x > 3", &c).unwrap()); // type mismatch
        assert!(!eval_condition("when missing > 3", &c).unwrap()); // absent field
        assert!(eval_condition("when x not in 3", &c).unwrap()); // failure satisfies `not in`
    }

    #[test]
    fn flow_runs_to_terminal() {
        let g = parse("---\nname: t\nstart: a\n---\n\n## a\nDo a.\n-> b: when ok\n\n## b\nDone.\n");
        let res = run(
            &g,
            |_, _, _| {
                Ok(V::Obj(vec![
                    ("ok".into(), V::Bool(true)),
                    ("text".into(), V::Str("x".into())),
                ]))
            },
            RunOpts::default(),
        )
        .unwrap();
        assert_eq!(res.path, vec!["a", "b"]);
        assert_eq!(res.stopped, "terminal");
    }

    #[test]
    fn max_steps_protects_against_loops() {
        let g = parse("## a\n-> a: always\n");
        let res = run(&g, |_, _, _| Ok(V::Str("t".into())), RunOpts::default()).unwrap();
        assert_eq!(res.stopped, "max_steps");
        assert_eq!(res.path.len(), 26); // start + 25 steps
    }

    #[test]
    fn semantic_edge_is_refused_up_front() {
        let g = parse("## a\n-> b: the answer looks correct\n\n## b\nDone.\n");
        assert!(matches!(
            run(&g, |_, _, _| Ok(V::Null), RunOpts::default()),
            Err(EngineError::NotPortable(_))
        ));
    }

    #[test]
    fn locked_routing_picks_closest_condition() {
        let g = parse("## a\nClassify.\n\n-> b: positive\n-> c: negative\n\n## b\nB.\n\n## c\nC.\n");
        let mut conds = HashMap::new();
        conds.insert("positive".to_string(), vec![1.0f32, 0.0, 0.0, 0.0]);
        conds.insert("negative".to_string(), vec![0.0, 1.0, 0.0, 0.0]);
        let lock = Lock { conditions: conds, centroids: None, dim: 4 };
        let res = run_locked(
            &g,
            |_, _, _| Ok(V::Obj(vec![("text".to_string(), V::Str("great".into()))])),
            |_text| vec![0.99f32, 0.11, 0.0, 0.0],
            &lock,
            RunOpts::default(),
        ).unwrap();
        assert_eq!(res.path, vec!["a", "b"]);
        assert_eq!(res.stopped, "terminal");
        assert_eq!(res.steps[0].used, "locked");
        assert!(res.steps[0].score.unwrap() > 0.9);
    }

    #[test]
    fn locked_routing_human_floor_suspends() {
        let g = parse("## a\nClassify.\n\n-> b: positive\n-> c: negative\n\n## b\nB.\n\n## c\nC.\n");
        let mut conds = HashMap::new();
        conds.insert("positive".to_string(), vec![1.0f32, 0.0, 0.0, 0.0]);
        conds.insert("negative".to_string(), vec![0.0, 1.0, 0.0, 0.0]);
        let lock = Lock { conditions: conds, centroids: None, dim: 4 };
        let res = run_locked(
            &g,
            |_, _, _| Ok(V::Obj(vec![("text".to_string(), V::Str("ambiguous".into()))])),
            |_text| vec![0.72f32, 0.69, 0.0, 0.07],
            &lock,
            RunOpts { human_floor: Some(0.99), ..Default::default() },
        ).unwrap();
        assert_eq!(res.stopped, "needs_human");
        assert_eq!(res.pending.as_ref().unwrap().would_pick.as_deref(), Some("b"));
    }

    #[test]
    fn locked_routing_deterministic_takes_priority() {
        let g = parse("## a\nRoute.\n\n-> b: when x == 1\n-> c: semantic edge\n\n## b\nB.\n\n## c\nC.\n");
        let mut conds = HashMap::new();
        conds.insert("semantic edge".to_string(), vec![0.0, 0.0, 1.0, 0.0]);
        let lock = Lock { conditions: conds, centroids: None, dim: 4 };
        let res = run_locked(
            &g,
            |_, _, _| Ok(V::Obj(vec![
                ("text".to_string(), V::Str("go".into())),
                ("x".to_string(), V::Num(1.0)),
            ])),
            |_text| vec![0.0, 0.0, 0.9, 0.0],
            &lock,
            RunOpts::default(),
        ).unwrap();
        assert_eq!(res.path, vec!["a", "b"]);
        assert!(res.steps[0].used.starts_with("deterministic"));
    }

    #[test]
    fn lock_missing_condition_is_caught() {
        let g = parse("## a\nDo.\n\n-> b: foo\n-> c: bar\n\n## b\nB.\n\n## c\nC.\n");
        let mut conds = HashMap::new();
        conds.insert("foo".to_string(), vec![1.0, 0.0, 0.0, 0.0]);
        // "bar" is missing from the lock
        let lock = Lock { conditions: conds, centroids: None, dim: 4 };
        let res = run_locked(
            &g,
            |_, _, _| Ok(V::Null),
            |_| vec![1.0, 0.0, 0.0, 0.0],
            &lock,
            RunOpts::default(),
        );
        assert!(matches!(res, Err(EngineError::LockMissing(_))));
    }

    #[test]
    fn centroid_overrides_condition_vector() {
        let g = parse("## a\nClassify.\n\n-> b: positive\n-> c: negative\n\n## b\nB.\n\n## c\nC.\n");
        let mut conds = HashMap::new();
        conds.insert("positive".to_string(), vec![1.0, 0.0, 0.0, 0.0]);
        conds.insert("negative".to_string(), vec![0.0, 1.0, 0.0, 0.0]);
        let mut centroids = HashMap::new();
        // Centroid overrides "positive" to point toward the negative direction
        centroids.insert("positive".to_string(), CentroidPin {
            vec: vec![0.0, 1.0, 0.0, 0.0], n: 5,
        });
        let lock = Lock { conditions: conds, centroids: Some(centroids), dim: 4 };
        let res = run_locked(
            &g,
            |_, _, _| Ok(V::Obj(vec![("text".to_string(), V::Str("test".into()))])),
            |_| vec![0.0, 0.99, 0.0, 0.1],
            &lock,
            RunOpts::default(),
        ).unwrap();
        // Both "positive" (via centroid) and "negative" point at [0,1,0,0], so either could win.
        // With the centroid override, "positive" has the SAME vector as "negative", so the first
        // in document order wins when margin is 0 (argsort is stable in Rust's sort_by).
        assert_eq!(res.path[1], "b"); // "positive" is first in doc order
    }

    #[test]
    fn decode_b64_f32_roundtrip() {
        let original = vec![1.0f32, 0.0, -0.5, 3.5]; // arbitrary f32s; avoid 3.14 (clippy reads it as PI)
        let b64 = {
            let bytes: Vec<u8> = original.iter().flat_map(|f| f.to_le_bytes()).collect();
            const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut out = String::new();
            for chunk in bytes.chunks(3) {
                let (b0, b1, b2) = (chunk[0] as u32,
                    *chunk.get(1).unwrap_or(&0) as u32,
                    *chunk.get(2).unwrap_or(&0) as u32);
                let n = (b0 << 16) | (b1 << 8) | b2;
                out.push(CHARS[((n >> 18) & 63) as usize] as char);
                out.push(CHARS[((n >> 12) & 63) as usize] as char);
                if chunk.len() > 1 { out.push(CHARS[((n >> 6) & 63) as usize] as char); }
                else { out.push('='); }
                if chunk.len() > 2 { out.push(CHARS[(n & 63) as usize] as char); }
                else { out.push('='); }
            }
            out
        };
        let decoded = decode_b64_f32(&b64).unwrap();
        assert_eq!(decoded.len(), original.len());
        for (a, b) in decoded.iter().zip(&original) {
            assert!((a - b).abs() < 1e-6, "{a} != {b}");
        }
    }
}
