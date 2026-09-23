// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Decision-preserving quantizer — the differentiator.

use prismpath_rs::{Graph, V};
use std::collections::HashMap;

pub const OTHER: &str = "\x00__other__";

const ALWAYS: &[&str] = &["always", "true", "else", "otherwise", "default", "_"];
const NEVER: &[&str] = &["false", "never"];

#[derive(Debug, Clone, PartialEq)]
pub enum AtomConst {
    None,
    Bool(bool),
    Num(i64),
    Str(String),
    List(Vec<AtomConst>),
}

impl AtomConst {
    pub fn is_str(&self) -> bool {
        match self {
            AtomConst::Str(_) => true,
            AtomConst::List(members) => members.iter().any(|member| member.is_str()),
            _ => false,
        }
    }

    pub fn is_bool(&self) -> bool {
        match self {
            AtomConst::Bool(_) => true,
            AtomConst::List(members) => members.iter().any(|member| member.is_bool()),
            _ => false,
        }
    }

    pub fn is_num(&self) -> bool {
        match self {
            AtomConst::Num(_) => true,
            AtomConst::List(members) => members.iter().any(|member| member.is_num()),
            _ => false,
        }
    }

    pub fn flat_consts(&self) -> Vec<AtomConst> {
        match self {
            AtomConst::List(members) => members.clone(),
            single => vec![single.clone()],
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Atom {
    pub field: String,
    pub op: String, // "<", "<=", ">", ">=", "==", "!=", "in", "not in", "truthy"
    pub const_val: AtomConst,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FieldKind {
    Numeric,
    Boolean,
    Categorical,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Cell {
    pub lo: Option<i64>,
    pub hi: Option<i64>,
    pub const_val: Option<String>,
    pub rep: V,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FieldPartition {
    pub field: String,
    pub kind: FieldKind,
    pub cells: Vec<Cell>,
    pub n: usize,
}

impl FieldPartition {
    pub fn new(field: String, kind: FieldKind, cells: Vec<Cell>) -> Self {
        let n = cells.len();
        FieldPartition { field, kind, cells, n }
    }

    /// The cell index a value falls in. `Err` only for a value outside every cell of a numeric
    /// partition — unreachable for partitions built by `build_partitions` (open ends), but a
    /// hand-constructed partition can bound both ends, and a library consumer (e.g. a Vector
    /// codec) must never be able to panic the encoder.
    pub fn symbol(&self, value: &V) -> Result<usize, String> {
        match self.kind {
            FieldKind::Numeric => {
                let number = v_to_i64(value)?;
                for (index, cell) in self.cells.iter().enumerate() {
                    let lo_ok = cell.lo.is_none_or(|low| number >= low);
                    let hi_ok = cell.hi.is_none_or(|high| number <= high);
                    if lo_ok && hi_ok {
                        return Ok(index);
                    }
                }
                Err(format!("{}={:?} fell outside its numeric partition", self.field, value))
            }
            FieldKind::Boolean => {
                Ok(if prismpath_rs::py_truthy(value) { 1 } else { 0 })
            }
            FieldKind::Categorical => {
                let text = v_to_str(value);
                for (index, cell) in self.cells.iter().enumerate() {
                    if let Some(ref constant) = cell.const_val {
                        if constant == &text {
                            return Ok(index);
                        }
                    }
                }
                Ok(self.n - 1) // trailing "other" cell
            }
        }
    }

    pub fn representative(&self, symbol: usize) -> V {
        self.cells[symbol].rep.clone()
    }

    /// `symbol` behind acceptance: the value is accepted and converted by `accept_value`
    /// or the error names the field and the reason. Encode through this at a runtime boundary;
    /// `symbol` keeps its permissive numeric view for compatibility.
    pub fn checked_symbol(&self, value: &V) -> Result<usize, AcceptanceError> {
        let converted = accept_value(&self.kind, value)
            .map_err(|refusal| AcceptanceError { field: self.field.clone(), refusal })?;
        self.symbol(&converted)
            .map_err(|_| AcceptanceError { field: self.field.clone(), refusal: InputRefusal::OutOfRange })
    }
}

/// The permissive numeric view `symbol` keeps for compatibility: a fraction truncates, a bool is
/// 0 or 1. A string that is not an integer literal and a null are errors, never zero; reading them
/// as zero was a silent coercion the reference never had, and a preflight that passed could not
/// predict it.
fn v_to_i64(value: &V) -> Result<i64, String> {
    match value {
        V::Num(number) => Ok(*number as i64),
        V::Bool(flag) => Ok(if *flag { 1 } else { 0 }),
        V::Str(text) => text.parse::<i64>().map_err(|_| format!("{text:?} is not an integer literal")),
        other => Err(format!("{other:?} is not a number")),
    }
}

// ------------------------------------------------------------------ acceptance
// One rule set for the Rust and Python encoders and for both preflight tools, frozen as the
// inputs corpus. Integers are accepted within the range every JSON reader represents exactly.
pub const SAFE_INTEGER_LIMIT: f64 = 9007199254740992.0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputRefusal {
    Missing,
    WrongType,
    UnparseableString,
    Fractional,
    OutOfRange,
}

impl InputRefusal {
    /// The reason string shared with the Python side and the preflight reports.
    pub fn reason(&self) -> &'static str {
        match self {
            InputRefusal::Missing => "missing",
            InputRefusal::WrongType => "wrong_type",
            InputRefusal::UnparseableString => "unparseable_string",
            InputRefusal::Fractional => "fractional",
            InputRefusal::OutOfRange => "out_of_range",
        }
    }
}

impl std::fmt::Display for InputRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason())
    }
}

/// A value acceptance refuses, with the field it was offered for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptanceError {
    pub field: String,
    pub refusal: InputRefusal,
}

impl std::fmt::Display for AcceptanceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.field, self.refusal)
    }
}

fn integer_literal(text: &str) -> bool {
    let digits = text.strip_prefix('+').or_else(|| text.strip_prefix('-')).unwrap_or(text);
    !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
}

/// Acceptance for one field kind: the converted value, or the refusal.
///
/// numeric accepts an integer within the safe range, an integral float, a bool as 0 or 1, and a
/// string that is an integer literal with an optional sign; a fraction is refused rather than
/// truncated, another string is refused rather than read as zero, null is missing. boolean accepts
/// a bool and a number exactly 0 or 1. categorical accepts a string only. Anything else is the
/// wrong type. Python's `accept_value` is the same function; the inputs corpus pins both.
pub fn accept_value(kind: &FieldKind, value: &V) -> Result<V, InputRefusal> {
    if matches!(value, V::Null) {
        return Err(InputRefusal::Missing);
    }
    match kind {
        FieldKind::Numeric => {
            let number = match value {
                V::Bool(flag) => if *flag { 1.0 } else { 0.0 },
                V::Num(number) => {
                    if !number.is_finite() {
                        return Err(InputRefusal::OutOfRange);
                    }
                    if number.fract() != 0.0 {
                        return Err(InputRefusal::Fractional);
                    }
                    *number
                }
                V::Str(text) => {
                    if !integer_literal(text) {
                        return Err(InputRefusal::UnparseableString);
                    }
                    // A literal that overflows f64 parsing is out of range, not unparseable.
                    text.parse::<f64>().map_err(|_| InputRefusal::OutOfRange)?
                }
                _ => return Err(InputRefusal::WrongType),
            };
            if number.abs() >= SAFE_INTEGER_LIMIT {
                return Err(InputRefusal::OutOfRange);
            }
            Ok(V::Num(number))
        }
        FieldKind::Boolean => match value {
            V::Bool(flag) => Ok(V::Bool(*flag)),
            V::Num(number) if *number == 0.0 || *number == 1.0 => Ok(V::Bool(*number == 1.0)),
            _ => Err(InputRefusal::WrongType),
        },
        FieldKind::Categorical => match value {
            V::Str(text) => Ok(V::Str(text.clone())),
            _ => Err(InputRefusal::WrongType),
        },
    }
}

/// `quantize` behind acceptance: every decision field present and accepted, or the error
/// names the first field that is not.
pub fn checked_quantize(
    parts: &HashMap<String, FieldPartition>,
    reading: &HashMap<String, V>,
) -> Result<HashMap<String, usize>, AcceptanceError> {
    let mut fields: Vec<&String> = parts.keys().collect();
    fields.sort();
    let mut out = HashMap::new();
    for field in fields {
        let value = reading.get(field).ok_or_else(|| AcceptanceError { field: field.clone(), refusal: InputRefusal::Missing })?;
        out.insert(field.clone(), parts[field].checked_symbol(value)?);
    }
    Ok(out)
}

fn v_to_str(value: &V) -> String {
    match value {
        V::Str(text) => text.clone(),
        V::Num(number) => number.to_string(),
        V::Bool(flag) => if *flag { "True".to_string() } else { "False".to_string() },
        _ => String::new(),
    }
}

fn atom_true(op: &str, const_val: &AtomConst, reading_value: i64) -> bool {
    let constant = match const_val {
        AtomConst::Num(number) => *number,
        _ => 0,
    };
    // `in` / `not in` over a numeric list: membership of the value in the list's integers. The
    // first version returned false for both, so list atoms never influenced the merge (September
    // 2026, found by the Lean formalization of I1 alongside the missing cut points below).
    let in_list = || match const_val {
        AtomConst::List(members) => members.iter().any(|member| matches!(member, AtomConst::Num(number) if *number == reading_value)),
        AtomConst::Num(number) => *number == reading_value,
        _ => false,
    };
    match op {
        "<" => reading_value < constant,
        "<=" => reading_value <= constant,
        ">" => reading_value > constant,
        ">=" => reading_value >= constant,
        "==" => reading_value == constant,
        "!=" => reading_value != constant,
        "in" => in_list(),
        "not in" => !in_list(),
        "truthy" => reading_value != 0,
        _ => false,
    }
}

fn numeric_partition(field: &str, atoms: &[Atom]) -> FieldPartition {
    // Every value at which an atom can change truth is a cut point: ordering and equality
    // constants, every integer in an `in` / `not in` list, and 0 for a bare truthiness atom.
    // Mirrors quantizer.py `_numeric_partition` after the September 2026 correction.
    let mut const_set: Vec<i64> = Vec::new();
    for atom in atoms {
        match atom.op.as_str() {
            "<" | "<=" | ">" | ">=" | "==" | "!=" => {
                if let AtomConst::Num(number) = atom.const_val {
                    if !const_set.contains(&number) {
                        const_set.push(number);
                    }
                }
            }
            "in" | "not in" => {
                for member in atom.const_val.flat_consts() {
                    if let AtomConst::Num(number) = member {
                        if !const_set.contains(&number) {
                            const_set.push(number);
                        }
                    }
                }
            }
            "truthy" if !const_set.contains(&0) => const_set.push(0),
            _ => {}
        }
    }
    const_set.sort();
    if const_set.is_empty() {
        const_set.push(0);
    }

    let mut fine: Vec<(Option<i64>, Option<i64>)> = Vec::new();
    fine.push((None, Some(const_set[0] - 1)));
    for (index, &cut_point) in const_set.iter().enumerate() {
        fine.push((Some(cut_point), Some(cut_point)));
        let nxt = const_set.get(index + 1).copied();
        let lo = cut_point + 1;
        let hi = nxt.map(|next_cut_point| next_cut_point - 1);
        if hi.is_none_or(|bound| lo <= bound) {
            fine.push((Some(lo), hi));
        }
    }

    fn rep(lo: Option<i64>, hi: Option<i64>) -> i64 {
        lo.or(hi).unwrap_or_default()
    }

    let truth = |reading_value: i64| -> Vec<bool> {
        atoms.iter().map(|atom| atom_true(&atom.op, &atom.const_val, reading_value)).collect()
    };

    let mut cells: Vec<Cell> = Vec::new();
    let mut prev_tv: Option<Vec<bool>> = None;

    for (lo, hi) in fine {
        let tv = truth(rep(lo, hi));
        if prev_tv.as_ref() == Some(&tv) {
            if let Some(last) = cells.last_mut() {
                last.hi = hi;
            }
        } else {
            cells.push(Cell {
                lo,
                hi,
                const_val: None,
                rep: V::Num(rep(lo, hi) as f64),
            });
            prev_tv = Some(tv);
        }
    }

    FieldPartition::new(field.to_string(), FieldKind::Numeric, cells)
}

fn boolean_partition(field: &str) -> FieldPartition {
    let cells = vec![
        Cell { lo: None, hi: None, const_val: None, rep: V::Bool(false) },
        Cell { lo: None, hi: None, const_val: None, rep: V::Bool(true) },
    ];
    FieldPartition::new(field.to_string(), FieldKind::Boolean, cells)
}

fn categorical_partition(field: &str, atoms: &[Atom]) -> FieldPartition {
    let mut consts: Vec<String> = Vec::new();
    for atom in atoms {
        // str truthiness is `s != ""`: the empty string is a named constant (September 2026).
        let vals: Vec<String> = if atom.op == "truthy" {
            vec![String::new()]
        } else {
            match &atom.const_val {
                AtomConst::List(members) => members.iter().filter_map(|member| match member {
                    AtomConst::Str(text) => Some(text.clone()),
                    _ => None,
                }).collect(),
                AtomConst::Str(text) => vec![text.clone()],
                _ => vec![],
            }
        };
        for value in vals {
            if !consts.contains(&value) {
                consts.push(value);
            }
        }
    }

    let mut cells: Vec<Cell> = consts.iter().map(|constant| Cell {
        lo: None,
        hi: None,
        const_val: Some(constant.clone()),
        rep: V::Str(constant.clone()),
    }).collect();

    cells.push(Cell {
        lo: None,
        hi: None,
        const_val: Some(OTHER.to_string()),
        rep: V::Str(OTHER.to_string()),
    });

    FieldPartition::new(field.to_string(), FieldKind::Categorical, cells)
}

fn classify_kind(atoms: &[Atom]) -> Result<FieldKind, String> {
    let mut flat = Vec::new();
    for atom in atoms {
        if atom.op != "truthy" {
            flat.extend(atom.const_val.flat_consts());
        }
    }
    let has_str = flat.iter().any(|member| member.is_str());
    let has_num = flat.iter().any(|member| member.is_num());

    if has_str && has_num {
        return Err("field mixes string and numeric constants — not a Level M field".to_string());
    }
    if has_str {
        Ok(FieldKind::Categorical)
    } else if has_num {
        Ok(FieldKind::Numeric)
    } else {
        Ok(FieldKind::Boolean)
    }
}

// ----------------------------------------------------------------- Condition Atom Parser
#[derive(Debug, Clone)]
enum Tok {
    Ident(String),
    Num(i64),
    Str(String),
    Bool(bool),
    Op(String),
}

fn tokenize_cond(src: &str) -> Vec<Tok> {
    let mut toks = Vec::new();
    let chars: Vec<char> = src.chars().collect();
    let mut cursor = 0;
    while cursor < chars.len() {
        let character = chars[cursor];
        if character.is_whitespace() {
            cursor += 1;
            continue;
        }
        if character == '\'' || character == '"' {
            let quote = character;
            cursor += 1;
            let mut text = String::new();
            while cursor < chars.len() && chars[cursor] != quote {
                text.push(chars[cursor]);
                cursor += 1;
            }
            if cursor < chars.len() {
                cursor += 1;
            }
            toks.push(Tok::Str(text));
            continue;
        }
        if character == '-' || character.is_ascii_digit() {
            let start = cursor;
            if character == '-' {
                cursor += 1;
            }
            while cursor < chars.len() && chars[cursor].is_ascii_digit() {
                cursor += 1;
            }
            if cursor > start && (start != cursor - 1 || chars[start] != '-') {
                let text: String = chars[start..cursor].iter().collect();
                if let Ok(number) = text.parse::<i64>() {
                    toks.push(Tok::Num(number));
                    continue;
                }
            }
            cursor = start;
        }
        if character.is_alphabetic() || character == '_' {
            let start = cursor;
            while cursor < chars.len() && (chars[cursor].is_alphanumeric() || chars[cursor] == '_') {
                cursor += 1;
            }
            let text: String = chars[start..cursor].iter().collect();
            match text.as_str() {
                "True" => toks.push(Tok::Bool(true)),
                "False" => toks.push(Tok::Bool(false)),
                "and" | "or" | "not" | "in" => toks.push(Tok::Op(text)),
                _ => toks.push(Tok::Ident(text)),
            }
            continue;
        }
        if cursor + 1 < chars.len() {
            let two: String = chars[cursor..cursor + 2].iter().collect();
            if matches!(two.as_str(), "==" | "!=" | "<=" | ">=") {
                toks.push(Tok::Op(two));
                cursor += 2;
                continue;
            }
        }
        if matches!(character, '<' | '>') {
            toks.push(Tok::Op(character.to_string()));
            cursor += 1;
            continue;
        }
        if matches!(character, '(' | ')' | '[' | ']' | ',') {
            toks.push(Tok::Op(character.to_string()));
            cursor += 1;
            continue;
        }
        cursor += 1;
    }

    // Coalesce "not" + "in" -> "not in"
    let mut out = Vec::new();
    let mut idx = 0;
    while idx < toks.len() {
        if idx + 1 < toks.len() {
            if let (Tok::Op(o1), Tok::Op(o2)) = (&toks[idx], &toks[idx + 1]) {
                if o1 == "not" && o2 == "in" {
                    out.push(Tok::Op("not in".to_string()));
                    idx += 2;
                    continue;
                }
            }
        }
        out.push(toks[idx].clone());
        idx += 1;
    }
    out
}

fn flip_op(op: &str) -> String {
    match op {
        "<" => ">".to_string(),
        "<=" => ">=".to_string(),
        ">" => "<".to_string(),
        ">=" => "<=".to_string(),
        "==" => "==".to_string(),
        "!=" => "!=".to_string(),
        other => other.to_string(),
    }
}

pub fn parse_atoms(expr_str: &str) -> Vec<Atom> {
    let toks = tokenize_cond(expr_str);
    let mut atoms = Vec::new();
    let mut cursor = 0;

    while cursor < toks.len() {
        match &toks[cursor] {
            Tok::Op(op) if op == "and" || op == "or" || op == "not" => {
                cursor += 1;
            }
            Tok::Op(op) if op == "(" || op == ")" || op == "[" || op == "]" || op == "," => {
                cursor += 1;
            }
            Tok::Ident(field) => {
                let f_name = field.clone();
                if cursor + 1 < toks.len() {
                    if let Tok::Op(cmp_op) = &toks[cursor + 1] {
                        if cmp_op == "in" || cmp_op == "not in" {
                            // field in (c1, c2, ...)
                            let op_str = cmp_op.clone();
                            cursor += 2;
                            let mut consts = Vec::new();
                            if cursor < toks.len() && matches!(&toks[cursor], Tok::Op(bracket) if bracket == "(" || bracket == "[") {
                                cursor += 1;
                                while cursor < toks.len() {
                                    match &toks[cursor] {
                                        Tok::Str(text) => consts.push(AtomConst::Str(text.clone())),
                                        Tok::Num(number) => consts.push(AtomConst::Num(*number)),
                                        Tok::Bool(flag) => consts.push(AtomConst::Bool(*flag)),
                                        Tok::Op(bracket) if bracket == ")" || bracket == "]" => {
                                            cursor += 1;
                                            break;
                                        }
                                        _ => {}
                                    }
                                    cursor += 1;
                                }
                            }
                            atoms.push(Atom {
                                field: f_name,
                                op: op_str,
                                const_val: AtomConst::List(consts),
                            });
                            continue;
                        } else if matches!(cmp_op.as_str(), "<" | "<=" | ">" | ">=" | "==" | "!=") {
                            let op_str = cmp_op.clone();
                            if cursor + 2 < toks.len() {
                                match &toks[cursor + 2] {
                                    Tok::Num(number) => {
                                        atoms.push(Atom {
                                            field: f_name,
                                            op: op_str,
                                            const_val: AtomConst::Num(*number),
                                        });
                                        cursor += 3;
                                        continue;
                                    }
                                    Tok::Str(text) => {
                                        atoms.push(Atom {
                                            field: f_name,
                                            op: op_str,
                                            const_val: AtomConst::Str(text.clone()),
                                        });
                                        cursor += 3;
                                        continue;
                                    }
                                    Tok::Bool(flag) => {
                                        atoms.push(Atom {
                                            field: f_name,
                                            op: op_str,
                                            const_val: AtomConst::Bool(*flag),
                                        });
                                        cursor += 3;
                                        continue;
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
                // Bare field -> truthiness
                atoms.push(Atom {
                    field: f_name,
                    op: "truthy".to_string(),
                    const_val: AtomConst::None,
                });
                cursor += 1;
            }
            Tok::Num(number) => {
                let val = *number;
                if cursor + 2 < toks.len() {
                    if let (Tok::Op(cmp_op), Tok::Ident(field)) = (&toks[cursor + 1], &toks[cursor + 2]) {
                        if matches!(cmp_op.as_str(), "<" | "<=" | ">" | ">=" | "==" | "!=") {
                            atoms.push(Atom {
                                field: field.clone(),
                                op: flip_op(cmp_op),
                                const_val: AtomConst::Num(val),
                            });
                            cursor += 3;
                            continue;
                        }
                    }
                }
                cursor += 1;
            }
            Tok::Str(text) => {
                let val = text.clone();
                if cursor + 2 < toks.len() {
                    if let (Tok::Op(cmp_op), Tok::Ident(field)) = (&toks[cursor + 1], &toks[cursor + 2]) {
                        if matches!(cmp_op.as_str(), "<" | "<=" | ">" | ">=" | "==" | "!=") {
                            atoms.push(Atom {
                                field: field.clone(),
                                op: flip_op(cmp_op),
                                const_val: AtomConst::Str(val),
                            });
                            cursor += 3;
                            continue;
                        }
                    }
                }
                cursor += 1;
            }
            _ => {
                cursor += 1;
            }
        }
    }

    atoms
}

fn expr_of(cond: &str) -> String {
    let text = cond.trim();
    if text.to_lowercase().starts_with("when ") {
        text[5..].trim().to_string()
    } else {
        text.to_string()
    }
}

pub fn extract_flow_atoms(graph: &Graph) -> HashMap<String, Vec<Atom>> {
    let mut fields: HashMap<String, Vec<Atom>> = HashMap::new();
    for node in graph.nodes.values() {
        for (_target, cond) in &node.edges {
            if !prismpath_rs::is_deterministic(cond) || prismpath_rs::is_semantic(cond) {
                continue;
            }
            let expr = expr_of(cond);
            let lower = expr.to_lowercase();
            if ALWAYS.contains(&lower.as_str()) || NEVER.contains(&lower.as_str()) {
                continue;
            }
            let atoms = parse_atoms(&expr);
            for atom in atoms {
                fields.entry(atom.field.clone()).or_default().push(atom);
            }
        }
    }
    fields
}

pub fn build_partitions(graph: &Graph) -> HashMap<String, FieldPartition> {
    let flow_atoms = extract_flow_atoms(graph);
    let mut parts = HashMap::new();
    for (field, atoms) in flow_atoms {
        if let Ok(kind) = classify_kind(&atoms) {
            let part = match kind {
                FieldKind::Numeric => numeric_partition(&field, &atoms),
                FieldKind::Categorical => categorical_partition(&field, &atoms),
                FieldKind::Boolean => boolean_partition(&field),
            };
            parts.insert(field, part);
        }
    }
    parts
}

pub fn quantize(
    parts: &HashMap<String, FieldPartition>,
    reading: &HashMap<String, V>,
) -> Result<HashMap<String, usize>, String> {
    let mut out = HashMap::new();
    for (field, partition) in parts {
        if let Some(value) = reading.get(field) {
            out.insert(field.clone(), partition.symbol(value)?);
        }
    }
    Ok(out)
}

pub fn reconstruct(
    parts: &HashMap<String, FieldPartition>,
    symbols: &HashMap<String, usize>,
) -> HashMap<String, V> {
    let mut out = HashMap::new();
    for (field, &symbol) in symbols {
        if let Some(partition) = parts.get(field) {
            out.insert(field.clone(), partition.representative(symbol));
        }
    }
    out
}
