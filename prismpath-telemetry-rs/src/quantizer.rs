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
            AtomConst::List(l) => l.iter().any(|x| x.is_str()),
            _ => false,
        }
    }

    pub fn is_bool(&self) -> bool {
        match self {
            AtomConst::Bool(_) => true,
            AtomConst::List(l) => l.iter().any(|x| x.is_bool()),
            _ => false,
        }
    }

    pub fn is_num(&self) -> bool {
        match self {
            AtomConst::Num(_) => true,
            AtomConst::List(l) => l.iter().any(|x| x.is_num()),
            _ => false,
        }
    }

    pub fn flat_consts(&self) -> Vec<AtomConst> {
        match self {
            AtomConst::List(l) => l.clone(),
            c => vec![c.clone()],
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
                let v = v_to_i64(value);
                for (i, c) in self.cells.iter().enumerate() {
                    let lo_ok = c.lo.is_none_or(|l| v >= l);
                    let hi_ok = c.hi.is_none_or(|h| v <= h);
                    if lo_ok && hi_ok {
                        return Ok(i);
                    }
                }
                Err(format!("{}={:?} fell outside its numeric partition", self.field, value))
            }
            FieldKind::Boolean => {
                Ok(if prismpath_rs::py_truthy(value) { 1 } else { 0 })
            }
            FieldKind::Categorical => {
                let s = v_to_str(value);
                for (i, c) in self.cells.iter().enumerate() {
                    if let Some(ref cv) = c.const_val {
                        if cv == &s {
                            return Ok(i);
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
}

fn v_to_i64(value: &V) -> i64 {
    match value {
        V::Num(n) => *n as i64,
        V::Bool(b) => if *b { 1 } else { 0 },
        V::Str(s) => s.parse::<i64>().unwrap_or(0),
        _ => 0,
    }
}

fn v_to_str(value: &V) -> String {
    match value {
        V::Str(s) => s.clone(),
        V::Num(n) => n.to_string(),
        V::Bool(b) => if *b { "True".to_string() } else { "False".to_string() },
        _ => String::new(),
    }
}

fn atom_true(op: &str, const_val: &AtomConst, v: i64) -> bool {
    let c = match const_val {
        AtomConst::Num(n) => *n,
        _ => 0,
    };
    match op {
        "<" => v < c,
        "<=" => v <= c,
        ">" => v > c,
        ">=" => v >= c,
        "==" => v == c,
        "!=" => v != c,
        "truthy" => v != 0,
        _ => false,
    }
}

fn numeric_partition(field: &str, atoms: &[Atom]) -> FieldPartition {
    let mut const_set: Vec<i64> = Vec::new();
    for a in atoms {
        if matches!(a.op.as_str(), "<" | "<=" | ">" | ">=" | "==" | "!=") {
            if let AtomConst::Num(n) = a.const_val {
                if !const_set.contains(&n) {
                    const_set.push(n);
                }
            }
        }
    }
    const_set.sort();
    if const_set.is_empty() {
        const_set.push(0);
    }

    let mut fine: Vec<(Option<i64>, Option<i64>)> = Vec::new();
    fine.push((None, Some(const_set[0] - 1)));
    for (i, &c) in const_set.iter().enumerate() {
        fine.push((Some(c), Some(c)));
        let nxt = const_set.get(i + 1).copied();
        let lo = c + 1;
        let hi = nxt.map(|n| n - 1);
        if hi.is_none_or(|h| lo <= h) {
            fine.push((Some(lo), hi));
        }
    }

    fn rep(lo: Option<i64>, hi: Option<i64>) -> i64 {
        lo.or(hi).unwrap_or_default()
    }

    let truth = |v: i64| -> Vec<bool> {
        atoms.iter().map(|a| atom_true(&a.op, &a.const_val, v)).collect()
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
    for a in atoms {
        let vals = match &a.const_val {
            AtomConst::List(l) => l.iter().filter_map(|x| match x {
                AtomConst::Str(s) => Some(s.clone()),
                _ => None,
            }).collect(),
            AtomConst::Str(s) => vec![s.clone()],
            _ => vec![],
        };
        for v in vals {
            if !consts.contains(&v) {
                consts.push(v);
            }
        }
    }

    let mut cells: Vec<Cell> = consts.iter().map(|c| Cell {
        lo: None,
        hi: None,
        const_val: Some(c.clone()),
        rep: V::Str(c.clone()),
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
    for a in atoms {
        if a.op != "truthy" {
            flat.extend(a.const_val.flat_consts());
        }
    }
    let has_str = flat.iter().any(|x| x.is_str());
    let has_num = flat.iter().any(|x| x.is_num());

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
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '\'' || c == '"' {
            let quote = c;
            i += 1;
            let mut s = String::new();
            while i < chars.len() && chars[i] != quote {
                s.push(chars[i]);
                i += 1;
            }
            if i < chars.len() {
                i += 1;
            }
            toks.push(Tok::Str(s));
            continue;
        }
        if c == '-' || c.is_ascii_digit() {
            let start = i;
            if c == '-' {
                i += 1;
            }
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            if i > start && (start != i - 1 || chars[start] != '-') {
                let s: String = chars[start..i].iter().collect();
                if let Ok(n) = s.parse::<i64>() {
                    toks.push(Tok::Num(n));
                    continue;
                }
            }
            i = start;
        }
        if c.is_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let s: String = chars[start..i].iter().collect();
            match s.as_str() {
                "True" => toks.push(Tok::Bool(true)),
                "False" => toks.push(Tok::Bool(false)),
                "and" | "or" | "not" | "in" => toks.push(Tok::Op(s)),
                _ => toks.push(Tok::Ident(s)),
            }
            continue;
        }
        if i + 1 < chars.len() {
            let two: String = chars[i..i + 2].iter().collect();
            if matches!(two.as_str(), "==" | "!=" | "<=" | ">=") {
                toks.push(Tok::Op(two));
                i += 2;
                continue;
            }
        }
        if matches!(c, '<' | '>') {
            toks.push(Tok::Op(c.to_string()));
            i += 1;
            continue;
        }
        if matches!(c, '(' | ')' | '[' | ']' | ',') {
            toks.push(Tok::Op(c.to_string()));
            i += 1;
            continue;
        }
        i += 1;
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
    let mut i = 0;

    while i < toks.len() {
        match &toks[i] {
            Tok::Op(op) if op == "and" || op == "or" || op == "not" => {
                i += 1;
            }
            Tok::Op(op) if op == "(" || op == ")" || op == "[" || op == "]" || op == "," => {
                i += 1;
            }
            Tok::Ident(field) => {
                let f_name = field.clone();
                if i + 1 < toks.len() {
                    if let Tok::Op(cmp_op) = &toks[i + 1] {
                        if cmp_op == "in" || cmp_op == "not in" {
                            // field in (c1, c2, ...)
                            let op_str = cmp_op.clone();
                            i += 2;
                            let mut consts = Vec::new();
                            if i < toks.len() && matches!(&toks[i], Tok::Op(o) if o == "(" || o == "[") {
                                i += 1;
                                while i < toks.len() {
                                    match &toks[i] {
                                        Tok::Str(s) => consts.push(AtomConst::Str(s.clone())),
                                        Tok::Num(n) => consts.push(AtomConst::Num(*n)),
                                        Tok::Bool(b) => consts.push(AtomConst::Bool(*b)),
                                        Tok::Op(o) if o == ")" || o == "]" => {
                                            i += 1;
                                            break;
                                        }
                                        _ => {}
                                    }
                                    i += 1;
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
                            if i + 2 < toks.len() {
                                match &toks[i + 2] {
                                    Tok::Num(n) => {
                                        atoms.push(Atom {
                                            field: f_name,
                                            op: op_str,
                                            const_val: AtomConst::Num(*n),
                                        });
                                        i += 3;
                                        continue;
                                    }
                                    Tok::Str(s) => {
                                        atoms.push(Atom {
                                            field: f_name,
                                            op: op_str,
                                            const_val: AtomConst::Str(s.clone()),
                                        });
                                        i += 3;
                                        continue;
                                    }
                                    Tok::Bool(b) => {
                                        atoms.push(Atom {
                                            field: f_name,
                                            op: op_str,
                                            const_val: AtomConst::Bool(*b),
                                        });
                                        i += 3;
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
                i += 1;
            }
            Tok::Num(n) => {
                let val = *n;
                if i + 2 < toks.len() {
                    if let (Tok::Op(cmp_op), Tok::Ident(field)) = (&toks[i + 1], &toks[i + 2]) {
                        if matches!(cmp_op.as_str(), "<" | "<=" | ">" | ">=" | "==" | "!=") {
                            atoms.push(Atom {
                                field: field.clone(),
                                op: flip_op(cmp_op),
                                const_val: AtomConst::Num(val),
                            });
                            i += 3;
                            continue;
                        }
                    }
                }
                i += 1;
            }
            Tok::Str(s) => {
                let val = s.clone();
                if i + 2 < toks.len() {
                    if let (Tok::Op(cmp_op), Tok::Ident(field)) = (&toks[i + 1], &toks[i + 2]) {
                        if matches!(cmp_op.as_str(), "<" | "<=" | ">" | ">=" | "==" | "!=") {
                            atoms.push(Atom {
                                field: field.clone(),
                                op: flip_op(cmp_op),
                                const_val: AtomConst::Str(val),
                            });
                            i += 3;
                            continue;
                        }
                    }
                }
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    atoms
}

fn expr_of(cond: &str) -> String {
    let c = cond.trim();
    if c.to_lowercase().starts_with("when ") {
        c[5..].trim().to_string()
    } else {
        c.to_string()
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
    for (f, p) in parts {
        if let Some(v) = reading.get(f) {
            out.insert(f.clone(), p.symbol(v)?);
        }
    }
    Ok(out)
}

pub fn reconstruct(
    parts: &HashMap<String, FieldPartition>,
    symbols: &HashMap<String, usize>,
) -> HashMap<String, V> {
    let mut out = HashMap::new();
    for (f, &s) in symbols {
        if let Some(p) = parts.get(f) {
            out.insert(f.clone(), p.representative(s));
        }
    }
    out
}
