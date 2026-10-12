// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Decision-preserving quantizer — the differentiator.

use prismpath_rs::{accept_canonical, DefinedKind, FieldDefinition, Graph, Value, V};
use std::collections::HashMap;

pub const OTHER: &str = "\x00__other__";

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
    /// The field's signed definition when the flow defines its fields (SPEC section 4.5). A defined
    /// field takes only canonical values on every path, permissive included.
    pub definition: Option<FieldDefinition>,
    /// The index of the absent cell, always the last, when the definition allows absence. No present
    /// value falls in it, so absence is never zero, false or a string.
    pub absent_symbol: Option<usize>,
}

impl FieldPartition {
    pub fn new(field: String, kind: FieldKind, cells: Vec<Cell>) -> Self {
        let n = cells.len();
        FieldPartition { field, kind, cells, n, definition: None, absent_symbol: None }
    }

    /// A partition for a defined field: the inferred cells of its kind, plus the absent cell when the
    /// definition allows absence.
    fn defined(built: FieldPartition, definition: FieldDefinition) -> Self {
        let mut cells = built.cells;
        let absent_symbol = if definition.absent_allowed {
            cells.push(Cell { lo: None, hi: None, const_val: None, rep: V::Null });
            Some(cells.len() - 1)
        } else {
            None
        };
        let n = cells.len();
        FieldPartition { field: built.field, kind: built.kind, cells, n, definition: Some(definition), absent_symbol }
    }

    /// The cells a present value can fall in: every cell but the absent one.
    fn present_cells(&self) -> usize {
        self.n - usize::from(self.absent_symbol.is_some())
    }

    /// The symbol of a value on a defined field, or the refusal reason. Nothing is converted.
    fn defined_symbol(&self, definition: &FieldDefinition, value: &V) -> Result<usize, &'static str> {
        let canonical = accept_canonical(definition, value)?;
        if matches!(canonical, V::Null) {
            return self.absent_symbol.ok_or(prismpath_rs::field_definitions::REFUSAL_MISSING);
        }
        self.present_symbol(&canonical).map_err(|_| prismpath_rs::field_definitions::REFUSAL_OUT_OF_RANGE)
    }

    /// The cell index a value falls in. `Err` only for a value outside every cell of a numeric
    /// partition — unreachable for partitions built by `build_partitions` (open ends), but a
    /// hand-constructed partition can bound both ends, and a library consumer (e.g. a Vector
    /// codec) must never be able to panic the encoder.
    /// The cell index of a value, or the refusal naming the field and the reason. One rule for every
    /// encoder, the twin of quantizer.py `symbol`: a defined field takes only canonical values, and an
    /// inferred field takes what `accept_value` accepts, converted only in ways the engine cannot tell
    /// apart. Until October 2026 this permissive path also parsed integer strings, read a boolean field
    /// by truthiness, and turned a number on a categorical field into its string, and each of those
    /// could change a decision.
    pub fn symbol(&self, value: &V) -> Result<usize, String> {
        self.checked_symbol(value).map_err(|error| format!("{error} ({value:?})"))
    }

    fn present_symbol(&self, value: &V) -> Result<usize, String> {
        match self.kind {
            FieldKind::Numeric => {
                let number = v_to_i64(value)?;
                for (index, cell) in self.cells.iter().enumerate().take(self.present_cells()) {
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
                let V::Str(text) = value else {
                    return Err(format!("{}={:?} is not a string", self.field, value));
                };
                for (index, cell) in self.cells.iter().enumerate().take(self.present_cells()) {
                    if let Some(ref constant) = cell.const_val {
                        if constant == text {
                            return Ok(index);
                        }
                    }
                }
                Ok(self.present_cells() - 1) // the "other" cell, last of the present cells
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
        if let Some(definition) = &self.definition {
            return self.defined_symbol(definition, value)
                .map_err(|reason| AcceptanceError { field: self.field.clone(), refusal: InputRefusal::from_reason(reason) });
        }
        let converted = accept_value(&self.kind, value)
            .map_err(|refusal| AcceptanceError { field: self.field.clone(), refusal })?;
        self.present_symbol(&converted)
            .map_err(|_| AcceptanceError { field: self.field.clone(), refusal: InputRefusal::OutOfRange })
    }
}

/// The integer an accepted numeric value compares as: an integral number, or a bool as 0 or 1. A
/// fraction or a non finite number is an error, never truncated: `as i64` truncates toward zero,
/// which moves a reading across a cut (-0.5 against `x < 0`, 3.5 against `x == 3`) and changes the
/// decision (the Lean formalization's float check, October 2026). A string is an error rather than
/// parsed, since the engine never orders a string against a number; parsing belongs to the adapter.
fn v_to_i64(value: &V) -> Result<i64, String> {
    match value {
        V::Num(number) if !number.is_finite() || number.fract() != 0.0 =>
            Err(format!("{number} is fractional or not finite: refused rather than truncated")),
        V::Num(number) => Ok(*number as i64),
        V::Bool(flag) => Ok(if *flag { 1 } else { 0 }),
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
    /// The refusal a canonical boundary reason names. The boundary only ever gives the four reasons
    /// below; any other would be a bug, and it reads as wrong_type rather than as an acceptance.
    pub fn from_reason(reason: &str) -> InputRefusal {
        match reason {
            "missing" => InputRefusal::Missing,
            "fractional" => InputRefusal::Fractional,
            "out_of_range" => InputRefusal::OutOfRange,
            "unparseable_string" => InputRefusal::UnparseableString,
            _ => InputRefusal::WrongType,
        }
    }

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

/// Acceptance for one field kind: the converted value, or the refusal.
///
/// numeric accepts an integer within the safe range, an integral float, and a bool as 0 or 1; a
/// fraction is refused rather than truncated, a string is the wrong type rather than parsed (since
/// October 2026; accepting `"5"` as 5 routed it where the engine would not), and null is missing.
/// boolean accepts a bool and a number exactly 0 or 1. categorical accepts a string only. Anything
/// else is the wrong type. Every remaining conversion is one the engine cannot tell apart. Python's
/// `accept_value` is the same function; the inputs corpus pins both.
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
        // A defined field missing from the reading is the absent value, which its definition carries
        // or refuses; an inferred field missing is refused here.
        let value = match reading.get(field) {
            Some(value) => value,
            None if parts[field].definition.is_some() => &V::Null,
            None => return Err(AcceptanceError { field: field.clone(), refusal: InputRefusal::Missing }),
        };
        out.insert(field.clone(), parts[field].checked_symbol(value)?);
    }
    Ok(out)
}

/// The integer a constant compares as on a numeric field. A boolean is 0 or 1, because the engine
/// compares `1 == True` as true. Until October 2026 a boolean constant read as 0 here and added no cut
/// point, so `x == True` beside `x > 5` merged 1 into the cell of 0 and routed it the other way.
fn numeric_constant(constant: &AtomConst) -> Option<i64> {
    match constant {
        AtomConst::Num(number) => Some(*number),
        AtomConst::Bool(flag) => Some(i64::from(*flag)),
        _ => None,
    }
}

fn atom_true(op: &str, const_val: &AtomConst, reading_value: i64) -> bool {
    let constant = numeric_constant(const_val).unwrap_or_default();
    // `in` / `not in` over a numeric list: membership of the value in the list's integers. The
    // first version returned false for both, so list atoms never influenced the merge (September
    // 2026, found by the Lean formalization of I1 alongside the missing cut points below).
    let in_list = || match const_val {
        AtomConst::List(members) => members.iter().any(|member| numeric_constant(member) == Some(reading_value)),
        single => numeric_constant(single) == Some(reading_value),
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
                if let Some(number) = numeric_constant(&atom.const_val) {
                    if !const_set.contains(&number) {
                        const_set.push(number);
                    }
                }
            }
            "in" | "not in" => {
                for member in atom.const_val.flat_consts() {
                    if let Some(number) = numeric_constant(&member) {
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
    if flat.iter().any(|member| matches!(member, AtomConst::None)) {
        // The engine reads a missing field as None, so `x == None` tests for absence, and the codec
        // has no cell for absence yet. Before October 2026 the token scanner read `None` as a second
        // field, so every reading was refused for lacking it. Refused until the canonical reading
        // gives absence an explicit cell; quantizer.py refuses the same constant.
        return Err("a comparison with None tests for an absent field, and the codec does not carry absence yet".to_string());
    }
    let has_str = flat.iter().any(|member| member.is_str());
    let has_num = flat.iter().any(|member| member.is_num());
    let has_bool = flat.iter().any(|member| member.is_bool());

    // A boolean counts as a number here because the engine compares it as 0 or 1.
    if has_str && (has_num || has_bool) {
        return Err("field mixes string and numeric constants, which is not a Level M field".to_string());
    }
    if has_str {
        Ok(FieldKind::Categorical)
    } else if has_num {
        Ok(FieldKind::Numeric)
    } else {
        Ok(FieldKind::Boolean)
    }
}

// ----------------------------------------------------------------- Condition atoms
/// The atoms of one condition, read from the engine's own parse through `prismpath_rs::level_m_atoms`,
/// or the Level M reason code it cannot be carried. Until October 2026 this crate scanned the
/// condition's tokens itself, and it read `0 < x < 5` as `x > 0` alone, `True == x` as a bare `x`,
/// `2.5` as `2`, and `None` as a field named None, so the partition dropped or invented cut points
/// without saying so. A keyword catch all has no atoms.
pub fn condition_atoms(cond: &str) -> Result<Vec<Atom>, String> {
    prismpath_rs::level_m_atoms(cond)?
        .into_iter()
        .map(|atom| {
            Ok(Atom { field: atom.field, op: atom.op, const_val: atom_constant(&atom.constant)? })
        })
        .collect()
}

fn atom_constant(value: &Value) -> Result<AtomConst, String> {
    match value {
        Value::Null => Ok(AtomConst::None),
        Value::Bool(flag) => Ok(AtomConst::Bool(*flag)),
        Value::Num(number) => {
            // Level M admits only integer literals, so a fraction cannot reach this point. An integer
            // past the i64 range can, and it is refused rather than saturated onto the wrong cut.
            let in_range = *number >= i64::MIN as f64 && *number < i64::MAX as f64;
            if number.is_finite() && number.fract() == 0.0 && in_range {
                Ok(AtomConst::Num(*number as i64))
            } else {
                Err(format!("constant {number} is not an integer the codec can compare"))
            }
        }
        Value::Str(text) => Ok(AtomConst::Str(text.clone())),
        Value::List(members) => {
            members.iter().map(atom_constant).collect::<Result<Vec<_>, _>>().map(AtomConst::List)
        }
        other => Err(format!("constant {other:?} is not a Level M scalar")),
    }
}

/// Every field's atoms across the flow's deterministic, non semantic edges. A flow with any such
/// condition outside Level M is refused whole, with every offending condition and its reason, because
/// only Level M conditions reduce to per field cut points. A field compared with another field, or a
/// string ordered against a constant, depends on values the partition does not keep, and skipping the
/// condition, as this crate did before October 2026, let a decoded reading take an edge the raw
/// reading did not. quantizer.py refuses the same flows.
pub fn extract_flow_atoms(graph: &Graph) -> Result<HashMap<String, Vec<Atom>>, String> {
    let mut fields: HashMap<String, Vec<Atom>> = HashMap::new();
    let mut outside: Vec<String> = Vec::new();
    let mut names: Vec<&String> = graph.nodes.keys().collect();
    names.sort();
    for name in names {
        for (_target, cond) in &graph.nodes[name].edges {
            if !prismpath_rs::is_deterministic(cond) || prismpath_rs::is_semantic(cond) {
                continue;
            }
            match condition_atoms(cond) {
                Ok(atoms) => {
                    for atom in atoms {
                        fields.entry(atom.field.clone()).or_default().push(atom);
                    }
                }
                Err(reason) => outside.push(format!("{name}: {cond:?} ({reason})")),
            }
        }
    }
    if !outside.is_empty() {
        return Err(format!(
            "the flow routes on conditions outside Level M, which the codec cannot carry: {}",
            outside.join("; ")
        ));
    }
    Ok(fields)
}

/// Per decision relevant field, the coarsest partition that preserves every routing decision, or
/// the reason the flow cannot be partitioned faithfully. A field whose kind cannot be settled, mixing
/// strings with numbers or comparing with None, used to be dropped from the partition silently, so
/// readings on it decoded without it.
pub fn build_partitions(graph: &Graph) -> Result<HashMap<String, FieldPartition>, String> {
    if let Some(reason) = &graph.field_error {
        return Err(reason.clone());
    }
    if !graph.fields.is_empty() {
        return defined_partitions(graph);
    }
    let mut parts = HashMap::new();
    for (field, atoms) in extract_flow_atoms(graph)? {
        let kind = classify_kind(&atoms).map_err(|reason| format!("{field}: {reason}"))?;
        let part = match kind {
            FieldKind::Numeric => numeric_partition(&field, &atoms),
            FieldKind::Categorical => categorical_partition(&field, &atoms),
            FieldKind::Boolean => boolean_partition(&field),
        };
        parts.insert(field, part);
    }
    Ok(parts)
}

/// The partitions of a flow that defines its fields, the twin of quantizer.py `_defined_partitions`.
/// The parser has lowered every decimal threshold and checked every rule, so each field's kind is its
/// definition's. A comparison with None adds no cut, since it is constant across present values, and a
/// field that allows absence gets the absent cell. The engine counters keep the inferred partition.
fn defined_partitions(graph: &Graph) -> Result<HashMap<String, FieldPartition>, String> {
    let mut parts = HashMap::new();
    for (field, atoms) in extract_flow_atoms(graph)? {
        let Some(definition) = graph.fields.get(&field) else {
            let kind = classify_kind(&atoms).map_err(|reason| format!("{field}: {reason}"))?;
            let part = match kind {
                FieldKind::Numeric => numeric_partition(&field, &atoms),
                FieldKind::Categorical => categorical_partition(&field, &atoms),
                FieldKind::Boolean => boolean_partition(&field),
            };
            parts.insert(field, part);
            continue;
        };
        let present: Vec<Atom> = atoms.into_iter()
            .filter(|atom| atom.op == "truthy" || !matches!(atom.const_val, AtomConst::None))
            .collect();
        let built = match definition.kind {
            DefinedKind::Int | DefinedKind::Fixed => numeric_partition(&field, &present),
            DefinedKind::Category => categorical_partition(&field, &present),
            DefinedKind::Bool => boolean_partition(&field),
        };
        parts.insert(field, FieldPartition::defined(built, definition.clone()));
    }
    Ok(parts)
}

pub fn quantize(
    parts: &HashMap<String, FieldPartition>,
    reading: &HashMap<String, V>,
) -> Result<HashMap<String, usize>, String> {
    let mut out = HashMap::new();
    for (field, partition) in parts {
        match reading.get(field) {
            Some(value) => {
                out.insert(field.clone(), partition.symbol(value)?);
            }
            None if partition.definition.is_some() => {
                out.insert(field.clone(), partition.symbol(&V::Null)?);
            }
            None => {}
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
