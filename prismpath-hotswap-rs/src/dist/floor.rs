// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The action floor of policy distribution (spec-policy-distribution.md, section 21.2) on the `host` kind, the
//! table half of `prismpath/distribution/floor.py` in Rust.
//!
//! A `host` action floor is a `.ppt` table the PEP asks first on every request, in every state (AF1). A table's
//! policy form has no escalation, so the floor only allows (AF2): an edge of its start node that holds is an allow
//! by that edge, and anything else leaves the floor silent and the decision to what would decide with no floor.
//!
//! ```text
//! read_layout   AF10: the layout document the PEP is built with, each field's register, role, bounds and
//!               staleness bound
//! narrow        AF9, AF10: whether a floor table is narrow, `dist:floor-broad` when it is not
//! evaluate      the embedded evaluator (`ppt_eval.h`), the first edge of a node whose program holds
//! ask           what one table answers one request, and with `floor` the floor's narrow reading of it
//! Book          AF8: the durable rate counts of floor overrides, per floor rule
//! ```
//!
//! A request is the register file the table indexes, a 4 byte node prefix then a type and a value per register,
//! each a little endian `i32`, and the age in seconds of the value of each independent register (AF10). The floor
//! reads nothing more (AF6).

use super::{load, Canon2Tag, LayoutFormat, RatesFormat, Refused, BAD_FORMAT, FLOOR_BROAD, TARGET_MISMATCH};
use crate::host::{atomic_write_bytes, HostError};
use prismpath_rs::canon2::codec;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// AF9: the rules that allow, the entries of a list, the routes of a table.
pub const MAX_RULES: usize = 8;

pub const TY_NONE: i32 = 0;
pub const TY_BOOL: i32 = 1;
pub const TY_INT: i32 = 2;
pub const TY_STR: i32 = 3;
pub const OP_EQ: u8 = 0;
pub const OP_NE: u8 = 1;
pub const OP_LT: u8 = 2;
pub const OP_LE: u8 = 3;
pub const OP_GT: u8 = 4;
pub const OP_GE: u8 = 5;
pub const OP_TRUTHY: u8 = 6;
pub const OPC_NOT: u16 = 0x8000;
pub const OPC_AND: u16 = 0x8001;
pub const OPC_OR: u16 = 0x8002;
pub const OPC_TRUE: u16 = 0x8003;
pub const OPC_FALSE: u16 = 0x8004;
const STACK_MAX: usize = 64;
const HEADER: usize = 28;
const ATOM: usize = 8;
const NODE: usize = 4;
const EDGE: usize = 6;
const WORD: usize = 2;

// ------------------------------------------------------------------ AF10: the layout document


/// AF10: one field of a table kind's reading.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayoutField {
    pub max: i64,
    pub min: i64,
    pub name: String,
    pub register: i64,
    pub role: String,
    pub stale: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Layout {
    pub encoding: Canon2Tag,
    pub fields: Vec<LayoutField>,
    pub format: LayoutFormat,
}

const ROLES: [&str; 4] = ["command", "parameter", "independent", "proposer"];

/// AF10: a layout document, the canon/2 list of each field: its `name`, its `register`, its `role` (the `command`,
/// a `parameter` of it, an `independent` reading of the world the PEP takes from a source other than the
/// proposer, or a `proposer`'s reading), its bounds and `stale`, the staleness bound in seconds of an independent
/// field, which is never 0, and 0 for every other. Exactly one field is the command.
pub fn read_layout(body: &[u8]) -> Result<Layout, Refused> {
    let doc: Layout = load(body, "layout document")?;
    let mut names = std::collections::BTreeSet::new();
    let mut registers = std::collections::BTreeSet::new();
    for one in &doc.fields {
        let well_formed = !one.name.is_empty()
            && (0..=255).contains(&one.register)
            && ROLES.contains(&one.role.as_str())
            && one.min <= one.max
            && (0..=86_400).contains(&one.stale)
            && (one.stale > 0) == (one.role == "independent");
        if !well_formed || !names.insert(one.name.clone()) || !registers.insert(one.register) {
            return Err(Refused::new(BAD_FORMAT, "a layout field that does not read, repeats, or is independent with no staleness bound"));
        }
    }
    if doc.fields.is_empty() || doc.fields.iter().filter(|one| one.role == "command").count() != 1 {
        return Err(Refused::new(BAD_FORMAT, "a layout labels exactly one field as its command"));
    }
    Ok(doc)
}

/// The engineer's layout document, its fields sorted by register.
pub fn layout_body(fields: &[LayoutField]) -> Result<Vec<u8>, Refused> {
    let mut fields = fields.to_vec();
    fields.sort_by_key(|one| one.register);
    let body = codec::to_bytes(&Layout { encoding: Canon2Tag, fields, format: LayoutFormat })
        .map_err(|error| Refused::new(BAD_FORMAT, error.to_string()))?;
    read_layout(&body)?;
    Ok(body)
}

// ------------------------------------------------------------------ the table

/// One program word's tree.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tree {
    Atom(usize),
    Const(bool),
    Not(Box<Tree>),
    And(Box<Tree>, Box<Tree>),
    Or(Box<Tree>, Box<Tree>),
}

impl Tree {
    fn conjuncts(&self) -> Vec<&Tree> {
        match self {
            Tree::And(left, right) => [left.conjuncts(), right.conjuncts()].concat(),
            other => vec![other],
        }
    }

    fn atoms(&self) -> Vec<usize> {
        match self {
            Tree::Atom(index) => vec![*index],
            Tree::Const(_) => Vec::new(),
            Tree::Not(inner) => inner.atoms(),
            Tree::And(left, right) | Tree::Or(left, right) => [left.atoms(), right.atoms()].concat(),
        }
    }
}

/// An atom: the register, the comparison, the type and the value.
type AtomRow = (usize, u8, i32, i32);

/// A table read for the floor: its start node, the nodes that have edges, and for each edge of the start node its
/// target and its program.
#[derive(Debug, Clone)]
struct Table {
    start: usize,
    deciding: Vec<usize>,
    edges: Vec<(usize, Tree)>,
    atoms: Vec<AtomRow>,
}

fn u16_at(image: &[u8], at: usize) -> Option<u16> {
    image.get(at..at + 2).map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn i32_at(image: &[u8], at: usize) -> Option<i32> {
    image.get(at..at + 4).map(|bytes| i32::from_le_bytes(bytes.try_into().expect("four bytes")))
}

struct Offsets {
    atoms: usize,
    nodes: usize,
    edges: usize,
    words: usize,
    natoms: usize,
    nnodes: usize,
    start: usize,
}

fn offsets(image: &[u8]) -> Option<Offsets> {
    let header = crate::read_ppt_header(image).ok()?;
    let atoms = HEADER;
    let nodes = atoms + ATOM * usize::from(header.atoms);
    let edges = nodes + NODE * usize::from(header.nodes);
    let words = edges + EDGE * usize::from(header.edges);
    Some(Offsets {
        atoms,
        nodes,
        edges,
        words,
        natoms: usize::from(header.atoms),
        nnodes: usize::from(header.nodes),
        start: usize::from(header.start),
    })
}

fn atom_at(image: &[u8], at: usize) -> Option<AtomRow> {
    Some((usize::from(u16_at(image, at)?), *image.get(at + 2)?, i32::from(*image.get(at + 3)?), i32_at(image, at + 4)?))
}

fn program(image: &[u8], words: usize, offset: usize, count: usize) -> Option<Tree> {
    let mut stack: Vec<Tree> = Vec::new();
    for position in 0..count {
        let word = u16_at(image, words + WORD * (offset + position))?;
        match word {
            word if word < 0x8000 => stack.push(Tree::Atom(usize::from(word))),
            OPC_TRUE | OPC_FALSE => stack.push(Tree::Const(word == OPC_TRUE)),
            OPC_NOT => {
                let top = stack.pop()?;
                stack.push(Tree::Not(Box::new(top)));
            }
            OPC_AND | OPC_OR => {
                let (right, left) = (stack.pop()?, stack.pop()?);
                stack.push(if word == OPC_AND { Tree::And(Box::new(left), Box::new(right)) } else { Tree::Or(Box::new(left), Box::new(right)) });
            }
            _ => return None,
        }
    }
    (stack.len() == 1).then(|| stack.pop().expect("one value"))
}

fn read_table(image: &[u8]) -> Option<Table> {
    let at = offsets(image)?;
    let atoms = (0..at.natoms).map(|index| atom_at(image, at.atoms + ATOM * index)).collect::<Option<Vec<_>>>()?;
    let mut deciding = Vec::new();
    let mut edges = Vec::new();
    for node in 0..at.nnodes {
        let (offset, count) = (usize::from(u16_at(image, at.nodes + NODE * node)?), usize::from(u16_at(image, at.nodes + NODE * node + 2)?));
        if count > 0 {
            deciding.push(node);
        }
        if node != at.start {
            continue;
        }
        for index in 0..count {
            let edge = at.edges + EDGE * (offset + index);
            let (target, program_offset, program_count) =
                (usize::from(u16_at(image, edge)?), usize::from(u16_at(image, edge + 2)?), usize::from(u16_at(image, edge + 4)?));
            edges.push((target, program(image, at.words, program_offset, program_count)?));
        }
    }
    Some(Table { start: at.start, deciding, edges, atoms })
}

/// AF9, AF10 for the `policy.ppt` of a `host` floor whose `meta` names `command` and `layout`, on a PEP built with
/// the layout document `built`. A floor whose `layout` is not the hash of that document is `dist:target-mismatch`,
/// and a PEP built with none takes no table floor. Otherwise there is one decision node, the start node, and each
/// of its edges is a rule: at most 8, each with an equality test of the command register against one value as a
/// conjunct of the whole program, each parameter register bounded from both sides by less than its whole domain,
/// and no test of a register the layout does not label or marks the proposer's. `command` is the register the
/// layout labels its command field. None when it is narrow, else `dist:floor-broad`.
pub fn narrow(image: &[u8], command: Option<i64>, layout: Option<&super::Hex64>, built: Option<&[u8]>) -> Option<&'static str> {
    let Some(built) = built else { return Some(TARGET_MISMATCH) };
    if layout != Some(&super::Hex64::of(built)) {
        return Some(TARGET_MISMATCH);
    }
    let Ok(read) = read_layout(built) else { return Some(FLOOR_BROAD) };
    let labelled = read.fields.iter().find(|one| one.role == "command").map(|one| one.register);
    if command != labelled {
        return Some(FLOOR_BROAD);
    }
    let Some(table) = read_table(image) else { return Some(FLOOR_BROAD) };
    if table.deciding != [table.start] || table.edges.is_empty() || table.edges.len() > MAX_RULES {
        return Some(FLOOR_BROAD);
    }
    let by_register: BTreeMap<usize, &LayoutField> = read.fields.iter().map(|one| (one.register as usize, one)).collect();
    let labelled = labelled.expect("a layout labels a command") as usize;
    for (_target, tree) in &table.edges {
        let mut tests = Vec::new();
        for conjunct in tree.conjuncts() {
            if let Tree::Atom(index) = conjunct {
                let Some(atom) = table.atoms.get(*index) else { return Some(FLOOR_BROAD) };
                tests.push(*atom);
            }
        }
        if !tests.iter().any(|(register, op, kind, _)| *register == labelled && *op == OP_EQ && *kind == TY_INT) {
            return Some(FLOOR_BROAD);
        }
        for index in tree.atoms() {
            let Some(&(register, ..)) = table.atoms.get(index) else { return Some(FLOOR_BROAD) };
            if by_register.get(&register).is_none_or(|one| one.role == "proposer") {
                return Some(FLOOR_BROAD);
            }
        }
        for one in read.fields.iter().filter(|one| one.role == "parameter") {
            let (mut low, mut high): (Option<i64>, Option<i64>) = (None, None);
            for (register, op, kind, value) in &tests {
                if *register != one.register as usize || *kind != TY_INT {
                    continue;
                }
                let value = i64::from(*value);
                if matches!(*op, OP_EQ | OP_GE | OP_GT) {
                    let bound = value + i64::from(*op == OP_GT);
                    low = Some(low.map_or(bound, |low| low.max(bound)));
                }
                if matches!(*op, OP_EQ | OP_LE | OP_LT) {
                    let bound = value - i64::from(*op == OP_LT);
                    high = Some(high.map_or(bound, |high| high.min(bound)));
                }
            }
            match (low, high) {
                (Some(low), Some(high)) if !(low <= one.min && high >= one.max) => {}
                _ => return Some(FLOOR_BROAD),
            }
        }
    }
    None
}

// ------------------------------------------------------------------ the evaluator

/// The register file after its 4 byte node prefix: (type, value) per field.
fn registers(regs: &[u8]) -> Vec<(i32, i32)> {
    let body = regs.get(4..).unwrap_or_default();
    body.chunks_exact(8).map(|chunk| (i32_at(chunk, 0).expect("four bytes"), i32_at(chunk, 4).expect("four bytes"))).collect()
}

fn holds(atom: AtomRow, registers: &[(i32, i32)]) -> bool {
    let (field, op, aty, aval) = atom;
    let (rty, rval) = registers.get(field).copied().unwrap_or((TY_NONE, 0));
    let (lnum, rnum) = (matches!(rty, TY_BOOL | TY_INT), matches!(aty, TY_BOOL | TY_INT));
    match op {
        OP_EQ | OP_NE => {
            let equal = if (lnum && rnum) || (rty == TY_STR && aty == TY_STR) { rval == aval } else { rty == TY_NONE && aty == TY_NONE };
            equal == (op == OP_EQ)
        }
        OP_LT | OP_LE | OP_GT | OP_GE if lnum && rnum => match op {
            OP_LT => rval < aval,
            OP_LE => rval <= aval,
            OP_GT => rval > aval,
            _ => rval >= aval,
        },
        OP_TRUTHY => rty != TY_NONE && rval != 0,
        _ => false,
    }
}

/// The evaluator could not read the table: a program word that is no opcode, a stack past its bound or an offset
/// past the image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvalError;

/// `ppt_eval.h` `evaluate`: (edge index, target node) of the first edge of `node` whose program holds, Ok(None)
/// when none does.
pub fn evaluate(image: &[u8], regs: &[u8], node: usize) -> Result<Option<(usize, usize)>, EvalError> {
    let at = offsets(image).ok_or(EvalError)?;
    let registers = registers(regs);
    let (offset, count) = (usize::from(u16_at(image, at.nodes + NODE * node).ok_or(EvalError)?), usize::from(u16_at(image, at.nodes + NODE * node + 2).ok_or(EvalError)?));
    for index in 0..count {
        let edge = at.edges + EDGE * (offset + index);
        let (target, program_offset, program_count) = (
            usize::from(u16_at(image, edge).ok_or(EvalError)?),
            usize::from(u16_at(image, edge + 2).ok_or(EvalError)?),
            usize::from(u16_at(image, edge + 4).ok_or(EvalError)?),
        );
        let mut stack: Vec<bool> = Vec::new();
        for position in 0..program_count {
            let word = u16_at(image, at.words + WORD * (program_offset + position)).ok_or(EvalError)?;
            match word {
                word if word < 0x8000 || word == OPC_TRUE || word == OPC_FALSE => {
                    if stack.len() >= STACK_MAX {
                        return Err(EvalError);
                    }
                    let value = if word >= 0x8000 { word == OPC_TRUE } else { holds(atom_at(image, at.atoms + ATOM * usize::from(word)).ok_or(EvalError)?, &registers) };
                    stack.push(value);
                }
                OPC_NOT => {
                    let top = stack.last_mut().ok_or(EvalError)?;
                    *top = !*top;
                }
                OPC_AND | OPC_OR => {
                    let right = stack.pop().ok_or(EvalError)?;
                    let left = stack.last_mut().ok_or(EvalError)?;
                    *left = if word == OPC_AND { *left && right } else { *left || right };
                }
                _ => return Err(EvalError),
            }
        }
        if stack.first().copied().unwrap_or(false) {
            return Ok(Some((index, target)));
        }
    }
    Ok(None)
}

/// A request to a `host` PEP: the register file and the age in seconds of each independent register's value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Request {
    pub regs: Vec<u8>,
    pub ages: BTreeMap<usize, i64>,
}

/// What one set answers one request: `allow` or `refuse`, or None when it cannot read it (silent), with the cause
/// and the rule that answered, the count key of AF8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub outcome: Option<&'static str>,
    pub cause: Option<&'static str>,
    pub rule: Option<String>,
}

pub const ALLOW: &str = "allow";
pub const REFUSE: &str = "refuse";
pub const NO_EDGE: &str = "route:no-matching-edge";

impl Answer {
    pub const SILENT: Answer = Answer { outcome: None, cause: None, rule: None };

    pub fn allows(&self) -> bool {
        self.outcome == Some(ALLOW)
    }
}

/// The answer of the table `image` to `request`: an allow by the first edge of the start node that holds, a refusal
/// with `route:no-matching-edge` when none does, silent when it does not read. With `floor` the table is an action
/// floor read under the layout `built`: a rule that tests an independent register whose value is absent or older
/// than its staleness bound is silent (AF10).
pub fn ask(image: &[u8], request: &Request, floor: bool, built: Option<&[u8]>) -> Answer {
    let Some(start) = offsets(image).map(|at| at.start) else { return Answer::SILENT };
    let edge = match evaluate(image, &request.regs, start) {
        Err(EvalError) => return Answer::SILENT,
        Ok(None) => return Answer { outcome: Some(REFUSE), cause: Some(NO_EDGE), rule: None },
        Ok(Some((edge, _target))) => edge,
    };
    if floor {
        let layout = built.and_then(|body| read_layout(body).ok());
        let (Some(layout), Some(table)) = (layout, read_table(image)) else { return Answer::SILENT };
        for index in table.edges.get(edge).map(|(_, tree)| tree.atoms()).unwrap_or_default() {
            let Some(atom) = table.atoms.get(index) else { return Answer::SILENT };
            let Some(one) = layout.fields.iter().find(|one| one.register as usize == atom.0) else { continue };
            if one.role == "independent" && request.ages.get(&atom.0).is_none_or(|age| *age < 0 || *age > one.stale) {
                return Answer::SILENT;
            }
        }
    }
    Answer { outcome: Some(ALLOW), cause: None, rule: Some(format!("policy.ppt:{edge}")) }
}

// ------------------------------------------------------------------ AF8: the rate counts


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RatesDoc {
    encoding: Canon2Tag,
    format: RatesFormat,
    rules: BTreeMap<String, (i64, i64)>,
}

/// AF8: the rate counts of one PEP, kept beside its install record in both copies (IS10). `rules` maps a floor rule
/// to (window start, overrides counted in it). Every change is written before the PEP acts on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Book {
    paths: [String; 2],
    pub rules: BTreeMap<String, (i64, i64)>,
}

impl Book {
    /// The book from the first copy that reads, or an empty one.
    pub fn load(paths: [String; 2]) -> Book {
        let rules = paths.iter().find_map(|path| std::fs::read(path).ok().and_then(|raw| load::<RatesDoc>(&raw, "rate counts").ok()));
        Book { rules: rules.map(|doc| doc.rules).unwrap_or_default(), paths }
    }

    fn save(&self) -> Result<(), HostError> {
        let doc = RatesDoc { encoding: Canon2Tag, format: RatesFormat, rules: self.rules.clone() };
        let raw = codec::to_bytes(&doc).map_err(|error| HostError::Canonical(format!("rate counts: {error}")))?;
        for path in &self.paths {
            if let Some(parent) = std::path::Path::new(path).parent() {
                std::fs::create_dir_all(parent).map_err(|error| HostError::Io(format!("{}: {error}", parent.display())))?;
            }
            atomic_write_bytes(path, &raw)?;
        }
        Ok(())
    }

    /// AF8: count one override of `rule` under `rate`, durably, and answer (window start, count after it), or None
    /// when the rate is spent and nothing was counted. A fixed window of the PEP's own time starts once `window`
    /// seconds passed since the start.
    pub fn spend(&mut self, rule: &str, rate: super::install::Rate, now: i64) -> Result<Option<(i64, i64)>, HostError> {
        let (start, count) = self.rules.get(rule).copied().unwrap_or((0, 0));
        let (start, count) = if count == 0 || now >= start + rate.window || now < start { (now, 0) } else { (start, count) };
        if count >= rate.allows {
            return Ok(None);
        }
        self.rules.insert(rule.to_string(), (start, count + 1));
        self.save()?;
        Ok(Some((start, count + 1)))
    }
}
