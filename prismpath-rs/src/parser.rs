// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Markdown flow parser.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::condition::{is_js_ws, is_py_ws, js_trim, py_trim, split_lines_py};

/// File suffix that identifies a rules source rather than a workflow document.
pub const RULES_SUFFIX: &str = ".rules.md";

/// The input bounds of the reference parser (`kernel/parser.py`): a flow is human authored routing config, not
/// a data payload, and these keep an untrusted or accidental oversized document from exhausting memory or
/// driving the polynomial analyses off a cliff. Each is overridden by the environment variable of the same
/// name as the reference's constant, `PRISMPATH_MAX_FLOW_BYTES`, `PRISMPATH_MAX_NODES` and `PRISMPATH_MAX_EDGES`.
pub const DEFAULT_MAX_FLOW_BYTES: i64 = 2 * 1024 * 1024;
pub const DEFAULT_MAX_NODES: i64 = 5000;
pub const DEFAULT_MAX_EDGES: i64 = 20000;

/// Bounds on a flow document. A cap below zero refuses every document, as the reference's does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// The most characters a document may have (the reference counts `len(text)`, characters not bytes).
    pub max_flow_bytes: i64,
    /// The most distinct node names.
    pub max_nodes: i64,
    /// The most edge lines under a heading.
    pub max_edges: i64,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits { max_flow_bytes: DEFAULT_MAX_FLOW_BYTES, max_nodes: DEFAULT_MAX_NODES, max_edges: DEFAULT_MAX_EDGES }
    }
}

impl Limits {
    /// The limits the environment gives: each variable read as Python's `int()` reads it (a sign, digits with
    /// single underscores between them, spaces around). The reference reads them once when it is imported, and
    /// a value that is not an integer stops the import; here it refuses every document, naming the variable,
    /// and so does a value beyond a 64 bit integer.
    pub fn from_env() -> Result<Limits, String> {
        fn read(name: &str, default: i64) -> Result<i64, String> {
            match std::env::var(name) {
                Ok(raw) => Limits::read_value(name, &raw),
                Err(_) => Ok(default),
            }
        }
        Ok(Limits {
            max_flow_bytes: read("PRISMPATH_MAX_FLOW_BYTES", DEFAULT_MAX_FLOW_BYTES)?,
            max_nodes: read("PRISMPATH_MAX_NODES", DEFAULT_MAX_NODES)?,
            max_edges: read("PRISMPATH_MAX_EDGES", DEFAULT_MAX_EDGES)?,
        })
    }

    /// What the variable `name` holding `raw` means: the integer Python's `int(raw)` makes of it, or the reason
    /// it is refused. The digits of other scripts, which `int()` reads, are refused, and so is a value
    /// beyond a 64 bit integer.
    pub fn read_value(name: &str, raw: &str) -> Result<i64, String> {
        let Some((negative, digits)) = crate::engine::py_int_text(raw) else {
            return Err(format!("{name} is not an integer: {}", crate::contract::py_str_repr(raw)));
        };
        let magnitude: i64 = digits
            .parse()
            .map_err(|_| format!("{name} is beyond a 64 bit integer: {}", crate::contract::py_str_repr(raw)))?;
        Ok(if negative { -magnitude } else { magnitude })
    }
}

fn env_limits() -> &'static Result<Limits, String> {
    static LIMITS: OnceLock<Result<Limits, String>> = OnceLock::new();
    LIMITS.get_or_init(Limits::from_env)
}

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
    /// The node names in document order, each at its first heading (the order the reference's
    /// dictionary iterates), which the type gate's contract and the flow's state bound read in.
    pub order: Vec<String>,
    /// Every front matter `key: value` line, as the reference keeps it.
    pub meta: HashMap<String, String>,
    /// The field definitions (SPEC section 4.5), keyed by field name; empty when the flow defines none.
    pub fields: std::collections::BTreeMap<String, crate::field_definitions::FieldDefinition>,
    /// Why the flow breaks its field definitions, when it does. Such a graph has every edge disabled,
    /// the engine refuses to run it, and the codec refuses to partition it.
    pub field_error: Option<String>,
    /// The registered cause (prismpath/kernel/causes.py) of the first problem in `field_error`, as the
    /// reference's `FieldDefinitionError.cause` names it; `None` exactly when `field_error` is.
    pub field_error_cause: Option<&'static str>,
    /// The field the first problem names, where its refusal names one (the oracle's `field`).
    pub field_error_field: Option<String>,
    /// The reason the first problem names, where its refusal names one (the oracle's `reason`).
    pub field_error_reason: Option<&'static str>,
    /// The registered cause of every problem in `field_error`, in the order of the core's checks
    /// (docs/design/spec-verified-core.md, section 4): the first is `field_error_cause`.
    pub field_error_causes: Vec<&'static str>,
    /// Why the document could not be parsed at all, when it could not: it is over one of the `Limits`, or it
    /// is a rules source rather than a flow. Such a graph is empty, and the reference raises `ParseError` (or
    /// its subclass `RulesSourceError`) with this message instead of returning one.
    pub parse_error: Option<String>,
    /// True when `parse_error` was raised because the document is a rules source (Python's `RulesSourceError`,
    /// a subclass of `ParseError`).
    pub rules_source_error: bool,
}

impl Graph {
    /// Why this graph must not be run, analysed or encoded: it was not parsed (`parse_error`) or it breaks its
    /// field definitions (`field_error`).
    pub fn refusal(&self) -> Option<&str> {
        self.parse_error.as_deref().or(self.field_error.as_deref())
    }
}

/// -> target: condition (optionally as a - bullet): EDGE_RE.
fn match_edge(line: &str) -> Option<(String, String)> {
    let line_chars: Vec<char> = line.chars().collect();
    let mut pos = 0;
    while pos < line_chars.len() && is_js_ws(line_chars[pos]) {
        pos += 1;
    }
    // the optional bullet -
    if pos < line_chars.len() && line_chars[pos] == '-' && !(pos + 1 < line_chars.len() && line_chars[pos + 1] == '>') {
        pos += 1;
        while pos < line_chars.len() && is_js_ws(line_chars[pos]) {
            pos += 1;
        }
    }
    if !(pos + 1 < line_chars.len() && line_chars[pos] == '-' && line_chars[pos + 1] == '>') {
        return None;
    }
    pos += 2;
    while pos < line_chars.len() && is_js_ws(line_chars[pos]) {
        pos += 1;
    }
    let target_start = pos;
    while pos < line_chars.len() && (line_chars[pos].is_ascii_alphanumeric() || line_chars[pos] == '_' || line_chars[pos] == '-') {
        pos += 1;
    }
    if pos == target_start {
        return None;
    }
    let target: String = line_chars[target_start..pos].iter().collect();
    while pos < line_chars.len() && is_js_ws(line_chars[pos]) {
        pos += 1;
    }
    if pos >= line_chars.len() || line_chars[pos] != ':' {
        return None;
    }
    pos += 1;
    let rest: String = line_chars[pos..].iter().collect();
    if rest.is_empty() {
        return None;
    }
    Some((target, js_trim(&rest).to_string()))
}

/// ## heading: HEAD_RE
fn match_head(line: &str) -> Option<String> {
    let line_chars: Vec<char> = line.chars().collect();
    let mut pos = 0;
    while pos < line_chars.len() && is_js_ws(line_chars[pos]) {
        pos += 1;
    }
    if !(pos + 1 < line_chars.len() && line_chars[pos] == '#' && line_chars[pos + 1] == '#') {
        return None;
    }
    pos += 2;
    if pos >= line_chars.len() || !is_js_ws(line_chars[pos]) {
        return None;
    }
    if pos + 1 >= line_chars.len() {
        return None;
    }
    let rest: String = line_chars[pos + 1..].iter().collect();
    Some(js_trim(&rest).to_string())
}

/// @name(args): ANNO_RE
fn match_anno(line: &str) -> Option<(String, String)> {
    let line_chars: Vec<char> = line.chars().collect();
    let mut pos = 0;
    while pos < line_chars.len() && is_js_ws(line_chars[pos]) {
        pos += 1;
    }
    if pos >= line_chars.len() || line_chars[pos] != '@' {
        return None;
    }
    pos += 1;
    let name_start = pos;
    while pos < line_chars.len() && (line_chars[pos].is_alphanumeric() || line_chars[pos] == '_') {
        pos += 1;
    }
    if pos == name_start || pos >= line_chars.len() || line_chars[pos] != '(' {
        return None;
    }
    let name: String = line_chars[name_start..pos].iter().collect();
    let mut close_pos = None;
    for scan in (pos + 1..line_chars.len()).rev() {
        if line_chars[scan] == ')' && line_chars[scan + 1..].iter().all(|ch| is_js_ws(*ch)) {
            close_pos = Some(scan);
            break;
        }
    }
    let close_pos = close_pos?;
    let args: String = line_chars[pos + 1..close_pos].iter().collect();
    Some((name, args))
}

fn parse_anno_args(argstr: &str) -> Vec<(String, Option<String>)> {
    let mut args = Vec::new();
    for part in argstr.split(',') {
        let part_trimmed = js_trim(part);
        if part_trimmed.is_empty() {
            continue;
        }
        match part_trimmed.find('=') {
            Some(equals_pos) => {
                let key = js_trim(&part_trimmed[..equals_pos]);
                if !key.is_empty() {
                    args.push((key.to_string(), Some(js_trim(&part_trimmed[equals_pos + 1..]).to_string())));
                }
            }
            None => args.push((part_trimmed.to_string(), None)),
        }
    }
    args
}

/// Split off YAML frontmatter.
fn split_frontmatter(text: &str) -> Option<(String, String)> {
    let text_chars: Vec<char> = text.chars().collect();
    if text_chars.len() < 3 || text_chars[0] != '-' || text_chars[1] != '-' || text_chars[2] != '-' {
        return None;
    }
    let mut pos = 3;
    let mut last_newline = None;
    while pos < text_chars.len() && is_js_ws(text_chars[pos]) {
        if text_chars[pos] == '\n' {
            last_newline = Some(pos);
        }
        pos += 1;
    }
    let body_start = last_newline? + 1;
    let mut scan = body_start;
    while scan + 3 < text_chars.len() {
        if text_chars[scan] == '\n' && text_chars[scan + 1] == '-' && text_chars[scan + 2] == '-' && text_chars[scan + 3] == '-' {
            let mut lookahead = scan + 4;
            let mut newline2 = None;
            while lookahead < text_chars.len() && is_js_ws(text_chars[lookahead]) {
                if text_chars[lookahead] == '\n' {
                    newline2 = Some(lookahead);
                }
                lookahead += 1;
            }
            if let Some(newline2) = newline2 {
                let meta: String = text_chars[body_start..scan].iter().collect();
                let rest: String = text_chars[newline2 + 1..].iter().collect();
                return Some((meta, rest));
            }
        }
        scan += 1;
    }
    None
}

/// A rule of a rules source (`-> refuse <cause>:` or `-> escalate <cause>:`): RULES_LINE_RE.
fn match_rules_line(line: &str) -> bool {
    let line_chars: Vec<char> = line.chars().collect();
    let mut pos = 0;
    while pos < line_chars.len() && is_py_ws(line_chars[pos]) {
        pos += 1;
    }
    if pos < line_chars.len()
        && line_chars[pos] == '-'
        && !(pos + 1 < line_chars.len() && line_chars[pos + 1] == '>')
    {
        pos += 1;
        while pos < line_chars.len() && is_py_ws(line_chars[pos]) {
            pos += 1;
        }
    }
    if !(pos + 1 < line_chars.len() && line_chars[pos] == '-' && line_chars[pos + 1] == '>') {
        return false;
    }
    pos += 2;
    while pos < line_chars.len() && is_py_ws(line_chars[pos]) {
        pos += 1;
    }
    let rest: String = line_chars[pos..].iter().collect();
    let after_kw = if let Some(tail) = rest.strip_prefix("refuse") {
        tail
    } else if let Some(tail) = rest.strip_prefix("escalate") {
        tail
    } else {
        return false;
    };
    let tail_chars: Vec<char> = after_kw.chars().collect();
    let mut tpos = 0;
    while tpos < tail_chars.len() && is_py_ws(tail_chars[tpos]) {
        tpos += 1;
    }
    if tpos == 0 {
        return false;
    }
    let tok_start = tpos;
    while tpos < tail_chars.len() && !is_py_ws(tail_chars[tpos]) {
        tpos += 1;
    }
    tpos - tok_start >= 2 && tail_chars[tpos - 1] == ':'
}

fn rules_source_line_message(line_number: usize) -> String {
    format!(
        "line {line_number} is a rule of a rules source, not a flow edge. A rules source is compiled with \
         `prismpath policy compile` and read back with `prismpath policy render`"
    )
}

fn rules_source_file_message(basename: &str) -> String {
    format!(
        "{basename} is a rules source, not a flow. A rules source is compiled with \
         `prismpath policy compile` and read back with `prismpath policy render`"
    )
}

fn basename_of(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// The graph of a document that is over a bound: empty, with the reason.
fn refused(reason: String) -> Graph {
    Graph { parse_error: Some(reason), ..Default::default() }
}

/// The graph of a document refused as a rules source: empty, with `parse_error` and `rules_source_error` set.
fn refused_rules_source(reason: String) -> Graph {
    Graph { parse_error: Some(reason), rules_source_error: true, ..Default::default() }
}

/// Markdown -> Graph: a faithful port of the reference parse, within the bounds of `Limits::from_env`. A node
/// with no edges is terminal. A document over a bound or a rules source has `parse_error` set and no nodes
/// (see `parse_checked`).
pub fn parse(text: &str) -> Graph {
    match env_limits() {
        Ok(limits) => parse_with_limits(text, limits),
        Err(reason) => refused(reason.clone()),
    }
}

/// `parse`, also refusing a document whose filename ends with `.rules.md` as a rules source.
pub fn parse_named(text: &str, filename: Option<&str>) -> Graph {
    if let Some(name) = filename {
        let base = basename_of(name);
        if base.ends_with(RULES_SUFFIX) {
            return refused_rules_source(rules_source_file_message(base));
        }
    }
    parse(text)
}

/// Read and parse a flow file on disk, refusing oversized files and `.rules.md` rules sources before parsing.
pub fn parse_file(path: impl AsRef<std::path::Path>) -> Result<Graph, String> {
    let path = path.as_ref();
    let limits = match env_limits() {
        Ok(limits) => limits,
        Err(reason) => return Err(reason.clone()),
    };
    let basename = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
    let metadata = std::fs::metadata(path)
        .map_err(|err| format!("failed to stat flow file {basename:?}: {err}"))?;
    if metadata.len() as i128 > limits.max_flow_bytes as i128 {
        return Err(format!(
            "flow file '{}' is {} bytes, exceeds PRISMPATH_MAX_FLOW_BYTES ({})",
            basename,
            metadata.len(),
            limits.max_flow_bytes
        ));
    }
    if basename.ends_with(RULES_SUFFIX) {
        return Err(rules_source_file_message(basename));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read flow file {basename:?}: {err}"))?;
    let graph = parse_with_limits(&text, limits);
    match graph.refusal() {
        Some(reason) => Err(reason.to_string()),
        None => Ok(graph),
    }
}

/// `parse` with the bounds given. The messages are the reference's: `flow document exceeds
/// PRISMPATH_MAX_FLOW_BYTES (N bytes)`, `... PRISMPATH_MAX_NODES (N nodes)` and `... PRISMPATH_MAX_EDGES (N
/// edges)`, raised in the order the document reaches them (the size first, before any work).
pub fn parse_with_limits(text: &str, limits: &Limits) -> Graph {
    // the size is a character count, as the reference's `len(text)` is: the figure that governs the in memory
    // string and the line scan
    if text.chars().count() as i128 > limits.max_flow_bytes as i128 {
        return refused(format!("flow document exceeds PRISMPATH_MAX_FLOW_BYTES ({} bytes)", limits.max_flow_bytes));
    }
    let mut edge_count: i64 = 0;
    let mut meta: HashMap<String, String> = HashMap::new();
    let body = match split_frontmatter(text) {
        Some((frontmatter, body_text)) => {
            for line in split_lines_py(&frontmatter) {
                if let Some(colon_pos) = line.find(':') {
                    // the reference strips both with `str.strip()`: Python's whitespace, which a field
                    // definition's words are also split on (D3), not JS trim's
                    meta.insert(
                        py_trim(&line[..colon_pos]).to_string(),
                        py_trim(&line[colon_pos + 1..]).to_string(),
                    );
                }
            }
            body_text
        }
        None => text.to_string(),
    };

    let mut nodes: HashMap<String, Node> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    let mut current_node: Option<String> = None;
    let mut instructions: Vec<String> = Vec::new();

    fn flush(
        cur_node: &Option<String>,
        instr_vec: &[String],
        nodes_map: &mut HashMap<String, Node>,
    ) {
        if let Some(name) = cur_node {
            if let Some(node) = nodes_map.get_mut(name) {
                node.instruction = js_trim(&instr_vec.join("\n")).to_string();
            }
        }
    }

    let body_offset = text[..text.len() - body.len()].bytes().filter(|&b| b == b'\n').count();
    for (idx, line) in split_lines_py(&body).into_iter().enumerate() {
        if match_rules_line(line) {
            return refused_rules_source(rules_source_line_message(body_offset + idx + 1));
        }
        if let Some(heading_text) = match_head(line) {
            flush(&current_node, &instructions, &mut nodes);
            let name = heading_text.to_lowercase().replace(' ', "_");
            // distinct node names are counted: a heading that reuses a name is not a new node
            if !nodes.contains_key(&name) && nodes.len() as i64 >= limits.max_nodes {
                return refused(format!("flow document exceeds PRISMPATH_MAX_NODES ({} nodes)", limits.max_nodes));
            }
            nodes.insert(name.clone(), Node { name: name.clone(), ..Default::default() });
            if !order.contains(&name) {
                order.push(name.clone());
            }
            current_node = Some(name);
            instructions = Vec::new();
            continue;
        }
        let Some(cur_name) = &current_node else { continue };
        if let Some((target, cond)) = match_edge(line) {
            edge_count += 1;
            if edge_count > limits.max_edges {
                return refused(format!("flow document exceeds PRISMPATH_MAX_EDGES ({} edges)", limits.max_edges));
            }
            nodes.get_mut(cur_name).expect("cur names an inserted node").edges.push((target, cond));
        } else if let Some((anno_name, argstr)) = match_anno(line) {
            let node = nodes.get_mut(cur_name).expect("cur names an inserted node");
            let entry = node.annotations.entry(anno_name).or_default();
            for (key, val) in parse_anno_args(&argstr) {
                entry.insert(key, val);
            }
        } else {
            instructions.push(line.to_string());
        }
    }
    flush(&current_node, &instructions, &mut nodes);

    let start = match meta.get("start") {
        Some(start_node) if !start_node.is_empty() => start_node.clone(),
        _ => order.first().cloned().unwrap_or_default(),
    };
    let name = meta.get("name").cloned().unwrap_or_else(|| "flow".to_string());
    let mut graph = Graph { name, start, nodes, order, meta, ..Default::default() };
    crate::field_definitions::apply_definitions(&mut graph);
    graph
}

/// `parse`, returning the reason instead of a disabled graph when the flow breaks its field definitions.
pub fn parse_checked(text: &str) -> Result<Graph, String> {
    let graph = parse(text);
    match graph.refusal() {
        Some(reason) => Err(reason.to_string()),
        None => Ok(graph),
    }
}
