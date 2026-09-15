// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Markdown flow parser.

use std::collections::HashMap;

use crate::condition::{is_js_ws, js_trim, split_lines_py};

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

/// Markdown -> Graph: a faithful port of the reference parse. A node with no edges is terminal.
pub fn parse(text: &str) -> Graph {
    let mut meta: HashMap<String, String> = HashMap::new();
    let body = match split_frontmatter(text) {
        Some((frontmatter, body_text)) => {
            for line in split_lines_py(&frontmatter) {
                if let Some(colon_pos) = line.find(':') {
                    meta.insert(
                        js_trim(&line[..colon_pos]).to_string(),
                        js_trim(&line[colon_pos + 1..]).to_string(),
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

    for line in split_lines_py(&body) {
        if let Some(heading_text) = match_head(line) {
            flush(&current_node, &instructions, &mut nodes);
            let name = heading_text.to_lowercase().replace(' ', "_");
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
    Graph { name, start, nodes }
}
