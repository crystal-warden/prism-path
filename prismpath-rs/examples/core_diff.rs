// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The Rust leg of the verified core's differential harness (formal/diff/core_diff.py). It is an
//! adapter, not part of the kernel: it composes the kernel's own public functions exactly as the
//! frozen field definition vectors do (`tests/test_field_definitions.rs`) and prints what they decide.
//!
//! Input on stdin, one case after another: `case <id> <n>\n`, then the flow text and `n` reading
//! documents, each framed as `<byte length>\n<bytes>\n`. A flow of length 0 means the image has no
//! flow rendering, and the case is reported as such. Output: one JSON line per case.

use prismpath_rs::value::parse_strict;
use prismpath_rs::{accept_canonical, first_deterministic, parse_checked, Value};
use std::collections::HashMap;
use std::io::{Read, Write};

fn read_line(input: &[u8], pos: &mut usize) -> Option<String> {
    let end = input[*pos..].iter().position(|byte| *byte == b'\n')? + *pos;
    let line = String::from_utf8(input[*pos..end].to_vec()).ok()?;
    *pos = end + 1;
    Some(line)
}

fn read_frame<'a>(input: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let length: usize = read_line(input, pos)?.parse().ok()?;
    let frame = input.get(*pos..*pos + length)?;
    *pos += length + 1;
    Some(frame)
}

fn reading_verdict(graph: &prismpath_rs::Graph, bytes: &[u8]) -> serde_json::Value {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return serde_json::json!({"verdict": "refuse", "cause": "reading:unreadable", "reason": "utf8"});
    };
    let document = match parse_strict(text) {
        Ok(document) => document,
        Err(error) => return serde_json::json!({"verdict": "refuse", "cause": "reading:unreadable", "reason": error.to_string()}),
    };
    let Some(object) = document.as_object() else {
        return serde_json::json!({"verdict": "refuse", "cause": "reading:not-object"});
    };
    let mut values: HashMap<String, Value> = HashMap::new();
    for (key, value) in object {
        match Value::try_from_json(value) {
            Ok(converted) => {
                values.insert(key.clone(), converted);
            }
            Err(error) => return serde_json::json!({"verdict": "refuse", "cause": "reading:unreadable", "reason": error}),
        }
    }
    for (field, definition) in &graph.fields {
        if let Err(reason) = accept_canonical(definition, values.get(field).unwrap_or(&Value::Null)) {
            return serde_json::json!({"verdict": "refuse", "cause": "route:contract-violation", "field": field, "reason": reason});
        }
    }
    match first_deterministic(&graph.nodes[&graph.start].edges, &values) {
        Some((target, _)) => serde_json::json!({"verdict": "route", "target": target}),
        None => serde_json::json!({"verdict": "refuse", "cause": "route:no-matching-edge"}),
    }
}

fn main() {
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).expect("read stdin");
    let mut out = std::io::BufWriter::new(std::io::stdout());
    let mut pos = 0;
    while pos < input.len() {
        let header = read_line(&input, &mut pos).expect("case header");
        let parts: Vec<&str> = header.split(' ').collect();
        assert!(parts.len() == 3 && parts[0] == "case", "malformed case header {header:?}");
        let count: usize = parts[2].parse().expect("reading count");
        let flow = read_frame(&input, &mut pos).expect("flow frame");
        let readings: Vec<&[u8]> = (0..count).map(|_| read_frame(&input, &mut pos).expect("reading frame")).collect();
        let line = if flow.is_empty() {
            serde_json::json!({"id": parts[1], "policy": "unrenderable"})
        } else {
            let flow_text = std::str::from_utf8(flow).expect("a rendered flow is UTF-8");
            match parse_checked(flow_text) {
                Err(reason) => serde_json::json!({"id": parts[1], "policy": "refused", "reason": reason}),
                Ok(graph) => {
                    let verdicts: Vec<serde_json::Value> = readings.iter().map(|bytes| reading_verdict(&graph, bytes)).collect();
                    serde_json::json!({"id": parts[1], "policy": "accepted", "defines": !graph.fields.is_empty(), "readings": verdicts})
                }
            }
        };
        writeln!(out, "{line}").expect("write");
    }
    out.flush().expect("flush");
}
