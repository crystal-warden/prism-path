// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The Rust leg of the verified core's differential harness (formal/diff/core_diff.py). It is an
//! adapter, not part of the kernel: it composes the kernel's own public functions exactly as the
//! frozen field definition vectors do (`tests/test_field_definitions.rs`) and prints what they decide.
//!
//! Input on stdin, one case after another: `case <id> <n>\n`, then the policy image, the flow text
//! and `n` reading documents, each framed as `<byte length>\n<bytes>\n`. The image and the readings are
//! canon/2 documents, read here with `canon2::read`; the flow is the image's rendering, which the harness
//! writes. A flow of length 0 means the image has no flow rendering, and the case is reported as such.
//! Output: one JSON line per case.

use prismpath_rs::canon2::{self, Doc};
use prismpath_rs::{accept_canonical, causes, first_deterministic, parse, Value};
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

/// A refusal with its registered code, as the oracle prints one.
fn refuse(cause: &str, mut detail: serde_json::Value) -> serde_json::Value {
    detail["verdict"] = "refuse".into();
    detail["cause"] = cause.into();
    detail["code"] = causes::code(cause).into();
    detail
}

fn reading_verdict(graph: &prismpath_rs::Graph, bytes: &[u8]) -> serde_json::Value {
    let document = match canon2::read(bytes) {
        Ok(document) => document,
        Err(error) => return refuse("reading:unreadable", serde_json::json!({"reason": error.rule()})),
    };
    let Doc::Obj(members) = document else {
        return refuse("reading:not-object", serde_json::json!({}));
    };
    let values: HashMap<String, Value> = members.iter().map(|(key, value)| (key.clone(), value.to_value())).collect();
    for (field, definition) in &graph.fields {
        if let Err(reason) = accept_canonical(definition, values.get(field).unwrap_or(&Value::Null)) {
            return refuse("route:contract-violation", serde_json::json!({"field": field, "reason": reason}));
        }
    }
    match first_deterministic(&graph.nodes[&graph.start].edges, &values) {
        Some((target, _)) => serde_json::json!({"verdict": "route", "target": target}),
        None => refuse("route:no-matching-edge", serde_json::json!({})),
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
        let image = read_frame(&input, &mut pos).expect("image frame");
        let flow = read_frame(&input, &mut pos).expect("flow frame");
        let readings: Vec<&[u8]> = (0..count).map(|_| read_frame(&input, &mut pos).expect("reading frame")).collect();
        let line = if let Err(error) = canon2::read(image) {
            serde_json::json!({"id": parts[1], "policy": "refused", "cause": "policy:unreadable", "reason": error.rule(),
                               "code": causes::code("policy:unreadable"), "causes": ["policy:unreadable"]})
        } else if flow.is_empty() {
            serde_json::json!({"id": parts[1], "policy": "unrenderable"})
        } else {
            let flow_text = std::str::from_utf8(flow).expect("a rendered flow is UTF-8");
            let graph = parse(flow_text);
            match graph.refusal() {
                Some(reason) => {
                    // the registered cause of the first problem, and of every problem the port found
                    let cause = graph.field_error_cause;
                    serde_json::json!({"id": parts[1], "policy": "refused", "reason": reason, "cause": cause,
                                       "code": cause.and_then(causes::code), "causes": graph.field_error_causes})
                }
                None => {
                    let verdicts: Vec<serde_json::Value> = readings.iter().map(|bytes| reading_verdict(&graph, bytes)).collect();
                    serde_json::json!({"id": parts[1], "policy": "accepted", "defines": !graph.fields.is_empty(), "readings": verdicts})
                }
            }
        };
        writeln!(out, "{line}").expect("write");
    }
    out.flush().expect("flush");
}
