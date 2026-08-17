// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! prismpath-preflight: will YOUR events survive the Facet codec? One command, one report.
//!
//! Formerly published as `facet-preflight` (0.1.0, yanked): the `facet-*` prefix belongs to the
//! facet reflection ecosystem on crates.io, and this crate moved out of it the day that was
//! flagged. Same code, same contract, new name.
//!
//! Same contract as the Python reference tool (`adapters/telemetry/preflight.py`), but running on
//! the exact crates the Vector codec is built from — so what this reports IS what the codec will
//! do, by construction, including the places the Rust value model differs from the reference
//! (a non-numeric string on a numeric field is coerced to 0 here, where the reference errors;
//! this tool surfaces that as its own finding). Running both tools on one sample is a free
//! differential test of the whole stack.

use std::collections::HashMap;
use std::io::BufRead;

use prismpath_rs::{parse, py_truthy, Graph, V};
use prismpath_telemetry_rs::quantizer::{self, FieldKind, FieldPartition};
use prismpath_telemetry_rs::{packed, wire, zeckendorf};
use serde_json::{json, Value};

pub struct Config {
    pub flow: String,
    pub sample: String,
    pub field_paths: HashMap<String, String>,
    pub on_missing_skip: bool,
    pub route_node: Option<String>,
    pub limit: Option<usize>,
}

pub struct Outcome {
    pub markdown: String,
    pub report: Value,
    pub ready: bool,
}

// Mirrors of the quantizer's private coercions (quantizer.rs `v_to_i64` / `v_to_str`): the
// preflight must route the SAME view of a value that `symbol()` quantizes, or float truncation
// and string coercion would show up as false round-trip mismatches.
fn v_to_i64(value: &V) -> i64 {
    match value {
        V::Num(n) => *n as i64,
        V::Bool(b) => i64::from(*b),
        V::Str(s) => s.parse::<i64>().unwrap_or(0),
        _ => 0,
    }
}

fn v_to_str(value: &V) -> String {
    match value {
        V::Str(s) => s.clone(),
        V::Num(n) => n.to_string(),
        V::Bool(b) => if *b { "True".into() } else { "False".into() },
        _ => String::new(),
    }
}

/// Dot-path lookup, mirroring the codec's `parse_path_and_get_value`: absent and JSON null are
/// both "missing", exactly as the encoder treats them.
fn walk_path<'a>(event: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = event;
    for part in path.trim_start_matches('.').split('.') {
        cur = cur.as_object()?.get(part)?;
    }
    if cur.is_null() { None } else { Some(cur) }
}

fn cells_desc(p: &FieldPartition) -> String {
    match p.kind {
        FieldKind::Numeric => p.cells.iter()
            .map(|c| format!("[{}..{}]",
                c.lo.map_or("-inf".into(), |l| l.to_string()),
                c.hi.map_or("+inf".into(), |h| h.to_string())))
            .collect::<Vec<_>>().join(" "),
        FieldKind::Boolean => "[false] [true]".into(),
        FieldKind::Categorical => {
            let mut out: Vec<String> = p.cells.iter()
                .filter_map(|c| c.const_val.as_ref())
                .filter(|s| !s.starts_with('\0'))       // drop the internal "other" sentinel cell
                .map(|s| format!("['{s}']"))
                .collect();
            out.push("[other]".into());
            out.join(" ")
        }
    }
}

fn kind_name(k: &FieldKind) -> &'static str {
    match k {
        FieldKind::Numeric => "numeric",
        FieldKind::Boolean => "boolean",
        FieldKind::Categorical => "categorical",
    }
}

fn pct(part: usize, whole: usize) -> String {
    if whole == 0 { "n/a".into() } else { format!("{:.1}%", 100.0 * part as f64 / whole as f64) }
}

/// The reading exactly as `symbol()` will see it, plus which fields lost a fraction to
/// truncation and which strings the codec coerces to 0 (the Rust-specific hazard).
fn codec_view(parts: &HashMap<String, FieldPartition>, reading: &HashMap<String, V>)
              -> (HashMap<String, V>, Vec<String>, Vec<String>) {
    let mut seen = HashMap::new();
    let mut truncated = Vec::new();
    let mut coerced = Vec::new();
    for (f, v) in reading {
        let p = &parts[f];
        let out = match p.kind {
            FieldKind::Numeric => {
                if let V::Num(n) = v {
                    if n.fract() != 0.0 {
                        truncated.push(f.clone());
                    }
                }
                if let V::Str(s) = v {
                    if s.parse::<i64>().is_err() {
                        coerced.push(f.clone());
                    }
                }
                V::Num(v_to_i64(v) as f64)
            }
            FieldKind::Boolean => V::Bool(py_truthy(v)),
            FieldKind::Categorical => V::Str(v_to_str(v)),
        };
        seen.insert(f.clone(), out);
    }
    (seen, truncated, coerced)
}

fn branch_nodes(graph: &Graph, nodes: &[String]) -> Vec<String> {
    let out: Vec<String> = nodes.iter()
        .filter(|n| {
            let targets: std::collections::HashSet<&str> =
                graph.nodes[*n].edges.iter().map(|(t, _c)| t.as_str()).collect();
            targets.len() > 1
        })
        .cloned().collect();
    if out.is_empty() { nodes.to_vec() } else { out }
}

pub fn run(cfg: &Config) -> Result<Outcome, String> {
    let flow_text = std::fs::read_to_string(&cfg.flow)
        .map_err(|e| format!("cannot read flow {:?}: {e}", cfg.flow))?;
    let graph = parse(&flow_text);
    let parts = quantizer::build_partitions(&graph);
    if parts.is_empty() {
        return Err(format!(
            "NOT READY: policy {:?} yields no decision-relevant fields (no `field OP const` \
             conditions on deterministic edges).", cfg.flow));
    }
    let order = wire::order(&parts);

    let mut nodes = wire::decision_nodes(&graph);
    if let Some(rn) = &cfg.route_node {
        if !nodes.contains(rn) {
            return Err(format!("--route-node {:?} is not a decision node (decision nodes: {})",
                               rn, nodes.join(", ")));
        }
        nodes = vec![rn.clone()];
    }

    // ------------------------------------------------------------- scan the sample
    let reader: Box<dyn BufRead> = if cfg.sample == "-" {
        Box::new(std::io::BufReader::new(std::io::stdin()))
    } else {
        Box::new(std::io::BufReader::new(std::fs::File::open(&cfg.sample)
            .map_err(|e| format!("cannot read sample {:?}: {e}", cfg.sample))?))
    };
    let (mut n_events, mut n_encoded, mut bad_json) = (0usize, 0usize, 0usize);
    let mut missing_events = 0usize;
    let mut missing_counts: HashMap<String, usize> = HashMap::new();
    let mut out_of_partition: HashMap<String, usize> = HashMap::new();
    let mut oop_examples: HashMap<String, String> = HashMap::new();
    let mut truncated_counts: HashMap<String, usize> = HashMap::new();
    let mut coerced_counts: HashMap<String, usize> = HashMap::new();
    let mut field_seen: HashMap<String, usize> = HashMap::new();
    let (mut raw_bytes, mut wire_bits, mut framed_bytes) = (0usize, 0usize, 0usize);
    let mut route_dist: HashMap<String, HashMap<String, usize>> =
        nodes.iter().map(|n| (n.clone(), HashMap::new())).collect();
    let mut mismatches: Vec<Value> = Vec::new();
    let mut non_decision_keys: HashMap<String, usize> = HashMap::new();

    let mut n_lines = 0usize;
    for line in reader.lines() {
        let line = line.map_err(|e| format!("read error: {e}"))?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(limit) = cfg.limit {
            if n_lines >= limit {
                break;
            }
        }
        n_lines += 1;
        let event: Value = match serde_json::from_str(line) {
            Ok(Value::Object(o)) => Value::Object(o),
            _ => {
                bad_json += 1;
                continue;
            }
        };
        n_events += 1;
        raw_bytes += line.len();
        for k in event.as_object().unwrap().keys() {
            let mapped = cfg.field_paths.get(k).map(String::as_str).unwrap_or(k);
            if !parts.contains_key(k) && !parts.contains_key(mapped) {
                *non_decision_keys.entry(k.clone()).or_default() += 1;
            }
        }

        let mut reading: HashMap<String, V> = HashMap::new();
        let mut missing: Vec<&str> = Vec::new();
        for f in &order {
            let path = cfg.field_paths.get(f).map(String::as_str).unwrap_or(f);
            match walk_path(&event, path) {
                Some(v) => {
                    reading.insert(f.clone(), V::from_json(v));
                    *field_seen.entry(f.clone()).or_default() += 1;
                }
                None => missing.push(f),
            }
        }
        if !missing.is_empty() {
            missing_events += 1;
            for f in missing {
                *missing_counts.entry(f.to_string()).or_default() += 1;
            }
            continue;
        }

        let (seen, truncated, coerced) = codec_view(&parts, &reading);
        for f in truncated {
            *truncated_counts.entry(f).or_default() += 1;
        }
        for f in coerced {
            *coerced_counts.entry(f).or_default() += 1;
        }

        let bits = match wire::encode_reading(&parts, &seen) {
            Ok(b) => b,
            Err(_) => {
                for f in &order {
                    if parts[f].symbol(&seen[f]).is_err() {
                        *out_of_partition.entry(f.clone()).or_default() += 1;
                        oop_examples.entry(f.clone())
                            .or_insert_with(|| format!("{:?}", reading[f]));
                    }
                }
                continue;
            }
        };
        n_encoded += 1;
        wire_bits += bits.len();
        let frame = packed::pack(&bits, 8);         // the Vector wire: one byte-aligned reading per frame
        framed_bytes += frame.len();

        // round trip through the same strict path the Vector decoder runs
        let syms = zeckendorf::decode_stream_strict(&packed::unpack(&frame))
            .map_err(|e| format!("round-trip decode failed (should be impossible): {e}"))?;
        if syms.len() != order.len() {
            return Err("round-trip symbol count mismatch (should be impossible)".into());
        }
        let sym_map: HashMap<String, usize> =
            order.iter().cloned().zip(syms.iter().map(|s| s - 1)).collect();
        let rep = quantizer::reconstruct(&parts, &sym_map);
        for node in &nodes {
            let orig_t = wire::route_node(&graph, node, &seen);
            let rep_t = wire::route_node(&graph, node, &rep);
            let label = orig_t.clone().unwrap_or_else(|| "(no match)".into());
            *route_dist.get_mut(node).unwrap().entry(label).or_default() += 1;
            if orig_t != rep_t && mismatches.len() < 10 {
                mismatches.push(json!({
                    "node": node, "reading": event,
                    "original": orig_t, "representative": rep_t}));
            }
        }
    }

    let unseen: Vec<&String> = order.iter().filter(|f| !field_seen.contains_key(*f)).collect();
    let codec_errors = if cfg.on_missing_skip { 0 } else { missing_events };
    let ready = n_encoded > 0 && mismatches.is_empty() && unseen.is_empty()
        && codec_errors == 0 && out_of_partition.is_empty() && coerced_counts.is_empty();

    // ------------------------------------------------------------- report
    let mut md: Vec<String> = Vec::new();
    let flow_name = std::path::Path::new(&cfg.flow).file_name()
        .map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| cfg.flow.clone());
    md.push(format!("# prismpath-preflight: {flow_name} x {n_events} events"));
    md.push(String::new());

    md.push("## Codebook (derived from the flow, nothing learned)".into());
    md.push(String::new());
    md.push("| field | kind | cells | decision cells |".into());
    md.push("|---|---|---|---|".into());
    let mut cell_product: u128 = 1;
    for f in &order {
        let p = &parts[f];
        md.push(format!("| `{f}` | {} | {} | {} |", kind_name(&p.kind), p.n, cells_desc(p)));
        cell_product *= p.n as u128;
    }
    md.push(String::new());
    md.push(format!(
        "Wire order is sorted field names (zero header). {} fields, {cell_product} joint cells: \
         every event collapses to one of {cell_product} decision-distinct messages.", order.len()));
    md.push(String::new());

    md.push("## Sample scan".into());
    md.push(String::new());
    md.push(format!("- events read: {n_events}{}",
        if bad_json > 0 { format!(" (of {} lines; {bad_json} not a JSON object)", n_lines) }
        else { String::new() }));
    md.push(format!("- encoded cleanly: {n_encoded} ({})", pct(n_encoded, n_events)));
    if missing_events > 0 {
        let mut detail: Vec<(&String, &usize)> = missing_counts.iter().collect();
        detail.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        let detail: Vec<String> = detail.iter().map(|(f, c)| format!("`{f}` x{c}")).collect();
        let verb = if cfg.on_missing_skip { "skip (event silently dropped)" }
                   else { "error (event dropped, error surfaced)" };
        md.push(format!("- missing decision fields: {missing_events} events -> \
                         on_missing={verb}: {}", detail.join(", ")));
    }
    let mut oop: Vec<(&String, &usize)> = out_of_partition.iter().collect();
    oop.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    for (f, c) in oop {
        md.push(format!("- out of partition on `{f}`: {c} events (example value: {}) -> \
                         encoding error", oop_examples[f]));
    }
    if !truncated_counts.is_empty() {
        let mut detail: Vec<(&String, &usize)> = truncated_counts.iter().collect();
        detail.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        let detail: Vec<String> = detail.iter().map(|(f, c)| format!("`{f}` x{c}")).collect();
        md.push(format!("- float truncation: numeric fields compare on int(value); affected: {} \
                         (a 21.7 routes as 21; make thresholds integer-aware or scale the field)",
                        detail.join(", ")));
    }
    if !coerced_counts.is_empty() {
        let mut detail: Vec<(&String, &usize)> = coerced_counts.iter().collect();
        detail.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        let detail: Vec<String> = detail.iter().map(|(f, c)| format!("`{f}` x{c}")).collect();
        md.push(format!("- COERCED TO 0: non-numeric strings on numeric fields: {} (the codec \
                         quantizes them as 0, which is almost never what you meant; fix the \
                         field or map a different path)", detail.join(", ")));
    }
    if !unseen.is_empty() {
        let names: Vec<String> = unseen.iter().map(|f| format!("`{f}`")).collect();
        md.push(format!("- NEVER SEEN in the sample: {} (is the field name right? try \
                         --map FIELD=your.json.path)", names.join(", ")));
    }
    md.push(String::new());

    if n_encoded > 0 {
        let raw_pe = raw_bytes as f64 / n_events as f64;
        let framed_pe = framed_bytes as f64 / n_encoded as f64;
        let stream_pe = wire_bits as f64 / 8.0 / n_encoded as f64;
        md.push("## Wire cost (projected)".into());
        md.push(String::new());
        md.push("| | bytes/event |".into());
        md.push("|---|---|".into());
        md.push(format!("| raw NDJSON (your sample) | {raw_pe:.3} |"));
        md.push(format!("| Facet, framed (one reading per frame, as the Vector codec sends) \
                         | {framed_pe:.3} |"));
        md.push(format!("| Facet, continuous stream (no per event alignment) | {stream_pe:.3} |"));
        md.push(String::new());
        md.push(format!(
            "Projected shrink: **{:.1}x** framed, {:.1}x continuous. Framing (length_delimited) \
             and transport headers are extra on both sides of the comparison.",
            raw_pe / framed_pe, raw_pe / stream_pe));
        md.push(String::new());

        md.push("## Decision preservation (round trip on your events)".into());
        md.push(String::new());
        if mismatches.is_empty() {
            md.push(format!(
                "{} route checks ({n_encoded} events x {} decision nodes): reconstructed \
                 representative routes **identically** to the original every time.",
                n_encoded * nodes.len(), nodes.len()));
        } else {
            md.push(format!(
                "**{}+ MISMATCHES** (original vs reconstructed route differs) - this should \
                 never happen; please report it with the flow + offending readings below:",
                mismatches.len()));
            for m in &mismatches {
                md.push(format!("- node `{}`: {:?} vs {:?} on {}",
                    m["node"].as_str().unwrap_or("?"), m["original"], m["representative"],
                    m["reading"]));
            }
        }
        md.push(String::new());

        let branches = branch_nodes(&graph, &nodes);
        md.push(format!("## Route distribution{}",
            if branches.len() < nodes.len() { " (pass-through nodes omitted)" } else { "" }));
        md.push(String::new());
        for node in &branches {
            md.push(format!("from `{node}`:"));
            md.push(String::new());
            let mut dist: Vec<(&String, &usize)> = route_dist[node].iter().collect();
            dist.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
            for (target, c) in dist {
                md.push(format!("- `{target}`: {c} ({})", pct(*c, n_encoded)));
            }
            md.push(String::new());
        }
        let only_route: Vec<String> = branches.iter()
            .filter(|n| route_dist[*n].len() == 1 && !route_dist[*n].contains_key("(no match)"))
            .map(|n| format!("`{n}`")).collect();
        if !only_route.is_empty() && n_encoded >= 20 {
            md.push(format!(
                "Note: {} routed every sample event the same way. Fine if the sample is quiet; \
                 if it should discriminate, check the thresholds against the sample's value \
                 range.", only_route.join(", ")));
            md.push(String::new());
        }
    }

    if !non_decision_keys.is_empty() {
        let mut keys: Vec<(&String, &usize)> = non_decision_keys.iter().collect();
        keys.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        let shown: Vec<String> = keys.iter().take(12).map(|(k, _c)| format!("`{k}`")).collect();
        md.push("## Not transmitted".into());
        md.push(String::new());
        md.push(format!(
            "Event keys with no decision role in this flow (they cost 0 bytes on the wire and \
             are not reconstructable from it): {}{}", shown.join(", "),
            if keys.len() > 12 { " ..." } else { "" }));
        md.push(String::new());
    }

    md.push("## Verdict".into());
    md.push(String::new());
    if ready {
        md.push(format!(
            "**READY.** All {n_encoded} events encode, every route is preserved. Vector config: \
             `encoding.codec = \"facet\"` + `encoding.policy = \"{}\"` on the sink; \
             `decoding.codec = \"facet\"` + `framing.method = \"length_delimited\"` on the \
             source.", cfg.flow));
    } else {
        md.push("**NOT READY** until the findings above are addressed (missing or never-seen \
                 fields usually mean a --map is needed; out of partition values mean the flow's \
                 thresholds do not cover the field's range).".into());
    }

    let report = json!({
        "flow": cfg.flow, "sample": cfg.sample,
        "field_paths": cfg.field_paths,
        "on_missing": if cfg.on_missing_skip { "skip" } else { "error" },
        "codebook": order.iter().map(|f| (f.clone(), json!({
            "kind": kind_name(&parts[f].kind), "cells": parts[f].n,
            "desc": cells_desc(&parts[f])}))).collect::<serde_json::Map<_, _>>(),
        "joint_cells": cell_product as u64,
        "events": n_events, "bad_json": bad_json, "encoded": n_encoded,
        "missing_events": missing_events, "missing_by_field": missing_counts,
        "out_of_partition": out_of_partition,
        "float_truncated_by_field": truncated_counts,
        "coerced_to_zero_by_field": coerced_counts,
        "fields_never_seen": unseen,
        "raw_bytes_per_event": if n_events > 0 {
            json!(raw_bytes as f64 / n_events as f64) } else { Value::Null },
        "framed_bytes_per_event": if n_encoded > 0 {
            json!(framed_bytes as f64 / n_encoded as f64) } else { Value::Null },
        "stream_bytes_per_event": if n_encoded > 0 {
            json!(wire_bits as f64 / 8.0 / n_encoded as f64) } else { Value::Null },
        "route_distribution": route_dist,
        "route_mismatches": mismatches,
        "non_decision_keys": non_decision_keys,
        "ready": ready,
    });

    Ok(Outcome { markdown: md.join("\n"), report, ready })
}
