// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! prismpath-preflight: will YOUR events survive the Facet codec? One command, one report.
//!
//! Formerly published as `facet-preflight` (0.1.0, yanked): the `facet-*` prefix belongs to the
//! facet reflection ecosystem on crates.io, and this crate moved out of it the day that was
//! flagged. Same code, same contract, new name.
//!
//! Same contract as the Python reference tool (`prismpath/telemetry/preflight.py`), but running on
//! the exact crates the Vector codec is built from — so what this reports IS what the codec will
//! do, by construction, including the places the Rust value model differs from the reference
//! (both apply the one input contract, `quantizer::accept_value`, and report its rejections;
//! this tool surfaces that as its own finding). Running both tools on one sample is a free
//! differential test of the whole stack.
//!
//! The tool runs in three phases, the same three the reference tool runs: [`Codebook::from_flow`]
//! derives what the wire will carry, [`scan_sample`] makes one pass over the events and fills a
//! [`Scan`] of counters, and [`render_markdown`] and [`render_json`] read that scan and nothing
//! else. Splitting there keeps the report's wording away from the counting, so the two can be read
//! and changed apart.

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

/// What the flow alone decides, before a single event is read: which fields reach the wire, in
/// which order, cut into which cells, and which nodes route on them.
pub struct Codebook {
    pub graph: Graph,
    pub parts: HashMap<String, FieldPartition>,
    pub order: Vec<String>,
    pub nodes: Vec<String>,
}

/// One pass over the sample, counted. Every number the report prints comes from here, so a
/// rendering change can never move a count and a counting change can never hide in the prose.
pub struct Scan {
    pub codebook: Codebook,
    pub n_lines: usize,
    pub n_events: usize,
    pub bad_json: usize,
    pub n_encoded: usize,
    pub missing_events: usize,
    pub missing_counts: HashMap<String, usize>,
    pub out_of_partition: HashMap<String, usize>,
    pub oop_examples: HashMap<String, String>,
    pub truncated_counts: HashMap<String, usize>,
    pub contract_rejections: HashMap<String, HashMap<String, usize>>,
    pub field_seen: HashMap<String, usize>,
    pub raw_bytes: usize,
    pub wire_bits: usize,
    pub framed_bytes: usize,
    pub route_dist: HashMap<String, HashMap<String, usize>>,
    pub mismatches: Vec<Value>,
    pub non_decision_keys: HashMap<String, usize>,
    pub unseen: Vec<String>,
    pub codec_errors: usize,
    pub ready: bool,
}

// Mirrors of the quantizer's private coercions (quantizer.rs `v_to_i64` / `v_to_str`): the
// preflight must route the SAME view of a value that `symbol()` quantizes, or float truncation
// and string coercion would show up as false round-trip mismatches.
/// The permissive numeric view the crate's `symbol` uses, mirrored here so the report shows the
/// reading as the encoder will see it: a fraction truncates, a bool is 0 or 1, and a string that
/// is not an integer literal is an error, never zero.
fn v_to_i64(value: &V) -> Result<i64, String> {
    match value {
        V::Num(number) => Ok(*number as i64),
        V::Bool(flag) => Ok(i64::from(*flag)),
        V::Str(text) => text.parse::<i64>().map_err(|_| format!("{text:?} is not an integer literal")),
        other => Err(format!("{other:?} is not a number")),
    }
}

fn v_to_str(value: &V) -> String {
    match value {
        V::Str(text) => text.clone(),
        V::Num(number) => number.to_string(),
        V::Bool(flag) => if *flag { "True".into() } else { "False".into() },
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

fn cells_desc(partition: &FieldPartition) -> String {
    match partition.kind {
        FieldKind::Numeric => partition.cells.iter()
            .map(|cell| format!("[{}..{}]",
                cell.lo.map_or("-inf".into(), |low| low.to_string()),
                cell.hi.map_or("+inf".into(), |high| high.to_string())))
            .collect::<Vec<_>>().join(" "),
        FieldKind::Boolean => "[false] [true]".into(),
        FieldKind::Categorical => {
            let mut out: Vec<String> = partition.cells.iter()
                .filter_map(|cell| cell.const_val.as_ref())
                .filter(|constant| !constant.starts_with('\0'))       // drop the internal "other" sentinel cell
                .map(|constant| format!("['{constant}']"))
                .collect();
            out.push("[other]".into());
            out.join(" ")
        }
    }
}

fn kind_name(kind: &FieldKind) -> &'static str {
    match kind {
        FieldKind::Numeric => "numeric",
        FieldKind::Boolean => "boolean",
        FieldKind::Categorical => "categorical",
    }
}

fn pct(part: usize, whole: usize) -> String {
    if whole == 0 { "n/a".into() } else { format!("{:.1}%", 100.0 * part as f64 / whole as f64) }
}

/// Counts most frequent first, ties broken by field name, so the same sample always renders the
/// same report however the hash map happened to be ordered.
fn by_count_desc(counts: &HashMap<String, usize>) -> Vec<(&String, &usize)> {
    let mut sorted: Vec<(&String, &usize)> = counts.iter().collect();
    sorted.sort_by(|left, right| right.1.cmp(left.1).then(left.0.cmp(right.0)));
    sorted
}

fn count_detail(counts: &HashMap<String, usize>) -> String {
    let detail: Vec<String> = by_count_desc(counts).iter()
        .map(|(field, count)| format!("`{field}` x{count}"))
        .collect();
    detail.join(", ")
}

/// The reading exactly as the permissive `symbol()` will see it, plus which fields lost a fraction
/// to truncation, and the fields the input contract rejects with the reason each. The contract is
/// what the checked encoder refuses at runtime, so the report predicts it exactly.
/// The reading as the encoder sees it, the fields that lost a fraction, and the fields the input
/// contract rejects with the reason each.
type CodecView = (HashMap<String, V>, Vec<String>, Vec<(String, String)>);

fn codec_view(parts: &HashMap<String, FieldPartition>, reading: &HashMap<String, V>) -> CodecView {
    let mut seen = HashMap::new();
    let mut truncated = Vec::new();
    let mut rejected = Vec::new();
    for (field, value) in reading {
        let partition = &parts[field];
        if let Err(rejection) = quantizer::accept_value(&partition.kind, value) {
            rejected.push((field.clone(), rejection.reason().to_string()));
        }
        let out = match partition.kind {
            FieldKind::Numeric => {
                if let V::Num(number) = value {
                    if number.fract() != 0.0 {
                        truncated.push(field.clone());
                    }
                }
                match v_to_i64(value) {
                    Ok(number) => V::Num(number as f64),
                    Err(_) => value.clone(),   // the permissive encoder will refuse it; keep it visible
                }
            }
            FieldKind::Boolean => V::Bool(py_truthy(value)),
            FieldKind::Categorical => V::Str(v_to_str(value)),
        };
        seen.insert(field.clone(), out);
    }
    (seen, truncated, rejected)
}

fn branch_nodes(graph: &Graph, nodes: &[String]) -> Vec<String> {
    let out: Vec<String> = nodes.iter()
        .filter(|node| {
            let targets: std::collections::HashSet<&str> =
                graph.nodes[*node].edges.iter().map(|(target, _cond)| target.as_str()).collect();
            targets.len() > 1
        })
        .cloned().collect();
    if out.is_empty() { nodes.to_vec() } else { out }
}

impl Codebook {
    /// Derives the codebook from the flow file, refusing a flow that decides nothing and a
    /// `--route-node` that is not a decision node.
    pub fn from_flow(cfg: &Config) -> Result<Codebook, String> {
        let flow_text = std::fs::read_to_string(&cfg.flow)
            .map_err(|error| format!("cannot read flow {:?}: {error}", cfg.flow))?;
        let graph = parse(&flow_text);
        let parts = quantizer::build_partitions(&graph);
        if parts.is_empty() {
            return Err(format!(
                "NOT READY: policy {:?} yields no decision-relevant fields (no `field OP const` \
                 conditions on deterministic edges).", cfg.flow));
        }
        let order = wire::order(&parts);

        let mut nodes = wire::decision_nodes(&graph);
        if let Some(route_node) = &cfg.route_node {
            if !nodes.contains(route_node) {
                return Err(format!("--route-node {:?} is not a decision node (decision nodes: {})",
                                   route_node, nodes.join(", ")));
            }
            nodes = vec![route_node.clone()];
        }
        Ok(Codebook { graph, parts, order, nodes })
    }
}

/// Every event collapses to one of this many decision-distinct messages.
fn joint_cells(codebook: &Codebook) -> u128 {
    codebook.order.iter().map(|field| codebook.parts[field].n as u128).product()
}

/// Opens the sample, or stdin for `-`.
pub fn open_sample(cfg: &Config) -> Result<Box<dyn BufRead>, String> {
    if cfg.sample == "-" {
        Ok(Box::new(std::io::BufReader::new(std::io::stdin())))
    } else {
        Ok(Box::new(std::io::BufReader::new(std::fs::File::open(&cfg.sample)
            .map_err(|error| format!("cannot read sample {:?}: {error}", cfg.sample))?)))
    }
}

/// The decision fields this event carries, and the ones it does not.
fn extract_reading(event: &Value, order: &[String], field_paths: &HashMap<String, String>)
                   -> (HashMap<String, V>, Vec<String>) {
    let mut reading: HashMap<String, V> = HashMap::new();
    let mut missing: Vec<String> = Vec::new();
    for field in order {
        let path = field_paths.get(field).map(String::as_str).unwrap_or(field);
        match walk_path(event, path) {
            Some(value) => {
                reading.insert(field.clone(), V::from_json(value));
            }
            None => missing.push(field.clone()),
        }
    }
    (reading, missing)
}

/// Which field refused to quantize, once `encode_reading` has said only that one of them did.
fn attribute_encode_failure(codebook: &Codebook, seen: &HashMap<String, V>,
                            reading: &HashMap<String, V>,
                            out_of_partition: &mut HashMap<String, usize>,
                            oop_examples: &mut HashMap<String, String>) {
    for field in &codebook.order {
        if codebook.parts[field].symbol(&seen[field]).is_err() {
            *out_of_partition.entry(field.clone()).or_default() += 1;
            oop_examples.entry(field.clone())
                .or_insert_with(|| format!("{:?}", reading[field]));
        }
    }
}

/// The reading a receiver would rebuild from the frame, through the same strict path the Vector
/// decoder runs. Its routes are what the report compares against the original's.
fn round_trip(codebook: &Codebook, frame: &[u8]) -> Result<HashMap<String, V>, String> {
    let syms = zeckendorf::decode_stream_strict(&packed::unpack(frame))
        .map_err(|error| format!("round-trip decode failed (should be impossible): {error}"))?;
    if syms.len() != codebook.order.len() {
        return Err("round-trip symbol count mismatch (should be impossible)".into());
    }
    let sym_map: HashMap<String, usize> =
        codebook.order.iter().cloned().zip(syms.iter().map(|symbol| symbol - 1)).collect();
    Ok(quantizer::reconstruct(&codebook.parts, &sym_map))
}

/// One pass over the sample: counts what encodes, what does not, what it costs on the wire, and
/// whether the reconstructed reading still routes where the original did.
pub fn scan_sample(codebook: Codebook, reader: &mut dyn BufRead, cfg: &Config)
                   -> Result<Scan, String> {
    let (mut n_events, mut n_encoded, mut bad_json) = (0usize, 0usize, 0usize);
    let mut missing_events = 0usize;
    let mut missing_counts: HashMap<String, usize> = HashMap::new();
    let mut out_of_partition: HashMap<String, usize> = HashMap::new();
    let mut oop_examples: HashMap<String, String> = HashMap::new();
    let mut truncated_counts: HashMap<String, usize> = HashMap::new();
    let mut contract_rejections: HashMap<String, HashMap<String, usize>> = HashMap::new();
    let mut field_seen: HashMap<String, usize> = HashMap::new();
    let (mut raw_bytes, mut wire_bits, mut framed_bytes) = (0usize, 0usize, 0usize);
    let mut route_dist: HashMap<String, HashMap<String, usize>> =
        codebook.nodes.iter().map(|node| (node.clone(), HashMap::new())).collect();
    let mut mismatches: Vec<Value> = Vec::new();
    let mut non_decision_keys: HashMap<String, usize> = HashMap::new();

    let mut n_lines = 0usize;
    for line in reader.lines() {
        let line = line.map_err(|error| format!("read error: {error}"))?;
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
            Ok(Value::Object(object)) => Value::Object(object),
            _ => {
                bad_json += 1;
                continue;
            }
        };
        n_events += 1;
        raw_bytes += line.len();
        for key in event.as_object().unwrap().keys() {
            let mapped = cfg.field_paths.get(key).map(String::as_str).unwrap_or(key);
            if !codebook.parts.contains_key(key) && !codebook.parts.contains_key(mapped) {
                *non_decision_keys.entry(key.clone()).or_default() += 1;
            }
        }

        let (reading, missing) = extract_reading(&event, &codebook.order, &cfg.field_paths);
        for field in reading.keys() {
            *field_seen.entry(field.clone()).or_default() += 1;
        }
        if !missing.is_empty() {
            missing_events += 1;
            for field in missing {
                *missing_counts.entry(field).or_default() += 1;
            }
            continue;
        }

        let (seen, truncated, rejected) = codec_view(&codebook.parts, &reading);
        for field in truncated {
            *truncated_counts.entry(field).or_default() += 1;
        }
        for (field, reason) in rejected {
            *contract_rejections.entry(field).or_default().entry(reason).or_default() += 1;
        }

        let bits = match wire::encode_reading(&codebook.parts, &seen) {
            Ok(encoded) => encoded,
            Err(_) => {
                attribute_encode_failure(&codebook, &seen, &reading,
                                         &mut out_of_partition, &mut oop_examples);
                continue;
            }
        };
        n_encoded += 1;
        wire_bits += bits.len();
        let frame = packed::pack(&bits, 8);         // the Vector wire: one byte-aligned reading per frame
        framed_bytes += frame.len();

        let rep = round_trip(&codebook, &frame)?;
        for node in &codebook.nodes {
            let orig_t = wire::route_node(&codebook.graph, node, &seen);
            let rep_t = wire::route_node(&codebook.graph, node, &rep);
            let label = orig_t.clone().unwrap_or_else(|| "(no match)".into());
            *route_dist.get_mut(node).unwrap().entry(label).or_default() += 1;
            if orig_t != rep_t && mismatches.len() < 10 {
                mismatches.push(json!({
                    "node": node, "reading": event,
                    "original": orig_t, "representative": rep_t}));
            }
        }
    }

    let unseen: Vec<String> = codebook.order.iter()
        .filter(|field| !field_seen.contains_key(*field))
        .cloned().collect();
    let codec_errors = if cfg.on_missing_skip { 0 } else { missing_events };
    let ready = n_encoded > 0 && mismatches.is_empty() && unseen.is_empty()
        && codec_errors == 0 && out_of_partition.is_empty() && contract_rejections.is_empty();

    Ok(Scan {
        codebook,
        n_lines,
        n_events,
        bad_json,
        n_encoded,
        missing_events,
        missing_counts,
        out_of_partition,
        oop_examples,
        truncated_counts,
        contract_rejections,
        field_seen,
        raw_bytes,
        wire_bits,
        framed_bytes,
        route_dist,
        mismatches,
        non_decision_keys,
        unseen,
        codec_errors,
        ready,
    })
}

fn section_codebook(scan: &Scan) -> Vec<String> {
    let mut md: Vec<String> = vec![
        "## Codebook (derived from the flow, nothing learned)".into(),
        String::new(),
        "| field | kind | cells | decision cells |".into(),
        "|---|---|---|---|".into(),
    ];
    for field in &scan.codebook.order {
        let partition = &scan.codebook.parts[field];
        md.push(format!("| `{field}` | {} | {} | {} |", kind_name(&partition.kind), partition.n, cells_desc(partition)));
    }
    let cell_product = joint_cells(&scan.codebook);
    md.push(String::new());
    md.push(format!(
        "Wire order is sorted field names (zero header). {} fields, {cell_product} joint cells: \
         every event collapses to one of {cell_product} decision-distinct messages.",
        scan.codebook.order.len()));
    md.push(String::new());
    md
}

fn section_sample_scan(cfg: &Config, scan: &Scan) -> Vec<String> {
    let (n_events, n_encoded, bad_json) = (scan.n_events, scan.n_encoded, scan.bad_json);
    let mut md: Vec<String> = Vec::new();
    md.push("## Sample scan".into());
    md.push(String::new());
    md.push(format!("- events read: {n_events}{}",
        if bad_json > 0 { format!(" (of {} lines; {bad_json} not a JSON object)", scan.n_lines) }
        else { String::new() }));
    md.push(format!("- encoded cleanly: {n_encoded} ({})", pct(n_encoded, n_events)));
    if scan.missing_events > 0 {
        let verb = if cfg.on_missing_skip { "skip (event silently dropped)" }
                   else { "error (event dropped, error surfaced)" };
        md.push(format!("- missing decision fields: {} events -> \
                         on_missing={verb}: {}", scan.missing_events,
                        count_detail(&scan.missing_counts)));
    }
    for (field, count) in by_count_desc(&scan.out_of_partition) {
        md.push(format!("- out of partition on `{field}`: {count} events (example value: {}) -> \
                         encoding error", scan.oop_examples[field]));
    }
    if !scan.truncated_counts.is_empty() {
        md.push(format!("- float truncation: numeric fields compare on int(value); affected: {} \
                         (a 21.7 routes as 21; make thresholds integer-aware or scale the field)",
                        count_detail(&scan.truncated_counts)));
    }
    let mut rejected_fields: Vec<&String> = scan.contract_rejections.keys().collect();
    rejected_fields.sort();
    for field in rejected_fields {
        let reasons = &scan.contract_rejections[field];
        let mut detail: Vec<(&String, &usize)> = reasons.iter().collect();
        detail.sort_by(|left, right| right.1.cmp(left.1).then(left.0.cmp(right.0)));
        let text: Vec<String> = detail.iter().map(|(reason, count)| format!("{reason} x{count}")).collect();
        md.push(format!("- REJECTED BY THE INPUT CONTRACT on `{field}`: {} (the checked encoder \
                         refuses these at runtime; fix the field or map a different path)", text.join(", ")));
    }
    if !scan.unseen.is_empty() {
        let names: Vec<String> = scan.unseen.iter().map(|field| format!("`{field}`")).collect();
        md.push(format!("- NEVER SEEN in the sample: {} (is the field name right? try \
                         --map FIELD=your.json.path)", names.join(", ")));
    }
    md.push(String::new());
    md
}

fn section_wire_cost(scan: &Scan) -> Vec<String> {
    let raw_pe = scan.raw_bytes as f64 / scan.n_events as f64;
    let framed_pe = scan.framed_bytes as f64 / scan.n_encoded as f64;
    let stream_pe = scan.wire_bits as f64 / 8.0 / scan.n_encoded as f64;
    let mut md: Vec<String> = Vec::new();
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
    md
}

fn section_decision_preservation(scan: &Scan) -> Vec<String> {
    let n_encoded = scan.n_encoded;
    let mut md: Vec<String> = Vec::new();
    md.push("## Decision preservation (round trip on your events)".into());
    md.push(String::new());
    if scan.mismatches.is_empty() {
        md.push(format!(
            "{} route checks ({n_encoded} events x {} decision nodes): reconstructed \
             representative routes **identically** to the original every time.",
            n_encoded * scan.codebook.nodes.len(), scan.codebook.nodes.len()));
    } else {
        md.push(format!(
            "**{}+ MISMATCHES** (original vs reconstructed route differs) - this should \
             never happen; please report it with the flow + offending readings below:",
            scan.mismatches.len()));
        for mismatch in &scan.mismatches {
            md.push(format!("- node `{}`: {:?} vs {:?} on {}",
                mismatch["node"].as_str().unwrap_or("?"), mismatch["original"], mismatch["representative"],
                mismatch["reading"]));
        }
    }
    md.push(String::new());
    md
}

fn section_route_distribution(scan: &Scan) -> Vec<String> {
    let nodes = &scan.codebook.nodes;
    let branches = branch_nodes(&scan.codebook.graph, nodes);
    let mut md: Vec<String> = Vec::new();
    md.push(format!("## Route distribution{}",
        if branches.len() < nodes.len() { " (pass-through nodes omitted)" } else { "" }));
    md.push(String::new());
    for node in &branches {
        md.push(format!("from `{node}`:"));
        md.push(String::new());
        for (target, count) in by_count_desc(&scan.route_dist[node]) {
            md.push(format!("- `{target}`: {count} ({})", pct(*count, scan.n_encoded)));
        }
        md.push(String::new());
    }
    let only_route: Vec<String> = branches.iter()
        .filter(|node| scan.route_dist[*node].len() == 1
                       && !scan.route_dist[*node].contains_key("(no match)"))
        .map(|node| format!("`{node}`")).collect();
    if !only_route.is_empty() && scan.n_encoded >= 20 {
        md.push(format!(
            "Note: {} routed every sample event the same way. Fine if the sample is quiet; \
             if it should discriminate, check the thresholds against the sample's value \
             range.", only_route.join(", ")));
        md.push(String::new());
    }
    md
}

fn section_not_transmitted(scan: &Scan) -> Vec<String> {
    let keys = by_count_desc(&scan.non_decision_keys);
    let shown: Vec<String> = keys.iter().take(12).map(|(key, _count)| format!("`{key}`")).collect();
    let mut md: Vec<String> = Vec::new();
    md.push("## Not transmitted".into());
    md.push(String::new());
    md.push(format!(
        "Event keys with no decision role in this flow (they cost 0 bytes on the wire and \
         are not reconstructable from it): {}{}", shown.join(", "),
        if keys.len() > 12 { " ..." } else { "" }));
    md.push(String::new());
    md
}

fn section_verdict(cfg: &Config, scan: &Scan) -> Vec<String> {
    let n_encoded = scan.n_encoded;
    let mut md: Vec<String> = Vec::new();
    md.push("## Verdict".into());
    md.push(String::new());
    if scan.ready {
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
    md
}

/// The operator's report: what the wire carries, what the sample did on it, and the verdict.
pub fn render_markdown(cfg: &Config, scan: &Scan) -> String {
    let flow_name = std::path::Path::new(&cfg.flow).file_name()
        .map(|name| name.to_string_lossy().into_owned()).unwrap_or_else(|| cfg.flow.clone());
    let mut md: Vec<String> = Vec::new();
    md.push(format!("# prismpath-preflight: {flow_name} x {} events", scan.n_events));
    md.push(String::new());
    md.extend(section_codebook(scan));
    md.extend(section_sample_scan(cfg, scan));
    // Wire cost, preservation and route distribution all divide by the encoded count, so a sample
    // where nothing encoded gets the findings and the verdict, and no sections of zeroes.
    if scan.n_encoded > 0 {
        md.extend(section_wire_cost(scan));
        md.extend(section_decision_preservation(scan));
        md.extend(section_route_distribution(scan));
    }
    if !scan.non_decision_keys.is_empty() {
        md.extend(section_not_transmitted(scan));
    }
    md.extend(section_verdict(cfg, scan));
    md.join("\n")
}

/// The same report as machine-readable JSON, for a gate or a diff between the two tools.
pub fn render_json(cfg: &Config, scan: &Scan) -> Value {
    let (parts, order) = (&scan.codebook.parts, &scan.codebook.order);
    json!({
        "flow": cfg.flow, "sample": cfg.sample,
        "field_paths": cfg.field_paths,
        "on_missing": if cfg.on_missing_skip { "skip" } else { "error" },
        "codebook": order.iter().map(|field| (field.clone(), json!({
            "kind": kind_name(&parts[field].kind), "cells": parts[field].n,
            "desc": cells_desc(&parts[field])}))).collect::<serde_json::Map<_, _>>(),
        "joint_cells": joint_cells(&scan.codebook) as u64,
        "events": scan.n_events, "bad_json": scan.bad_json, "encoded": scan.n_encoded,
        "missing_events": scan.missing_events, "missing_by_field": scan.missing_counts,
        "out_of_partition": scan.out_of_partition,
        "float_truncated_by_field": scan.truncated_counts,
        "rejected_by_contract": scan.contract_rejections,
        "fields_never_seen": scan.unseen,
        "raw_bytes_per_event": if scan.n_events > 0 {
            json!(scan.raw_bytes as f64 / scan.n_events as f64) } else { Value::Null },
        "framed_bytes_per_event": if scan.n_encoded > 0 {
            json!(scan.framed_bytes as f64 / scan.n_encoded as f64) } else { Value::Null },
        "stream_bytes_per_event": if scan.n_encoded > 0 {
            json!(scan.wire_bits as f64 / 8.0 / scan.n_encoded as f64) } else { Value::Null },
        "route_distribution": scan.route_dist,
        "route_mismatches": scan.mismatches,
        "non_decision_keys": scan.non_decision_keys,
        "ready": scan.ready,
    })
}

pub fn run(cfg: &Config) -> Result<Outcome, String> {
    let codebook = Codebook::from_flow(cfg)?;
    let mut reader = open_sample(cfg)?;
    let scan = scan_sample(codebook, &mut reader, cfg)?;
    Ok(Outcome {
        markdown: render_markdown(cfg, &scan),
        report: render_json(cfg, &scan),
        ready: scan.ready,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLOW: &str = "---
name: split_check
start: classify
---
## classify
-> critical: when temp >= 90 and armed
-> warn: when temp >= 50
-> ok: else
## critical
## warn
## ok
";

    fn config(dir: &std::path::Path) -> Config {
        std::fs::create_dir_all(dir).unwrap();
        let flow = dir.join("flow.md");
        std::fs::write(&flow, FLOW).unwrap();
        Config {
            flow: flow.to_str().unwrap().to_string(),
            sample: "-".into(),
            field_paths: HashMap::new(),
            on_missing_skip: false,
            route_node: None,
            limit: None,
        }
    }

    // The phases have to be usable one at a time, and the report has to be a function of the scan
    // alone: anything else and a caller counting once and rendering twice would get two answers.
    #[test]
    fn scan_then_render_matches_the_whole_run() {
        let dir = std::env::temp_dir().join(format!("ppf_split_{}", std::process::id()));
        let cfg = config(&dir);
        let sample = "{\"temp\": 95, \"armed\": true}\n{\"temp\": 10, \"armed\": false}\n";
        let codebook = Codebook::from_flow(&cfg).unwrap();
        assert_eq!(codebook.order, vec!["armed".to_string(), "temp".to_string()]);
        assert_eq!(joint_cells(&codebook), 6);

        let mut reader: &[u8] = sample.as_bytes();
        let scan = scan_sample(codebook, &mut reader, &cfg).unwrap();
        assert_eq!(scan.n_events, 2);
        assert_eq!(scan.n_encoded, 2);
        assert!(scan.ready);
        assert_eq!(render_markdown(&cfg, &scan), render_markdown(&cfg, &scan));
        assert_eq!(render_json(&cfg, &scan)["encoded"], 2);

        let sample_file = dir.join("sample.ndjson");
        std::fs::write(&sample_file, sample).unwrap();
        let whole = run(&Config { sample: sample_file.to_str().unwrap().to_string(), ..config(&dir) })
            .unwrap();
        assert_eq!(whole.markdown, render_markdown(&cfg, &scan));
        std::fs::remove_dir_all(&dir).ok();
    }
}
