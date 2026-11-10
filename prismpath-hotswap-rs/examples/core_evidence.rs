// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! A differential run as evidence, the Rust twin of `formal/diff/core_evidence.py`
//! (docs/design/spec-verified-core.md, section 11). The run format is that module's, byte for byte:
//! `run.json` (the manifest), `cases.jsonl` (the inputs), `images.jsonl` (an image attestation per case,
//! Ed25519 with the authority key over `prismpath.core-image/1\0` and the image's canon/2 bytes),
//! `receipts.jsonl` (a canon/2 receipt per decision; a receipt is not signed by itself) and
//! `receipts.roots.jsonl` (one canon/2 root statement, `prismpath.core-run-root/1`, signed with the
//! instance key over its own domain prefix, over the receipts' Merkle root, binding the manifest, its time
//! an integer count of microseconds), with the two public keys beside them.
//!
//!     core_evidence produce --from CASES.jsonl --out RUN --keys KEYS   # the Rust port decides
//!     core_evidence verify RUN [--sample N|all] [--seed S] [--pin-authority PUB --pin-instance PUB] [--oracle BIN]
//!
//! `produce` decides every case with the Rust port, composed as the differential harness's Rust leg
//! composes it (`prismpath-rs/examples/core_diff.rs`), and signs with test keys it generates in `--keys`
//! when none are there (`keygen`, the pack signing code); a case outside the core is excluded with its
//! reason (`outside_core`). `verify` re-checks the root statement, every
//! receipt and every image attestation, and replays a sample of the decisions through the Lean oracle;
//! it verifies a run the Python module produced, and the Python module verifies one produced here.

use ed25519_dalek::Signer;
use prismpath_hotswap_rs::merkle::merkle_root;
use prismpath_hotswap_rs::{keygen, load_private, sha256_hex, verify_ed25519};
use prismpath_rs::canon2::{self, Doc};
use prismpath_rs::field_definitions::system_boundary;
use prismpath_rs::{causes, first_deterministic, parse, Value};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

const RUN_FORMAT: &str = "prismpath.core-run/1";
const IMAGE_FORMAT: &str = "prismpath.core-image/1";
const RECEIPT_FORMAT: &str = "prismpath.core-receipt/1";
const IMAGE_DOMAIN: &[u8] = b"prismpath.core-image/1\x00";
const LOG_CORE_RUN: &str = "core-run";
/// The run's root statement: canon/2, its own format and domain prefix (`core_evidence.ROOT_FORMAT`).
const ROOT_FORMAT: &str = "prismpath.core-run-root/1";
const ROOT_DOMAIN: &[u8] = b"prismpath.core-run-root/1\x00";
const ROOT_MEMBERS: [&str; 10] = ["format", "log", "root", "leaves", "time_us", "trigger", "key_id", "public_key", "policy", "sig"];
const FILES: [&str; 7] = ["run.json", "cases.jsonl", "images.jsonl", "receipts.jsonl", "receipts.roots.jsonl", "authority.pub", "instance.pub"];

struct Case {
    id: String,
    image: Vec<u8>,
    flow: Option<String>,
    readings: Vec<Vec<u8>>,
}

fn obj(members: Vec<(&str, Doc)>) -> Doc {
    Doc::Obj(members.into_iter().map(|(key, value)| (key.to_string(), value)).collect())
}

fn text(value: &str) -> Doc {
    Doc::Str(value.to_string())
}

fn member<'a>(doc: &'a Doc, key: &str) -> Option<&'a Doc> {
    match doc {
        Doc::Obj(members) => members.iter().find(|(name, _)| name == key).map(|(_, value)| value),
        _ => None,
    }
}

fn str_of<'a>(doc: &'a Doc, key: &str) -> Result<&'a str, String> {
    match member(doc, key) {
        Some(Doc::Str(value)) => Ok(value),
        _ => Err(format!("no string member {key:?}")),
    }
}

fn int_of(doc: &Doc, key: &str) -> Result<i64, String> {
    match member(doc, key) {
        Some(Doc::Int(value)) => Ok(*value),
        _ => Err(format!("no integer member {key:?}")),
    }
}

fn lines(bytes: &[u8]) -> Vec<&[u8]> {
    let mut out: Vec<&[u8]> = bytes.split(|byte| *byte == b'\n').collect();
    if out.last().is_some_and(|line| line.is_empty()) {
        out.pop();
    }
    out
}

fn unhex(value: &str) -> Result<Vec<u8>, String> {
    hex::decode(value).map_err(|error| error.to_string())
}

fn read_cases(bytes: &[u8]) -> Result<Vec<Case>, String> {
    let mut cases = Vec::new();
    for line in lines(bytes) {
        let row = canon2::read(line).map_err(|error| format!("cases.jsonl: {error}"))?;
        let readings = match member(&row, "readings") {
            Some(Doc::Arr(items)) => items
                .iter()
                .map(|item| match item {
                    Doc::Str(value) => unhex(value),
                    _ => Err("a reading is hex".to_string()),
                })
                .collect::<Result<Vec<_>, _>>()?,
            _ => return Err("cases.jsonl: no readings".to_string()),
        };
        let flow = match member(&row, "flow") {
            Some(Doc::Str(flow)) => Some(flow.clone()),
            Some(Doc::Null) => None,
            _ => return Err("cases.jsonl: the flow is text or null".to_string()),
        };
        cases.push(Case { id: str_of(&row, "case")?.to_string(), image: unhex(str_of(&row, "image")?)?, flow, readings });
    }
    Ok(cases)
}

// ----------------------------------------------------------------- the core's scope
fn reads_counter(cond: &Doc) -> bool {
    let Doc::Arr(items) = cond else { return false };
    match items.first() {
        Some(Doc::Str(tag)) if ["truthy", "cmp", "in", "not in"].contains(&tag.as_str()) => {
            matches!(items.get(1), Some(Doc::Str(field)) if field == "visits" || field == "error_count")
        }
        Some(Doc::Str(tag)) if ["not", "and", "or"].contains(&tag.as_str()) => items[1..].iter().any(reads_counter),
        _ => false,
    }
}

/// Why a case is not a decision of the core, or None, as `core_evidence.outside_core` decides it from the
/// image alone: `engine-counter`, `unrenderable` or `inferred-path`.
fn outside_core(image: &[u8], flow: Option<&str>) -> Option<&'static str> {
    let doc = canon2::read(image).ok()?;
    let whens: Vec<&Doc> = match member(&doc, "rules") {
        Some(Doc::Arr(rules)) => rules.iter().filter_map(|rule| if let Doc::Obj(_) = rule { member(rule, "when") } else { None }).collect(),
        _ => Vec::new(),
    };
    if whens.iter().any(|when| reads_counter(when)) {
        return Some("engine-counter");
    }
    if flow.is_none() {
        return Some("unrenderable");
    }
    let catch_all = |when: &Doc| matches!(when, Doc::Arr(items) if items.len() == 1 && (items[0] == text("always") || items[0] == text("never")));
    if matches!(member(&doc, "fields"), Some(Doc::Obj(fields)) if fields.is_empty()) && whens.iter().any(|when| !catch_all(when)) {
        return Some("inferred-path");
    }
    None
}

// ----------------------------------------------------------------- the decisions
/// A receipt's decision members, in the order they are written (canon/2 sorts them).
type Decision = Vec<(&'static str, Doc)>;

/// A refusal's decision members: its registered cause, code, and the field and reason where it has them.
fn refusal(cause: &str, field: Option<&str>, reason: Option<&str>) -> Result<Decision, String> {
    let code = causes::code(cause).ok_or_else(|| format!("{cause} is not a registered cause"))?;
    let mut out = vec![("decision", text("refuse")), ("cause", text(cause)), ("cause_code", Doc::Int(i64::from(code)))];
    if let Some(field) = field.filter(|field| !field.is_empty()) {
        out.push(("field", text(field)));
    }
    if let Some(reason) = reason.filter(|reason| !reason.is_empty()) {
        out.push(("reason", text(reason)));
    }
    Ok(out)
}

/// One reading under a checked policy, composed as `core_diff.rs` composes it.
fn reading_decision(graph: &prismpath_rs::Graph, bytes: &[u8]) -> Result<Decision, String> {
    let document = match canon2::read(bytes) {
        Ok(document) => document,
        Err(error) => return refusal("reading:unreadable", None, Some(error.rule())),
    };
    let Doc::Obj(members) = document else {
        return refusal("reading:not-object", None, None);
    };
    let values: HashMap<String, Value> = members.iter().map(|(key, value)| (key.clone(), value.to_value())).collect();
    if let Some((field, reason)) = system_boundary(graph, &values) {
        return refusal("route:contract-violation", Some(&field), Some(reason));
    }
    match first_deterministic(&graph.nodes[&graph.start].edges, &values) {
        Some((target, _)) => Ok(vec![("decision", text("route")), ("target", text(target))]),
        None => refusal("route:no-matching-edge", None, None),
    }
}

/// Every reading's decision, or None for a case the port has no decision on (an image with no flow).
fn case_decisions(case: &Case) -> Result<Option<Vec<Decision>>, String> {
    if let Err(error) = canon2::read(&case.image) {
        let refused = refusal("policy:unreadable", None, Some(error.rule()))?;
        return Ok(Some(case.readings.iter().map(|_| refused.clone()).collect()));
    }
    let Some(flow) = &case.flow else { return Ok(None) };
    let graph = parse(flow);
    if graph.refusal().is_some() {
        let cause = graph.field_error_cause.ok_or_else(|| format!("case {}: an uncoded refusal", case.id))?;
        let refused = refusal(cause, graph.field_error_field.as_deref(), graph.field_error_reason)?;
        return Ok(Some(case.readings.iter().map(|_| refused.clone()).collect()));
    }
    case.readings.iter().map(|bytes| reading_decision(&graph, bytes)).collect::<Result<Vec<_>, _>>().map(Some)
}

// ----------------------------------------------------------------- producing a run
/// The signer's clock as the run's root statement holds it: microseconds since the epoch, an integer.
fn now_us() -> i64 {
    let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("a clock after 1970");
    i64::try_from(since.as_micros()).expect("a clock before the year 294,000")
}

/// What the root statement's signature covers: its domain prefix, then the canon/2 bytes of every member
/// but `sig`.
fn root_signed_bytes(statement: &Doc) -> Result<Vec<u8>, String> {
    let Doc::Obj(members) = statement else { return Err("the root statement is an object".to_string()) };
    let body = Doc::Obj(members.iter().filter(|(key, _)| key != "sig").cloned().collect());
    let mut out = ROOT_DOMAIN.to_vec();
    out.extend(canon2::write(&body).map_err(|error| error.to_string())?);
    Ok(out)
}

fn is_hex_of(value: &str, size: usize) -> bool {
    value.len() == 2 * size && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The run's root statement checked in full, as `core_evidence.verify_root_statement` checks it.
fn verify_root_statement(data: &[u8], leaves: &[String], manifest_bytes: &[u8], instance_raw: &[u8]) -> Result<Doc, String> {
    let Some(line) = data.strip_suffix(b"\n").filter(|line| !line.contains(&b'\n')) else {
        return Err("the root statement is not one line".to_string());
    };
    let statement = canon2::read(line).map_err(|error| format!("the root statement is not a canon/2 document ({})", error.rule()))?;
    if canon2::write(&statement).ok().as_deref() != Some(line) {
        return Err("the root statement is not in its canonical canon/2 spelling".to_string());
    }
    let Doc::Obj(members) = &statement else { return Err("the root statement is not in its canonical canon/2 spelling".to_string()) };
    let keys: BTreeSet<&str> = members.iter().map(|(key, _)| key.as_str()).collect();
    let shaped = keys == ROOT_MEMBERS.iter().copied().collect()
        && member(&statement, "format") == Some(&text(ROOT_FORMAT))
        && member(&statement, "log") == Some(&text(LOG_CORE_RUN))
        && member(&statement, "trigger") == Some(&text(LOG_CORE_RUN));
    if !shaped {
        return Err("the root statement is not a prismpath.core-run-root/1 statement".to_string());
    }
    for key in ["leaves", "time_us"] {
        if !matches!(member(&statement, key), Some(Doc::Int(value)) if *value >= 0) {
            return Err(format!("the root statement's {key} is not a nonnegative integer"));
        }
    }
    let (root, key_id, public_key, sig) = match (member(&statement, "root"), member(&statement, "key_id"), member(&statement, "public_key"), member(&statement, "sig")) {
        (Some(Doc::Str(root)), Some(Doc::Str(key_id)), Some(Doc::Str(public_key)), Some(Doc::Str(sig))) if is_hex_of(key_id, 32) && is_hex_of(public_key, 32) && is_hex_of(sig, 64) => (root, key_id, public_key, sig),
        _ => return Err("the root statement's root, key or signature is malformed".to_string()),
    };
    if *public_key != hex::encode(instance_raw) || *key_id != sha256_hex(instance_raw) {
        return Err("the root statement is not signed with the run's instance key".to_string());
    }
    if !verify_ed25519(instance_raw, &root_signed_bytes(&statement)?, &unhex(sig)?) {
        return Err("the root statement's signature does not verify".to_string());
    }
    if int_of(&statement, "leaves")? != leaves.len() as i64 || *root != merkle_root(leaves)? {
        return Err("the root statement does not verify: its root is not the receipts' Merkle root".to_string());
    }
    if member(&statement, "policy") != Some(&obj(vec![("core_run_sha256", text(&sha256_hex(manifest_bytes)))])) {
        return Err("the root statement does not bind this run.json".to_string());
    }
    Ok(statement)
}

fn produce(source: &Path, out: &Path, keys: &Path) -> Result<String, String> {
    let keys_dir = keys.to_str().ok_or("a key directory path that is UTF-8")?;
    if !keys.join("authority.key").exists() {
        keygen(keys_dir, "authority")?;
    }
    if !keys.join("instance.key").exists() {
        keygen(keys_dir, "instance")?;
    }
    let authority = load_private(keys.join("authority.key").to_str().ok_or("UTF-8 path")?)?;
    let instance = load_private(keys.join("instance.key").to_str().ok_or("UTF-8 path")?)?;
    let authority_raw = authority.verifying_key().to_bytes();
    let instance_raw = instance.verifying_key().to_bytes();
    let (authority_id, instance_id) = (sha256_hex(&authority_raw), sha256_hex(&instance_raw));
    if authority_id == instance_id {
        return Err("the instance key is also the authority key".to_string());
    }
    std::fs::create_dir_all(out).map_err(|error| error.to_string())?;
    let cases_bytes = std::fs::read(source).map_err(|error| error.to_string())?;
    std::fs::write(out.join("cases.jsonl"), &cases_bytes).map_err(|error| error.to_string())?;
    let cases = read_cases(&cases_bytes)?;

    let mut images = Vec::new();
    for case in &cases {
        let mut signed = IMAGE_DOMAIN.to_vec();
        signed.extend(&case.image);
        let attestation = obj(vec![
            ("format", text(IMAGE_FORMAT)),
            ("case", text(&case.id)),
            ("image_sha256", text(&sha256_hex(&case.image))),
            ("key_id", text(&authority_id)),
            ("sig", text(&hex::encode(authority.sign(&signed).to_bytes()))),
        ]);
        images.extend(canon2::write(&attestation).map_err(|error| error.to_string())?);
        images.push(b'\n');
    }
    std::fs::write(out.join("images.jsonl"), &images).map_err(|error| error.to_string())?;

    let (mut receipts, mut leaves, mut excluded) = (Vec::new(), Vec::new(), Vec::new());
    for case in &cases {
        if let Some(why) = outside_core(&case.image, case.flow.as_deref()) {
            excluded.push(obj(vec![("case", text(&case.id)), ("why", text(why))]));
            continue;
        }
        let Some(decisions) = case_decisions(case)? else {
            return Err(format!("case {}: no decision on a case inside the core", case.id));
        };
        for (index, (raw, decision)) in case.readings.iter().zip(decisions).enumerate() {
            let mut members = vec![
                ("format", text(RECEIPT_FORMAT)),
                ("idx", Doc::Int(leaves.len() as i64)),
                ("case", text(&case.id)),
                ("reading", Doc::Int(index as i64)),
                ("image_sha256", text(&sha256_hex(&case.image))),
                ("reading_sha256", text(&sha256_hex(raw))),
                ("decider", text("rust")),
            ];
            members.extend(decision);
            let line = canon2::write(&obj(members)).map_err(|error| error.to_string())?;
            leaves.push(sha256_hex(&line));
            receipts.extend(line);
            receipts.push(b'\n');
        }
    }
    std::fs::write(out.join("receipts.jsonl"), &receipts).map_err(|error| error.to_string())?;

    let excluded_count = excluded.len();
    let manifest = obj(vec![
        ("format", text(RUN_FORMAT)),
        ("decider", text("rust")),
        ("cases", Doc::Int(cases.len() as i64)),
        ("receipts", Doc::Int(leaves.len() as i64)),
        ("excluded", Doc::Arr(excluded)),
        ("cases_sha256", text(&sha256_hex(&cases_bytes))),
        ("images_sha256", text(&sha256_hex(&images))),
        ("authority_key_id", text(&authority_id)),
        ("instance_key_id", text(&instance_id)),
    ]);
    let manifest_bytes = canon2::write(&manifest).map_err(|error| error.to_string())?;
    let mut manifest_line = manifest_bytes.clone();
    manifest_line.push(b'\n');
    std::fs::write(out.join("run.json"), manifest_line).map_err(|error| error.to_string())?;
    std::fs::write(out.join("authority.pub"), authority_raw).map_err(|error| error.to_string())?;
    std::fs::write(out.join("instance.pub"), instance_raw).map_err(|error| error.to_string())?;

    // one canon/2 root statement over every receipt, as `core_evidence.make_root_statement` writes one
    let mut statement = obj(vec![
        ("format", text(ROOT_FORMAT)),
        ("log", text(LOG_CORE_RUN)),
        ("root", text(&merkle_root(&leaves)?)),
        ("leaves", Doc::Int(leaves.len() as i64)),
        ("time_us", Doc::Int(now_us())),
        ("trigger", text(LOG_CORE_RUN)),
        ("key_id", text(&instance_id)),
        ("public_key", text(&hex::encode(instance_raw))),
        ("policy", obj(vec![("core_run_sha256", text(&sha256_hex(&manifest_bytes)))])),
    ]);
    let sig = hex::encode(instance.sign(&root_signed_bytes(&statement)?).to_bytes());
    if let Doc::Obj(members) = &mut statement {
        members.push(("sig".to_string(), text(&sig)));
    }
    let mut line = canon2::write(&statement).map_err(|error| error.to_string())?;
    line.push(b'\n');
    std::fs::write(out.join("receipts.roots.jsonl"), line).map_err(|error| error.to_string())?;
    Ok(format!(
        "core_evidence: produced {}: decider rust, {} cases, {} receipts, {} excluded",
        out.display(),
        cases.len(),
        leaves.len(),
        excluded_count
    ))
}

// ----------------------------------------------------------------- verifying a run
struct Options {
    sample: Option<usize>,
    seed: u64,
    pin_authority: Option<PathBuf>,
    pin_instance: Option<PathBuf>,
    oracle: PathBuf,
}

/// A decision as comparable members: route and target, or refuse with cause, code, field and reason (an
/// empty field, the oracle's spelling of a threshold on no field, is no field).
fn normal(decision: &serde_json::Value) -> Vec<String> {
    let get = |key: &str| decision.get(key).map(|value| match value {
        serde_json::Value::String(text) => text.clone(),
        other => other.to_string(),
    });
    let verdict = get("decision").or_else(|| get("verdict")).unwrap_or_default();
    if verdict == "route" {
        return vec![verdict, get("target").unwrap_or_default()];
    }
    let code = get("cause_code").or_else(|| get("code")).unwrap_or_default();
    vec![verdict, get("cause").unwrap_or_default(), code, get("field").unwrap_or_default(), get("reason").unwrap_or_default()]
}

fn verify(run: &Path, options: &Options) -> Result<String, String> {
    for name in FILES {
        if !run.join(name).exists() {
            return Err(format!("the run has no {name}"));
        }
    }
    let read = |name: &str| std::fs::read(run.join(name)).map_err(|error| format!("{name}: {error}"));
    let manifest_file = read("run.json")?;
    let manifest_bytes = manifest_file.strip_suffix(b"\n").unwrap_or(&manifest_file).to_vec();
    let manifest = canon2::read(&manifest_bytes).map_err(|error| format!("run.json: {error}"))?;
    if member(&manifest, "format") != Some(&text(RUN_FORMAT)) || canon2::write(&manifest).ok().as_deref() != Some(&manifest_bytes[..]) {
        return Err("run.json is not a canonical prismpath.core-run/1 manifest".to_string());
    }
    let decider = str_of(&manifest, "decider")?.to_string();

    // the keys: pinned when the reader names them, else the ones the run carries
    let (authority_raw, instance_raw) = (read("authority.pub")?, read("instance.pub")?);
    for (pin, raw, role) in [(&options.pin_authority, &authority_raw, "authority"), (&options.pin_instance, &instance_raw, "instance")] {
        if let Some(pin) = pin {
            if &std::fs::read(pin).map_err(|error| error.to_string())? != raw {
                return Err(format!("the run's {role} key is not the pinned {role} key"));
            }
        }
    }
    let pinned = options.pin_authority.is_some() && options.pin_instance.is_some();
    let (authority_id, instance_id) = (sha256_hex(&authority_raw), sha256_hex(&instance_raw));
    if str_of(&manifest, "authority_key_id")? != authority_id || str_of(&manifest, "instance_key_id")? != instance_id {
        return Err("run.json names other keys than the run carries".to_string());
    }
    if authority_id == instance_id {
        return Err("the instance key is also the authority key".to_string());
    }

    // the root statement over the receipts, and the manifest it binds
    let receipts_bytes = read("receipts.jsonl")?;
    let receipt_lines = lines(&receipts_bytes);
    let leaves: Vec<String> = receipt_lines.iter().map(|line| sha256_hex(line)).collect();
    verify_root_statement(&read("receipts.roots.jsonl")?, &leaves, &manifest_bytes, &instance_raw)?;
    if int_of(&manifest, "receipts")? != leaves.len() as i64 {
        return Err("run.json counts other receipts than the run holds".to_string());
    }

    // the cases and the image attestations
    let (cases_bytes, images_bytes) = (read("cases.jsonl")?, read("images.jsonl")?);
    if sha256_hex(&cases_bytes) != str_of(&manifest, "cases_sha256")? || sha256_hex(&images_bytes) != str_of(&manifest, "images_sha256")? {
        return Err("cases.jsonl or images.jsonl is not the file run.json names".to_string());
    }
    let cases = read_cases(&cases_bytes)?;
    let image_lines = lines(&images_bytes);
    if cases.len() as i64 != int_of(&manifest, "cases")? || image_lines.len() != cases.len() {
        return Err("run.json, cases.jsonl and images.jsonl count other cases".to_string());
    }
    for (case, line) in cases.iter().zip(&image_lines) {
        let attestation = canon2::read(line).map_err(|error| format!("images.jsonl: {error}"))?;
        let mut signed = IMAGE_DOMAIN.to_vec();
        signed.extend(&case.image);
        let sound = canon2::write(&attestation).ok().as_deref() == Some(*line)
            && str_of(&attestation, "format")? == IMAGE_FORMAT
            && str_of(&attestation, "case")? == case.id
            && str_of(&attestation, "key_id")? == authority_id
            && str_of(&attestation, "image_sha256")? == sha256_hex(&case.image);
        if !sound {
            return Err(format!("case {}: the image attestation does not match the image", case.id));
        }
        if !verify_ed25519(&authority_raw, &signed, &unhex(str_of(&attestation, "sig")?)?) {
            return Err(format!("case {}: the image signature does not verify", case.id));
        }
    }

    // every receipt, in order: every reading of every case the run did not exclude, once
    let mut excluded: HashMap<String, String> = HashMap::new();
    let Some(Doc::Arr(rows)) = member(&manifest, "excluded") else { return Err("run.json lists no excluded cases".to_string()) };
    for row in rows {
        match row {
            Doc::Obj(members) if members.len() == 2 => {
                excluded.insert(str_of(row, "case")?.to_string(), str_of(row, "why")?.to_string());
            }
            _ => return Err("run.json lists an excluded case without its reason".to_string()),
        }
    }
    for case in &cases {
        let why = outside_core(&case.image, case.flow.as_deref());
        if excluded.get(&case.id).map(String::as_str) != why {
            return Err(format!("case {}: excluded as {:?}, but the image says {why:?}", case.id, excluded.get(&case.id)));
        }
    }
    let expected: Vec<(&Case, usize)> = cases.iter().filter(|case| !excluded.contains_key(&case.id)).flat_map(|case| (0..case.readings.len()).map(move |index| (case, index))).collect();
    if expected.len() != receipt_lines.len() {
        return Err(format!("{} receipts for {} decisions", receipt_lines.len(), expected.len()));
    }
    let mut receipts = Vec::new();
    for (idx, ((case, index), line)) in expected.iter().zip(&receipt_lines).enumerate() {
        let receipt = canon2::read(line).map_err(|error| format!("receipt {idx}: {error}"))?;
        if canon2::write(&receipt).ok().as_deref() != Some(*line) {
            return Err(format!("receipt {idx} is not in its canonical canon/2 spelling"));
        }
        let binds = str_of(&receipt, "format")? == RECEIPT_FORMAT
            && int_of(&receipt, "idx")? == idx as i64
            && str_of(&receipt, "case")? == case.id
            && int_of(&receipt, "reading")? == *index as i64
            && str_of(&receipt, "image_sha256")? == sha256_hex(&case.image)
            && str_of(&receipt, "reading_sha256")? == sha256_hex(&case.readings[*index])
            && str_of(&receipt, "decider")? == decider;
        if !binds {
            return Err(format!("receipt {idx} does not bind case {} reading {index}", case.id));
        }
        let Doc::Obj(members) = &receipt else { unreachable!("a receipt read as an object") };
        let keys: BTreeSet<&str> = members.iter().map(|(key, _)| key.as_str()).collect();
        let base = ["format", "idx", "case", "reading", "image_sha256", "reading_sha256", "decider", "decision"];
        match str_of(&receipt, "decision")? {
            "route" => {
                if keys != base.iter().copied().chain(["target"]).collect() {
                    return Err(format!("receipt {idx}: a route names a target and nothing else"));
                }
            }
            "refuse" => {
                let cause = str_of(&receipt, "cause")?;
                let code = int_of(&receipt, "cause_code")?;
                let allowed: BTreeSet<&str> = base.iter().copied().chain(["cause", "cause_code", "field", "reason"]).collect();
                if causes::code(cause).map(i64::from) != Some(code) || code == 0 || !keys.is_subset(&allowed) {
                    return Err(format!("receipt {idx}: a refusal carries a registered nonzero cause code"));
                }
            }
            _ => return Err(format!("receipt {idx}: the decision is a route or a refusal")),
        }
        receipts.push((*case, *index, receipt.to_json()));
    }

    // a sample of the decisions, replayed through the oracle
    let chosen: Vec<usize> = match options.sample {
        Some(count) if count < receipts.len() => {
            // a seeded partial Fisher Yates shuffle (xorshift64*), so a run replays the same sample
            let mut state = options.seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
            let mut order: Vec<usize> = (0..receipts.len()).collect();
            for slot in 0..count {
                state ^= state >> 12;
                state ^= state << 25;
                state ^= state >> 27;
                let pick = slot + (state.wrapping_mul(0x2545_F491_4F6C_DD1D) % (receipts.len() - slot) as u64) as usize;
                order.swap(slot, pick);
            }
            order.truncate(count);
            order
        }
        _ => (0..receipts.len()).collect(),
    };
    let mut frames = Vec::new();
    for (number, which) in chosen.iter().enumerate() {
        let (case, index, _) = &receipts[*which];
        let reading = &case.readings[*index];
        frames.extend(format!("case r{number} 1\n{}\n", case.image.len()).into_bytes());
        frames.extend(&case.image);
        frames.extend(format!("\n{}\n", reading.len()).into_bytes());
        frames.extend(reading);
        frames.push(b'\n');
    }
    let mut child = Command::new(&options.oracle)
        .arg("--batch")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|error| format!("the oracle {}: {error}", options.oracle.display()))?;
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().expect("piped stdin");
        let writer = std::thread::spawn(move || stdin.write_all(&frames));
        let output = child.wait_with_output().map_err(|error| error.to_string())?;
        writer.join().expect("the writer thread").map_err(|error| error.to_string())?;
        if !output.status.success() {
            return Err("the oracle failed".to_string());
        }
        let rows: HashMap<String, serde_json::Value> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .map(|row| (row["id"].as_str().unwrap_or_default().to_string(), row))
            .collect();
        let mut agree = 0usize;
        for (number, which) in chosen.iter().enumerate() {
            let (case, _index, receipt) = &receipts[*which];
            let row = rows.get(&format!("r{number}")).ok_or("the oracle skipped a case")?;
            let oracle = &row["readings"][0];
            // every receipted case is inside the core, so every decision must be the oracle's
            if normal(oracle) != normal(receipt) {
                return Err(format!("a replayed decision differs from the oracle: case {} receipt {receipt} oracle {oracle}", case.id));
            }
            agree += 1;
        }
        Ok(format!(
            "core_evidence: verified {}: decider {decider}, {} receipts, {} image attestations, root statement {}, {} replayed: {agree} agree, 0 disagree",
            run.display(),
            receipts.len(),
            cases.len(),
            if pinned { "signed" } else { "signed-unpinned" },
            chosen.len()
        ))
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |name: &str| args.iter().position(|arg| arg == name).and_then(|at| args.get(at + 1)).cloned();
    let outcome = match args.first().map(String::as_str) {
        Some("produce") => match (flag("--from"), flag("--out"), flag("--keys")) {
            (Some(source), Some(out), Some(keys)) => produce(Path::new(&source), Path::new(&out), Path::new(&keys)),
            _ => Err("produce --from CASES --out RUN --keys KEYS".to_string()),
        },
        Some("verify") if args.len() > 1 => {
            let sample = match flag("--sample").as_deref() {
                Some("all") => None,
                Some(count) => Some(count.parse().unwrap_or(200)),
                None => Some(200),
            };
            let oracle = flag("--oracle").map(PathBuf::from).unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../formal/.lake/build/bin/core-oracle"));
            let options = Options {
                sample,
                seed: flag("--seed").and_then(|seed| seed.parse().ok()).unwrap_or(0),
                pin_authority: flag("--pin-authority").map(PathBuf::from),
                pin_instance: flag("--pin-instance").map(PathBuf::from),
                oracle,
            };
            verify(Path::new(&args[1]), &options).map_err(|why| format!("core_evidence: REFUSED {}: {why}", args[1]))
        }
        _ => Err("usage: core_evidence produce --from CASES --out RUN --keys KEYS | verify RUN [--sample N|all] [--seed S] [--pin-authority PUB --pin-instance PUB] [--oracle BIN]".to_string()),
    };
    match outcome {
        Ok(line) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(why) => {
            println!("{why}");
            ExitCode::FAILURE
        }
    }
}
