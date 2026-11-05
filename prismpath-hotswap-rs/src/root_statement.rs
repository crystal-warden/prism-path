// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Root statements, verified: a deployment's own Ed25519 signature over the Merkle root of what it
//! recorded, chained, as `prismpath/ledgers/root_statement.py` defines them (format
//! `prismpath-root-statement/1`, SPEC 4.5, PROTOCOL 2.10).
//!
//! This is the verify side only. Nothing here signs, generates or loads a private key: a Rust
//! consumer can check a log, a chain of statements or one receipt that the Python engine produced,
//! and the statements, findings and verdicts are the Python reference's, name for name. The frozen
//! vectors in `prismpath/portable/conformance/receipts.json` hold the two to it.
//!
//! What a verdict proves is what the Python module's documentation says: a pinned public key and a
//! chain that verifies show that the holder of the instance key stated these roots in this order and
//! that the log still holds the leaves under them. It does not show when (the time field is the
//! signer's clock), and a log whose tail and tail statements were both deleted still verifies.
//!
//! Signatures are checked with `verify_strict`, which also refuses small order keys and signatures
//! the reference's OpenSSL backed check would accept; no honest key or signature is affected.

use crate::merkle::{merkle_root, path_from_json, verify_leaf};
use crate::pyval::{from_hex, head, py_int, universal_newlines};
use crate::{canonical_bytes, sha256_hex, verify_ed25519};
use serde_json::{json, Map, Value};

pub const STATEMENT_FORMAT: &str = "prismpath-root-statement/1";
/// Prefixed to the canonical bytes before signing, so a root statement signature can never be
/// presented as a pack or flow manifest signature or the reverse.
pub const SIGNING_DOMAIN: &[u8] = b"prismpath-root-statement/1\x00";
/// An audit log's root is the Merkle root of its first `leaves` events.
pub const LOG_AUDIT: &str = "audit-log";
/// An epoch chain's root is the chained root of its first `leaves` epochs.
pub const LOG_EPOCH_CHAIN: &str = "epoch-chain";

const BODY_FIELDS: [&str; 11] = [
    "format", "log", "seq", "root", "leaves", "prev", "time", "trigger", "key_id", "public_key", "policy",
];

/// Findings that make a chain invalid. `interrupted_statement` (a torn final line from a crash mid
/// write) is reported and is not one of them.
pub const FATAL_FINDINGS: [&str; 10] = [
    "bad_format", "key_id_mismatch", "bad_signature", "unpinned_key", "authority_key", "chain_broken",
    "leaf_count_regressed", "log_truncated", "root_mismatch", "no_statements",
];

pub const SIGNED: &str = "signed";
pub const SIGNED_UNPINNED: &str = "signed-unpinned";
pub const UNSIGNED: &str = "unsigned";
pub const INVALID: &str = "invalid";

/// sha256 hex of the raw 32 byte public key: the identity rule the authority keys use too.
pub fn key_id_of(public_raw: &[u8]) -> String {
    sha256_hex(public_raw)
}

/// The short form people read and compare: the first 16 characters of the key id.
pub fn fingerprint(key_id: &str) -> String {
    head(key_id, 16)
}

/// The bytes the signature covers: the domain prefix, then every field but `sig`, canonical.
/// `None` when a field is missing (a statement that is not well formed has no signed bytes).
pub fn signed_bytes(statement: &Value) -> Option<Vec<u8>> {
    let mut body = Map::new();
    for field in BODY_FIELDS {
        body.insert(field.to_string(), statement.get(field)?.clone());
    }
    let mut bytes = SIGNING_DOMAIN.to_vec();
    bytes.extend(canonical_bytes(&Value::Object(body)));
    Some(bytes)
}

/// The statement's content address, signature included: what the next statement names as `prev`.
pub fn statement_hash(statement: &Value) -> String {
    sha256_hex(&canonical_bytes(statement))
}

fn is_empty_object(value: &Value) -> bool {
    value.as_object().is_none_or(|object| object.is_empty())
}

/// Refuse an instance key that is also a policy authority key.
pub fn check_separation(instance_key_id: Option<&str>, authority_key_ids: &[String]) -> Result<(), String> {
    match instance_key_id {
        Some(instance) if authority_key_ids.iter().any(|authority| authority == instance) => Err(format!(
            "the instance key {} is also a policy authority key; generate a separate one with `prismpath ledger keygen`",
            fingerprint(instance)
        )),
        _ => Ok(()),
    }
}

// ------------------------------------------------------------------ reading

/// Every statement in a statements file's text, and the findings reading it produced. A final line
/// that is not JSON is a write a crash cut short (`interrupted_statement`); a bad line anywhere else
/// is `bad_format`, and stands in the chain as an empty statement, because a chain with an unreadable
/// link proves nothing past it. The text is read as Python reads a file: `\r\n` and `\r` are `\n`.
pub fn read_statements_text(text: &str) -> (Vec<Value>, Vec<Value>) {
    let text = universal_newlines(text);
    let mut lines: Vec<&str> = text.split('\n').collect();
    if lines.last() == Some(&"") {
        lines.pop();
    }
    let (mut statements, mut findings) = (Vec::new(), Vec::new());
    for (index, line) in lines.iter().enumerate() {
        match serde_json::from_str::<Value>(line) {
            Ok(record @ Value::Object(_)) => statements.push(record),
            _ if index == lines.len() - 1 => findings.push(json!({"finding": "interrupted_statement", "line": index + 1})),
            _ => {
                findings.push(json!({"finding": "bad_format", "line": index + 1}));
                statements.push(json!({}));
            }
        }
    }
    (statements, findings)
}

/// `read_statements_text` over a file; a missing file is no statements.
pub fn read_statements(path: &str) -> std::io::Result<(Vec<Value>, Vec<Value>)> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(read_statements_text(&text)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok((Vec::new(), Vec::new())),
        Err(error) => Err(error),
    }
}

/// Where a log's statements live: beside it, `run.audit.jsonl` becomes `run.audit.roots.jsonl` and
/// any other name gains `.roots.jsonl`.
pub fn statements_path_for(log_path: &str) -> String {
    match log_path.strip_suffix(".jsonl") {
        Some(stem) => format!("{stem}.roots.jsonl"),
        None => format!("{log_path}.roots.jsonl"),
    }
}

// ------------------------------------------------------------------ one statement

fn well_formed(statement: &Value, log: &str) -> bool {
    if statement.get("format").and_then(Value::as_str) != Some(STATEMENT_FORMAT)
        || statement.get("log").and_then(Value::as_str) != Some(log)
    {
        return false;
    }
    if BODY_FIELDS.iter().chain(["sig"].iter()).any(|key| statement.get(*key).is_none()) {
        return false;
    }
    let is_int = |key: &str| py_int(&statement[key]).is_some();
    let is_str = |key: &str| statement[key].is_string();
    if !(is_int("seq") && is_int("leaves") && is_str("root") && is_str("prev") && is_str("key_id")) {
        return false;
    }
    let decoded = |key: &str| statement[key].as_str().and_then(from_hex);
    decoded("public_key").is_some_and(|key| key.len() == 32) && decoded("sig").is_some_and(|sig| sig.len() == 64)
}

fn public_raw(statement: &Value) -> Vec<u8> {
    statement["public_key"].as_str().and_then(from_hex).unwrap_or_default()
}

fn signature_verifies(statement: &Value) -> bool {
    let (Some(message), Some(signature)) = (signed_bytes(statement), statement["sig"].as_str().and_then(from_hex)) else {
        return false;
    };
    verify_ed25519(&public_raw(statement), &message, &signature)
}

// ------------------------------------------------------------------ a chain

/// What `verify_chain` reports, field for field the Python dictionary.
#[derive(Debug, Clone, PartialEq)]
pub struct ChainReport {
    /// `signed`, `signed-unpinned`, `unsigned` or `invalid`.
    pub status: &'static str,
    pub statements: usize,
    pub signed_leaves: i64,
    pub log_leaves: usize,
    pub unsigned_tail: usize,
    /// Fingerprints of the keys that signed, in the order they first appear.
    pub keys: Vec<String>,
    pub pinned: bool,
    pub last_statement_sha256: Option<String>,
    /// Each finding is an object with a `finding` name and the fields the reference gives it.
    pub findings: Vec<Value>,
}

impl ChainReport {
    pub fn to_json(&self) -> Value {
        json!({
            "status": self.status, "statements": self.statements, "signed_leaves": self.signed_leaves,
            "log_leaves": self.log_leaves, "unsigned_tail": self.unsigned_tail, "keys": self.keys,
            "pinned": self.pinned, "last_statement_sha256": self.last_statement_sha256,
            "findings": self.findings,
        })
    }

    pub fn finding_names(&self) -> Vec<&str> {
        self.findings.iter().filter_map(|finding| finding["finding"].as_str()).collect()
    }
}

/// How a chain is read: which log it must name, the public keys the reader trusts (raw bytes; with
/// none, each statement is checked under the key it carries and the result is at best
/// `signed-unpinned`), and the policy authority key ids seen in the log.
#[derive(Debug, Clone, Copy)]
pub struct ChainOptions<'a> {
    pub log: &'a str,
    pub pinned: &'a [Vec<u8>],
    pub authority_key_ids: &'a [String],
}

impl Default for ChainOptions<'_> {
    fn default() -> Self {
        ChainOptions { log: LOG_AUDIT, pinned: &[], authority_key_ids: &[] }
    }
}

/// Check a chain of statements against the log it covers. `root_at(n)` is the root of the log's
/// first `n` leaves (as the reference's, a negative `n` counts from the end) and `total_leaves` is
/// how many the log holds now. With a pinned key a log with no statements is invalid
/// (`no_statements`), so removing the statements file cannot pass a signed log off as an old
/// unsigned one.
pub fn verify_chain(
    statements: &[Value],
    read_findings: Vec<Value>,
    root_at: &dyn Fn(i64) -> String,
    total_leaves: usize,
    options: ChainOptions,
) -> ChainReport {
    let pinned_ids: Vec<String> = options.pinned.iter().map(|raw| key_id_of(raw)).collect();
    let mut findings = read_findings;
    let (mut prev_hash, mut prev_leaves) = (String::new(), 0i64);
    let mut mismatch_from: Option<i64> = None;
    let mut key_ids: Vec<String> = Vec::new();
    for (index, statement) in statements.iter().enumerate() {
        if is_empty_object(statement) || !well_formed(statement, options.log) {
            if !is_empty_object(statement) {
                findings.push(json!({"finding": "bad_format", "statement": index}));
            }
            prev_hash = if is_empty_object(statement) { String::new() } else { statement_hash(statement) };
            continue;
        }
        let seq = py_int(&statement["seq"]).expect("well formed");
        let leaves = py_int(&statement["leaves"]).expect("well formed");
        let key_id = statement["key_id"].as_str().expect("well formed");
        if key_id_of(&public_raw(statement)) != key_id {
            findings.push(json!({"finding": "key_id_mismatch", "statement": seq}));
        } else if !signature_verifies(statement) {
            findings.push(json!({"finding": "bad_signature", "statement": seq}));
        }
        if !pinned_ids.is_empty() && !pinned_ids.iter().any(|pinned| pinned == key_id) {
            findings.push(json!({"finding": "unpinned_key", "statement": seq, "key": fingerprint(key_id)}));
        }
        if options.authority_key_ids.iter().any(|authority| authority == key_id) {
            findings.push(json!({"finding": "authority_key", "statement": seq, "key": fingerprint(key_id)}));
        }
        if !key_ids.iter().any(|seen| seen == key_id) {
            key_ids.push(key_id.to_string());
        }
        if seq != index as i64 || statement["prev"].as_str() != Some(prev_hash.as_str()) {
            findings.push(json!({"finding": "chain_broken", "statement": seq, "position": index}));
        }
        if leaves < prev_leaves {
            findings.push(json!({"finding": "leaf_count_regressed", "statement": seq, "leaves": leaves, "before": prev_leaves}));
        }
        if i128::from(leaves) > total_leaves as i128 {
            findings.push(json!({"finding": "log_truncated", "statement": seq, "signed_leaves": leaves, "log_leaves": total_leaves}));
        } else if statement["root"].as_str() != Some(root_at(leaves).as_str()) {
            // The first statement whose root no longer matches bounds the edit: a receipt at an index
            // in this range (event `idx`, from 0) changed after the statement before it was signed.
            let from = *mismatch_from.get_or_insert(prev_leaves.min(leaves));
            findings.push(json!({"finding": "root_mismatch", "statement": seq, "leaf_range": [from, leaves - 1]}));
        }
        prev_hash = statement_hash(statement);
        prev_leaves = leaves;
    }
    if !pinned_ids.is_empty() && statements.is_empty() {
        findings.push(json!({"finding": "no_statements"}));
    }
    let fatal = findings
        .iter()
        .any(|finding| finding["finding"].as_str().is_some_and(|name| FATAL_FINDINGS.contains(&name)));
    let status = if fatal {
        INVALID
    } else if statements.is_empty() {
        UNSIGNED
    } else if !pinned_ids.is_empty() {
        SIGNED
    } else {
        SIGNED_UNPINNED
    };
    let last = statements.iter().rev().find(|statement| !is_empty_object(statement));
    let signed_leaves = last.and_then(|statement| py_int(&statement["leaves"])).unwrap_or(0);
    ChainReport {
        status,
        statements: statements.len(),
        signed_leaves,
        log_leaves: total_leaves,
        unsigned_tail: if statements.is_empty() { total_leaves } else { (total_leaves as i128 - i128::from(signed_leaves)).max(0) as usize },
        keys: key_ids.iter().map(|key_id| fingerprint(key_id)).collect(),
        pinned: !pinned_ids.is_empty(),
        last_statement_sha256: last.map(statement_hash),
        findings,
    }
}

// ------------------------------------------------------------------ an audit log

/// An audit log read as `AuditLog` reads it: one event per JSON line (blank lines ignored, lines
/// that are not JSON skipped and remembered by line number), each event a Merkle leaf, the SHA-256
/// of its canonical JSON.
#[derive(Debug, Clone, Default)]
pub struct AuditLogView {
    pub events: Vec<Value>,
    pub leaves: Vec<String>,
    /// 1-based numbers of the lines that were not JSON.
    pub skipped: Vec<usize>,
}

impl AuditLogView {
    pub fn from_text(text: &str) -> AuditLogView {
        let mut view = AuditLogView::default();
        for (index, line) in universal_newlines(text).split('\n').enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<Value>(line) {
                Ok(event) => {
                    view.leaves.push(sha256_hex(&canonical_bytes(&event)));
                    view.events.push(event);
                }
                Err(_) => view.skipped.push(index + 1),
            }
        }
        view
    }

    /// The root over the first `count` leaves: what a statement of that count signed. A negative
    /// count counts from the end, as the reference's slice does.
    pub fn root_at(&self, count: i64) -> String {
        let length = self.leaves.len() as i64;
        let end = if count < 0 { (length + count).max(0) } else { count.min(length) };
        merkle_root(&self.leaves[..end as usize]).expect("leaves are hashes this module wrote")
    }
}

/// The policy authority key ids an audit log names: every accepted swap carries the pack's key id.
pub fn authority_key_ids_in(events: &[Value]) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for event in events {
        let Some(data) = event.get("data").filter(|data| data.is_object()) else { continue };
        if event.get("action").and_then(Value::as_str) != Some("swap") {
            continue;
        }
        let key_id = match data.get("key_id") {
            Some(Value::String(text)) if !text.is_empty() => text.clone(),
            Some(Value::Number(number)) if number.as_f64() != Some(0.0) => number.to_string(),
            _ => continue,
        };
        if !found.contains(&key_id) {
            found.push(key_id);
        }
    }
    found
}

/// Check an audit log's statements against the log (`AuditLog.verify_statements`): status `signed`,
/// `signed-unpinned`, `unsigned` or `invalid`, with every finding. `statements_text` is the
/// statements file beside the log, or `None` when there is none.
pub fn verify_trail(log_text: &str, statements_text: Option<&str>, pinned: &[Vec<u8>]) -> ChainReport {
    let view = AuditLogView::from_text(log_text);
    let (statements, mut read_findings) = statements_text.map(read_statements_text).unwrap_or_default();
    if !view.skipped.is_empty() {
        read_findings.push(json!({"finding": "bad_format", "log_lines": view.skipped}));
    }
    let authority = authority_key_ids_in(&view.events);
    verify_chain(
        &statements,
        read_findings,
        &|count| view.root_at(count),
        view.leaves.len(),
        ChainOptions { log: LOG_AUDIT, pinned, authority_key_ids: &authority },
    )
}

// ------------------------------------------------------------------ one receipt, offline

/// What `verify_receipt_bundle` returns, field for field.
#[derive(Debug, Clone, PartialEq)]
pub struct BundleVerdict {
    pub ok: bool,
    /// `signed` (a pinned key made the signature), `signed-unpinned` (the key the statement carries
    /// made it; none was pinned) or `invalid`.
    pub status: &'static str,
    pub pinned: bool,
    pub leaf: bool,
    /// The receipt's `idx` equals the bundle's `index`.
    pub index_matches: bool,
    pub inclusion: bool,
    pub well_formed: bool,
    /// The bundle's `index` is a leaf the statement covers: `0 <= index < leaves`.
    pub covered: bool,
    pub key_id: bool,
    pub signature: bool,
    /// `None` when no key was pinned.
    pub pinned_check: Option<bool>,
    pub index: Value,
    pub statement: Value,
    /// `None` for a bundle that is not shaped like one.
    pub statement_sha256: Option<String>,
    pub key: Value,
    /// Why the bundle is not shaped like a receipt bundle (`bundle_problem`). When set, the checks
    /// were not run: the only one reported is `well_formed: false`.
    pub problem: Option<String>,
}

impl BundleVerdict {
    pub fn to_json(&self) -> Value {
        if let Some(problem) = &self.problem {
            return json!({
                "ok": false, "status": INVALID, "pinned": self.pinned, "checks": {"well_formed": false},
                "problem": problem, "index": null, "statement": null, "statement_sha256": null, "key": "",
            });
        }
        json!({
            "ok": self.ok, "status": self.status, "pinned": self.pinned,
            "checks": {"leaf": self.leaf, "index": self.index_matches, "inclusion": self.inclusion,
                       "well_formed": self.well_formed, "covered": self.covered, "key_id": self.key_id,
                       "signature": self.signature, "pinned": self.pinned_check},
            "index": self.index, "statement": self.statement, "statement_sha256": self.statement_sha256,
            "key": self.key,
        })
    }
}

/// A test of one bundle field's JSON type.
type ShapeCheck = fn(&Value) -> bool;

/// Why `bundle` is not shaped like a receipt bundle, or `None` (`root_statement.bundle_problem`). A
/// bundle read from a file is untrusted input, so every field the check touches is looked at first, in
/// the reference's order, and the reason is its text.
pub fn bundle_problem(bundle: &Value) -> Option<String> {
    let Some(object) = bundle.as_object() else { return Some("a bundle is a JSON object".to_string()) };
    let shapes: [(&str, ShapeCheck); 5] = [
        ("receipt", Value::is_object),
        ("index", |value| value.is_i64() || value.is_u64()),
        ("leaf", Value::is_string),
        ("path", Value::is_array),
        ("statement", Value::is_object),
    ];
    for (name, is_kind) in shapes {
        if !object.get(name).is_some_and(is_kind) {
            return Some(format!("missing or malformed field '{name}'"));
        }
    }
    const NOT_HEX: &str = "the leaf and the inclusion path are hex hashes";
    if object["leaf"].as_str().and_then(from_hex).is_none() {
        return Some(NOT_HEX.to_string());
    }
    for step in object["path"].as_array().expect("checked") {
        let pair = step.as_array().filter(|pair| pair.len() == 2 && matches!(pair[0].as_str(), Some("L" | "R")));
        let Some(pair) = pair else { return Some("malformed inclusion path".to_string()) };
        if pair[1].as_str().and_then(from_hex).is_none() {
            return Some(NOT_HEX.to_string());
        }
    }
    None
}

/// Python's `receipt.get("idx") == bundle["index"]`, where `index` is an integer: a number equal to it
/// (`4.0` is, as in Python) or a boolean equal to it (`True == 1`, as in Python).
fn idx_equals(idx: Option<&Value>, index: i128) -> bool {
    match idx {
        Some(Value::Bool(flag)) => i128::from(*flag) == index,
        Some(Value::Number(number)) => match (number.as_i64(), number.as_u64()) {
            (Some(int), _) => i128::from(int) == index,
            (None, Some(int)) => i128::from(int) == index,
            // A float is equal to an integer exactly when it has no fraction and is that integer.
            _ => number.as_f64().is_some_and(|float| float.fract() == 0.0 && float.abs() < 1.0e30 && float as i128 == index),
        },
        _ => false,
    }
}

/// receipt -> leaf -> index -> inclusion path -> signed root -> signature, and the key against `pinned`.
/// Offline and self contained. It checks the one statement in the bundle, not the chain around it.
/// A bundle that is not shaped like one is `invalid` with a `problem`, never an `Err`. `Err` is left
/// for what still raises in the reference: a statement whose `key_id` is not text (and, with a key
/// pinned, one that is a list or object, which cannot be compared).
pub fn verify_receipt_bundle(bundle: &Value, pinned: &[Vec<u8>]) -> Result<BundleVerdict, String> {
    let pinned_ids: Vec<String> = pinned.iter().map(|raw| key_id_of(raw)).collect();
    if let Some(problem) = bundle_problem(bundle) {
        return Ok(BundleVerdict {
            ok: false,
            status: INVALID,
            pinned: !pinned.is_empty(),
            leaf: false,
            index_matches: false,
            inclusion: false,
            well_formed: false,
            covered: false,
            key_id: false,
            signature: false,
            pinned_check: None,
            index: Value::Null,
            statement: Value::Null,
            statement_sha256: None,
            key: json!(""),
            problem: Some(problem),
        });
    }
    let statement = &bundle["statement"];
    let index = &bundle["index"];
    let index_int = index.as_i64().map(i128::from).or_else(|| index.as_u64().map(i128::from)).expect("checked");
    let leaf = sha256_hex(&canonical_bytes(&bundle["receipt"]));
    let leaf_hex = bundle["leaf"].as_str().expect("checked");
    let leaf_matches = leaf_hex == leaf;
    let index_matches = idx_equals(bundle["receipt"].get("idx"), index_int);
    let path = path_from_json(&bundle["path"])?;
    // The root is only compared with the computed one, so a root that is missing or not text never matches.
    let root = statement.get("root").and_then(Value::as_str).unwrap_or("");
    let inclusion = verify_leaf(leaf_hex, &path, root)?;
    let well_formed = well_formed(statement, LOG_AUDIT);
    let covered = well_formed && index_int >= 0 && index_int < i128::from(py_int(&statement["leaves"]).expect("well formed"));
    let key_id = well_formed && key_id_of(&public_raw(statement)) == statement["key_id"].as_str().unwrap_or_default();
    let signature = key_id && signature_verifies(statement);
    let pinned_check = if pinned_ids.is_empty() {
        None
    } else {
        match statement.get("key_id") {
            Some(Value::Array(_) | Value::Object(_)) => {
                return Err("the statement's key_id cannot be compared with a pinned key".to_string())
            }
            other => Some(other.and_then(Value::as_str).is_some_and(|id| pinned_ids.iter().any(|pinned| pinned == id))),
        }
    };
    let ok = leaf_matches && index_matches && inclusion && well_formed && covered && key_id && signature && pinned_check != Some(false);
    let key = match statement.get("key_id") {
        None => json!(""),
        Some(Value::String(id)) => json!(fingerprint(id)),
        // Python slices whatever is there: a list gives its first 16 items, anything else raises.
        Some(Value::Array(items)) => Value::Array(items.iter().take(16).cloned().collect()),
        Some(_) => return Err("the statement's key_id is not a string".to_string()),
    };
    Ok(BundleVerdict {
        ok,
        status: if !ok { INVALID } else if pinned_ids.is_empty() { SIGNED_UNPINNED } else { SIGNED },
        pinned: !pinned_ids.is_empty(),
        leaf: leaf_matches,
        index_matches,
        inclusion,
        well_formed,
        covered,
        key_id,
        signature,
        pinned_check,
        index: index.clone(),
        statement: statement.get("seq").cloned().unwrap_or(Value::Null),
        statement_sha256: Some(statement_hash(statement)),
        key,
        problem: None,
    })
}
