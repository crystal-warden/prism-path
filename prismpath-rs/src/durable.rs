// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! durable.rs: durable execution + attestation manifests, feature `durable`.
//!
//! Faithful port of the runtime-relevant parts of `prismpath/checkpoint.py` and
//! `prismpath/ledger_airgap.py`:
//!
//!   * the JSON checkpoint: `run_durable` persists a sidecar at every step (atomic
//!     write-then-rename), `resume` re-parses the READ-ONLY `.md` and re-enters the engine at the
//!     pending node (crash), the human's chosen edge (`choose`), or the delivered event (`event`).
//!     The flow file is NEVER written; a resume against an edited flow is refused by content hash
//!     (`PRISMPATH_RESUME_ON_FLOW_CHANGE` = refuse | warn | allow, same contract as Python).
//!   * the content-addressed provenance/override manifests + `verify_manifest` + `salt_leaf`:
//!     the tamper-evidence primitives. `manifest_hash` is sha256 over the manifest's canon/2 bytes
//!     (`canon2_bytes`), so a manifest built on either runtime verifies on the other. canon/1, the
//!     earlier Python `json.dumps` layout, is retired: an untagged manifest is refused.
//!
//! Deliberately NOT ported (ops tooling, not edge runtime): the OTS batch-forward relay, tar
//! bundling, and the RFC-3161/openssl subprocess tiers of `ledger_airgap.py`; the Mission Control
//! human-queue helpers of `checkpoint.py`; and the git Flow-Ledger (`ledger.py`).
//!
//! The `type_gate` flag is persisted and enforced: a run, and a resume of one, hold each worker's output to
//! the contract derived from the flow (`contract::derive_contract`), so a Python resume of a Rust checkpoint
//! and the reverse keep the gate on.

use crate::{
    event_name, is_event, parse, run_observed, EngineError, Pending, RunOpts, RunResult, RunState,
    Step, Value as EngineValue, WorkerError,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write;

pub const CHECKPOINT_VERSION: i64 = 1;

#[derive(Debug)]
pub struct CheckpointError(pub String);
impl std::fmt::Display for CheckpointError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.0)
    }
}
impl std::error::Error for CheckpointError {}
fn cerr<RetType>(msg: impl Into<String>) -> Result<RetType, CheckpointError> {
    Err(CheckpointError(msg.into()))
}

// Python-parity canonical JSON

/// A value that has no canonical form: a number beyond the double range (`1e400`), a float in hashed
/// content, a document that does not name canon/2. `prismpath.canon.CanonicalError` is the same refusal in
/// Python. A string with a lone surrogate never reaches here, because a Rust `String` cannot hold one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalError(pub String);

impl std::fmt::Display for CanonicalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.0)
    }
}
impl std::error::Error for CanonicalError {}

/// Python `json.dumps(obj, sort_keys=True)` for a value that is never hashed or signed: a line of the
/// connector's JSONL sink. Sorted keys, the default `(", ", ": ")` separators, `ensure_ascii` escaping, ints
/// of any width, floats as `repr(float)`. It is `prismpath.canon.plain_dumps(..., sort_keys=True)`. Nothing
/// that is hashed or signed is written with it (canon/2 is: `canon2_bytes`), and a test holds every call of
/// it to a list of sink and message writers. A number beyond the double range is refused with
/// `CanonicalError`; it is never written as `Infinity`.
pub fn plain_dumps(val: &Value) -> Result<String, CanonicalError> {
    Ok(match val {
        Value::Null => "null".to_string(),
        Value::Bool(bool_val) => bool_val.to_string(),
        Value::Number(num_val) => {
            if let Some(i_val) = num_val.as_i64() {
                i_val.to_string()
            } else if let Some(u_val) = num_val.as_u64() {
                u_val.to_string()
            } else if let Some(integer) = beyond_64_bit_integer(num_val) {
                integer
            } else {
                match crate::value::number_to_f64(num_val) {
                    Some(float) => py_float_repr(float),
                    None => return Err(CanonicalError("NaN, Infinity and -Infinity have no JSON form".to_string())),
                }
            }
        }
        Value::String(raw) => py_json_quote(raw),
        Value::Array(arr_val) => {
            let items = arr_val.iter().map(plain_dumps).collect::<Result<Vec<String>, _>>()?;
            format!("[{}]", items.join(", "))
        }
        Value::Object(obj_map) => {
            let sorted: BTreeMap<&String, &Value> = obj_map.iter().collect();
            let items = sorted
                .iter()
                .map(|(key, item)| Ok(format!("{}: {}", py_json_quote(key), plain_dumps(item)?)))
                .collect::<Result<Vec<String>, CanonicalError>>()?;
            format!("{{{}}}", items.join(", "))
        }
    })
}

// canon/2, the one encoding of everything hashed or signed

/// The encoding every hashed or signed document is written in, named by the document's own
/// `encoding` member (`prismpath.canon.CANON2` in Python).
pub const CANON2: &str = "canon/2";
pub const ENCODING_KEY: &str = "encoding";
/// The domain a signature over a canon/2 document is computed over, before the document's bytes, when
/// its format has no domain of its own (`prismpath.canon.CANON2_DOMAIN`).
pub const CANON2_DOMAIN: &[u8] = b"prismpath.canon/2\x00";

/// `canon/2` for an object that names it. Any other tag, an object with no tag (canon/1, retired) and a
/// value that is not an object are refused. `prismpath.canon.encoding_of`.
pub fn encoding_of(val: &Value) -> Result<&'static str, CanonicalError> {
    match val.as_object().and_then(|obj| obj.get(ENCODING_KEY)) {
        None => Err(CanonicalError(
            "a document without \"encoding\": \"canon/2\" is refused: canon/1 is retired and is not read, hashed or verified".to_string(),
        )),
        Some(Value::String(tag)) if tag == CANON2 => Ok(CANON2),
        Some(other) => Err(CanonicalError(format!(
            "unknown encoding {}: only canon/2 is read",
            other.to_string().chars().take(40).collect::<String>()
        ))),
    }
}

/// The canon/2 bytes of `val`, the bytes every writer hashes and signs. A float, an integer beyond plus
/// or minus 2^53 minus 1 and nesting deeper than 128 are refused, never converted.
pub fn canon2_bytes(val: &Value) -> Result<Vec<u8>, CanonicalError> {
    crate::canon2::write_json(val).map_err(|error| CanonicalError(format!("no canon/2 form: {error}")))
}

/// The message of the refusal of a float in hashed content, the same words as
/// `prismpath.canon.FloatRefused`.
pub const FLOAT_REFUSED: &str =
    "a float is refused in hashed content: supply an integer of a stated unit (microseconds, basis points, bytes) or a decimal string";

/// The canon/2 bytes of content PrismPath hashes but did not write (a worker's outcome, a connector's
/// data). canon/2 has no float and PrismPath writes no spelling of one, so a number with a fraction or an
/// exponent anywhere in the content is refused (`FLOAT_REFUSED`), never converted. The caller supplies an
/// integer of a stated unit or a decimal string. `prismpath.canon.content_bytes`.
pub fn content_bytes(val: &Value) -> Result<Vec<u8>, CanonicalError> {
    fn is_float(val: &Value) -> bool {
        match val {
            Value::Number(number) => number.as_i64().is_none() && number.as_u64().is_none() && beyond_64_bit_integer(number).is_none(),
            Value::Array(items) => items.iter().any(is_float),
            Value::Object(members) => members.values().any(is_float),
            _ => false,
        }
    }
    if is_float(val) {
        return Err(CanonicalError(FLOAT_REFUSED.to_string()));
    }
    canon2_bytes(val)
}

/// `val` with `"encoding": "canon/2"`.
pub fn tagged(mut val: Value) -> Value {
    if let Value::Object(obj) = &mut val {
        obj.insert(ENCODING_KEY.to_string(), Value::String(CANON2.to_string()));
    }
    val
}

/// The bytes a document is hashed over: its canon/2 bytes. A document that does not name canon/2 is
/// refused. `prismpath.canon.document_bytes`.
pub fn document_bytes(val: &Value) -> Result<Vec<u8>, CanonicalError> {
    encoding_of(val)?;
    canon2_bytes(val)
}

/// What a signature over `val` covers when its format has no domain of its own: `CANON2_DOMAIN` and the
/// canon/2 bytes. A document that does not name canon/2 is refused. `prismpath.canon.signed_message`.
pub fn signed_message(val: &Value) -> Result<Vec<u8>, CanonicalError> {
    encoding_of(val)?;
    let mut message = CANON2_DOMAIN.to_vec();
    message.extend(canon2_bytes(val)?);
    Ok(message)
}

/// The registered cause of a hashed or signed document that reads as canon/2 but is not its exact
/// canonical bytes (`prismpath.canon.NotCanonical.CAUSE`).
pub const NOT_CANONICAL_CAUSE: &str = "document:not-canonical";

impl CanonicalError {
    /// The document read as canon/2 but was not its exact canonical bytes: the refusal whose registered
    /// cause is `document:not-canonical`.
    pub fn is_not_canonical(&self) -> bool {
        self.0.starts_with(NOT_CANONICAL_CAUSE)
    }
}

const NOT_CANONICAL_HELP: &str =
    "a hashed or signed document must be its exact canonical canon/2 bytes; write it through `prismpath canonicalize` first";

/// A document file or a JSON Lines line holds the canonical bytes followed by one line feed, the record
/// terminator, which is not part of the document; exactly that one byte is taken off.
fn strip_terminator(text: &str) -> &str {
    text.strip_suffix('\n').unwrap_or(text)
}

/// Read a document that is hashed or signed: an object that names canon/2, given as exactly its canonical
/// canon/2 bytes (followed by at most the one line feed that ends a file or a line). A float, a duplicate
/// key or an out of range integer is refused, and so is a document in any spelling but its canonical one
/// (`document:not-canonical`); an untagged object, another tag and a value that is not an object are
/// refused. `prismpath.canon.loads_document`.
pub fn read_document(text: &str) -> Result<Value, CanonicalError> {
    let text = strip_terminator(text);
    let val = crate::value::parse_plain(text).map_err(|error| CanonicalError(error.to_string()))?;
    if !val.is_object() {
        return Err(CanonicalError("a document that is hashed or signed is a JSON object".to_string()));
    }
    encoding_of(&val)?;
    crate::canon2::read_str(text).map_err(|error| match error {
        crate::canon2::Canon2Error::NotCanonical => CanonicalError(format!("{NOT_CANONICAL_CAUSE}: {NOT_CANONICAL_HELP}")),
        error => CanonicalError(format!("a document that is read as canon/2 does not read under it: {error}")),
    })?;
    Ok(val)
}

/// The canonical canon/2 bytes of a document a person wrote, in any legal spelling (whitespace, member
/// order, escapes), so that it can be hashed, signed or read; every other canon/2 rule still holds, and
/// the result is exactly what `read_document` and `canon2::read` accept. The writer's side of the strict
/// reader (`prismpath.canon.canonicalize_document`).
pub fn canonicalize_document(text: &str) -> Result<Vec<u8>, CanonicalError> {
    crate::canon2::canonicalize(strip_terminator(text).as_bytes())
        .map_err(|error| CanonicalError(format!("no canon/2 form: {error}")))
}

/// An integer too wide for i64 and u64, written the way Python writes it: every digit, no
/// exponent. serde_json is built with `arbitrary_precision`, so such a number still carries the
/// digits it was read from; a number written as a float (`1.0`, `1e30`) is not an integer here,
/// and `-0` is Python's `0`.
fn beyond_64_bit_integer(num_val: &serde_json::Number) -> Option<String> {
    let text = num_val.to_string();
    let digits = text.strip_prefix('-').unwrap_or(&text);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if digits.bytes().all(|byte| byte == b'0') {
        return Some("0".to_string());
    }
    Some(text)
}

/// Python `repr(float)`, which is what `json.dumps` writes for a float: the shortest digits that
/// round trip, fixed notation from 1e-4 up to (not including) 1e16 with a `.0` when integral, and
/// otherwise an exponent with an explicit sign and at least two digits (`1e-05`, `1.5e+20`).
/// Rust's own `Display` differs from this outside that window (`0.00001`, `150000000000000000000`).
/// Non finite values are written as `json.dumps` writes them (`NaN`, `Infinity`, `-Infinity`), so
/// this function is a spelling of `repr(float)` only; canonical JSON never calls it with one.
pub fn py_float_repr(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_string();
    }
    if value.is_infinite() {
        return if value < 0.0 { "-Infinity" } else { "Infinity" }.to_string();
    }
    let sign = if value.is_sign_negative() { "-" } else { "" };
    if value == 0.0 {
        return format!("{sign}0.0");
    }
    // `{:e}` writes the shortest round trip digits as `d.ddde<exp>`.
    let scientific = format!("{:e}", value.abs());
    let (mantissa, exponent) = scientific.split_once('e').expect("LowerExp always has an exponent");
    let exponent: i32 = exponent.parse().expect("LowerExp exponent is an integer");
    let digits: String = mantissa.chars().filter(|digit| *digit != '.').collect();
    if !(-4..16).contains(&exponent) {
        let (head, tail) = digits.split_at(1);
        let fraction = if tail.is_empty() { String::new() } else { format!(".{tail}") };
        let exponent_sign = if exponent < 0 { '-' } else { '+' };
        return format!("{sign}{head}{fraction}e{exponent_sign}{:02}", exponent.abs());
    }
    if exponent < 0 {
        return format!("{sign}0.{}{digits}", "0".repeat((-exponent - 1) as usize));
    }
    let integer_len = exponent as usize + 1;
    if digits.len() <= integer_len {
        format!("{sign}{digits}{}.0", "0".repeat(integer_len - digits.len()))
    } else {
        format!("{sign}{}.{}", &digits[..integer_len], &digits[integer_len..])
    }
}

/// Python json's default string escaping (`ensure_ascii=True`): `"` `\` and control chars use the
/// short escapes, everything non-ASCII becomes `\uXXXX` (surrogate pairs above the BMP).
fn py_json_quote(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 2);
    out.push('"');
    for ch in raw.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            char_val if (char_val as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", char_val as u32)),
            char_val if (char_val as u32) < 0x7f => out.push(char_val),
            char_val => {
                let code_point = char_val as u32;
                if code_point <= 0xffff {
                    out.push_str(&format!("\\u{code_point:04x}"));
                } else {
                    let val_offset = code_point - 0x10000;
                    out.push_str(&format!("\\u{:04x}\\u{:04x}", 0xd800 + (val_offset >> 10), 0xdc00 + (val_offset & 0x3ff)));
                }
            }
        }
    }
    out.push('"');
    out
}

// hashes

/// Content hash of a flow file: the run's POLICY HASH ("sha256:<hex>"; "" if unreadable).
pub fn flow_hash(path: &str) -> String {
    match std::fs::read(path) {
        Ok(bytes) => format!("sha256:{}", hex::encode(Sha256::digest(&bytes))),
        Err(_) => String::new(),
    }
}

// state / pending <-> checkpoint JSON

/// RunState -> the reference's state dict: engine fields under their Python names (`visits`,
/// `transcript`, `_errors`, `_outcomes`), host fields alongside.
pub fn state_to_json(st: &RunState) -> Value {
    let mut map_obj = serde_json::Map::new();
    for (key, val) in &st.extra {
        map_obj.insert(key.clone(), val.to_json());
    }
    let mut visits = serde_json::Map::new();
    for (key, count) in &st.visits {
        visits.insert(key.clone(), Value::Number((*count).into()));
    }
    map_obj.insert("visits".to_string(), Value::Object(visits));
    if !st.dropped.is_empty() {
        let mut dropped = serde_json::Map::new();
        for (key, count) in &st.dropped {
            dropped.insert(key.clone(), Value::Number((*count).into()));
        }
        map_obj.insert("_state_dropped".to_string(), Value::Object(dropped));
    }
    map_obj.insert(
        "transcript".to_string(),
        Value::Array(st.transcript.iter().map(EngineValue::to_json).collect()),
    );
    if !st.guard_errors.is_empty() {
        map_obj.insert("_guard_errors".to_string(), Value::Array(st.guard_errors.iter().map(EngineValue::to_json).collect()));
    }
    if !st.errors.is_empty() {
        let mut errs = serde_json::Map::new();
        for (key, count) in &st.errors {
            errs.insert(key.clone(), Value::Number((*count).into()));
        }
        map_obj.insert("_errors".to_string(), Value::Object(errs));
    }
    if !st.outcomes.is_empty() {
        let mut outs = serde_json::Map::new();
        for (key, entries) in &st.outcomes {
            outs.insert(key.clone(), EngineValue::Obj(entries.clone()).to_json());
        }
        map_obj.insert("_outcomes".to_string(), Value::Object(outs));
    }
    Value::Object(map_obj)
}

/// Pending -> the evidence-packet dict the reference engine builds.
pub fn pending_to_json(pending: &Pending) -> Value {
    let mut map_obj = serde_json::Map::new();
    map_obj.insert("node".to_string(), Value::String(pending.node.clone()));
    if pending.wait {
        map_obj.insert("wait".to_string(), Value::Bool(true));
        map_obj.insert(
            "awaiting".to_string(),
            Value::Array(pending.awaiting.iter().map(|item| Value::String(item.clone())).collect()),
        );
        map_obj.insert(
            "timeout_s".to_string(),
            pending.timeout_s.as_ref().map(EngineValue::to_json).unwrap_or(Value::Null),
        );
    } else if let Some(reason) = &pending.reason {
        map_obj.insert("reason".to_string(), Value::String(reason.clone()));
    }
    if let Some(violations) = &pending.violations {
        // a contract violation's evidence packet is the node, the reason and the problems, with no candidates
        map_obj.insert(
            "violations".to_string(),
            Value::Array(violations.iter().map(|item| Value::String(item.clone())).collect()),
        );
        return Value::Object(map_obj);
    }
    if let Some(would_pick) = &pending.would_pick {
        map_obj.insert("would_pick".to_string(), Value::String(would_pick.clone()));
    }
    let cands: Vec<Value> = match &pending.scored_candidates {
        Some(scored) => scored
            .iter()
            .map(|(target, cond, score)| {
                serde_json::json!({"target": target, "condition": cond, "score": score})
            })
            .collect(),
        None => pending
            .candidates
            .iter()
            .map(|(target, cond)| serde_json::json!({"target": target, "condition": cond}))
            .collect(),
    };
    map_obj.insert("candidates".to_string(), Value::Array(cands));
    if let Some(spawn_val) = &pending.spawn {
        map_obj.insert("spawn".to_string(), spawn_val.to_json());
    }
    Value::Object(map_obj)
}

// checkpoint

fn atomic_write(path: &str, data: &str) -> Result<(), CheckpointError> {
    if let Some(dir_path) = std::path::Path::new(path).parent() {
        if !dir_path.as_os_str().is_empty() {
            std::fs::create_dir_all(dir_path).map_err(|err| CheckpointError(err.to_string()))?;
        }
    }
    let tmp_path = format!("{path}.tmp");
    {
        let mut file_handle = std::fs::File::create(&tmp_path).map_err(|err| CheckpointError(err.to_string()))?;
        file_handle.write_all(data.as_bytes()).map_err(|err| CheckpointError(err.to_string()))?;
        file_handle.sync_all().map_err(|err| CheckpointError(err.to_string()))?;
    }
    std::fs::rename(&tmp_path, path).map_err(|err| CheckpointError(err.to_string()))
}

fn now_epoch() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|dur| dur.as_secs_f64())
        .unwrap_or(0.0)
}

/// Serialize the run to `path` atomically; `pending_node` is where a resume re-enters.
pub fn save_checkpoint(
    path: &str,
    flow_path: &str,
    result: &RunResult,
    state: &RunState,
    pending_node: Option<&str>,
    type_gate: bool,
) -> Result<(), CheckpointError> {
    let abs_path = std::fs::canonicalize(flow_path)
        .map(|path_buf| path_buf.to_string_lossy().into_owned())
        .unwrap_or_else(|_| flow_path.to_string());
    let doc = serde_json::json!({
        "version": CHECKPOINT_VERSION,
        "flow_path": abs_path,
        "flow_hash": flow_hash(flow_path),
        "pending_node": pending_node,
        "stopped": result.stopped,
        "type_gate": type_gate,
        "saved_at": now_epoch(),
        "path": result.path,
        "state": state_to_json(state),
        "pending_decision": result.pending.as_ref().map(pending_to_json).unwrap_or(Value::Null),
        "steps": result.steps.iter().map(|step| serde_json::json!({
            "node": step.node, "target": step.target,
            "used": step.used,
        })).collect::<Vec<_>>(),
    });
    atomic_write(path, &serde_json::to_string_pretty(&doc).map_err(|err| CheckpointError(err.to_string()))?)
}

pub fn load_checkpoint(path: &str) -> Result<Value, CheckpointError> {
    let text = std::fs::read_to_string(path).map_err(|err| CheckpointError(err.to_string()))?;
    let cp: Value = crate::value::parse_plain(&text).map_err(|err| CheckpointError(err.to_string()))?;
    if cp.get("version").and_then(|ver| ver.as_i64()) != Some(CHECKPOINT_VERSION) {
        return cerr(format!(
            "unsupported checkpoint version {:?} (this build expects {CHECKPOINT_VERSION})",
            cp.get("version")
        ));
    }
    Ok(cp)
}

fn check_flow_unchanged(cp: &Value) -> Result<(), CheckpointError> {
    let old_hash = cp.get("flow_hash").and_then(|hash_val| hash_val.as_str()).unwrap_or("");
    if old_hash.is_empty() {
        return Ok(());
    }
    let flow_path = cp.get("flow_path").and_then(|path_val| path_val.as_str()).unwrap_or("");
    let now_hash = flow_hash(flow_path);
    if !now_hash.is_empty() && now_hash == old_hash {
        return Ok(());
    }
    let policy = std::env::var("PRISMPATH_RESUME_ON_FLOW_CHANGE")
        .unwrap_or_default()
        .to_lowercase();
    let msg = format!(
        "flow {flow_path:?} changed since this run was checkpointed (was {}..., now {}...)",
        &old_hash[..old_hash.len().min(23)],
        if now_hash.is_empty() { "missing" } else { &now_hash[..now_hash.len().min(23)] },
    );
    match policy.as_str() {
        "allow" => Ok(()),
        "warn" => {
            eprintln!("  [checkpoint] WARNING: {msg} - resuming anyway");
            Ok(())
        }
        _ => cerr(format!(
            "{msg}. Refusing to resume against a changed flow - set \
             PRISMPATH_RESUME_ON_FLOW_CHANGE=warn (proceed) or =allow (silent) to override."
        )),
    }
}

// run_durable / resume

pub fn run_durable<WorkErr, AgentFn>(
    flow_path: &str,
    agent: AgentFn,
    checkpoint_path: &str,
    type_gate: bool,
    mut opts: RunOpts,
) -> Result<RunResult, EngineError>
where
    AgentFn: FnMut(&str, &str, &RunState) -> Result<EngineValue, WorkErr>,
    WorkErr: Into<WorkerError>,
{
    opts.type_gate = opts.type_gate || type_gate;
    let text = std::fs::read_to_string(flow_path)
        .map_err(|err| EngineError::Unhandled(format!("cannot read flow {flow_path:?}: {err}")))?;
    let graph = parse(&text);
    let mut disabled = false;
    run_observed(&graph, agent, opts, |res, state, pending_node| {
        if disabled {
            return;
        }
        if let Err(err) = save_checkpoint(checkpoint_path, flow_path, res, state, pending_node, type_gate)
        {
            eprintln!("  [checkpoint] disabled for this run - {err}");
            disabled = true;
        }
    })
}

fn prior_steps(cp: &Value) -> Vec<Step> {
    cp.get("steps")
        .and_then(|steps_val| steps_val.as_array())
        .map(|arr| {
            arr.iter()
                .map(|step_item| Step {
                    node: step_item.get("node").and_then(|str_val| str_val.as_str()).unwrap_or("").to_string(),
                    outcome: String::new(),
                    target: step_item.get("target").and_then(|str_val| str_val.as_str()).unwrap_or("").to_string(),
                    used: step_item.get("used").and_then(|str_val| str_val.as_str()).unwrap_or("").to_string(),
                    cond: None,
                    score: None,
                    margin: None,
                    sims: None,
                    locked: None,
                    error_type: None,
                    guard_errors: None,
                })
                .collect()
        })
        .unwrap_or_default()
}

fn push_transcript(state_v: &mut EngineValue, entry: EngineValue) {
    if let EngineValue::Obj(entries) = state_v {
        if let Some((_, EngineValue::List(items))) = entries.iter_mut().find(|(key, _)| key == "transcript") {
            items.push(entry);
            return;
        }
        entries.push(("transcript".to_string(), EngineValue::List(vec![entry])));
    }
}

pub fn resume<WorkErr, AgentFn>(
    checkpoint_path: &str,
    agent: AgentFn,
    choose: Option<&str>,
    event: Option<&str>,
    max_steps: usize,
    write_back: bool,
) -> Result<RunResult, CheckpointError>
where
    AgentFn: FnMut(&str, &str, &RunState) -> Result<EngineValue, WorkErr>,
    WorkErr: Into<WorkerError>,
{
    let cp = load_checkpoint(checkpoint_path)?;
    check_flow_unchanged(&cp)?;
    let flow_path =
        cp.get("flow_path").and_then(|path_val| path_val.as_str()).ok_or(CheckpointError("no flow_path".into()))?;
    let text = std::fs::read_to_string(flow_path)
        .map_err(|err| CheckpointError(format!("cannot read flow {flow_path:?}: {err}")))?;
    let graph = parse(&text);
    let mut state_v = EngineValue::try_from_json(cp.get("state").unwrap_or(&Value::Null)).map_err(CheckpointError)?;
    if !matches!(state_v, EngineValue::Obj(_)) {
        state_v = EngineValue::Obj(vec![]);
    }
    let stopped = cp.get("stopped").and_then(|str_val| str_val.as_str()).unwrap_or("");
    let type_gate = cp.get("type_gate").and_then(|bool_val| bool_val.as_bool()).unwrap_or(false);
    let choose: Option<String> = match choose {
        Some(choose_str) => Some(choose_str.to_string()),
        None => cp
            .get("decision")
            .and_then(|decision_obj| decision_obj.get("choose"))
            .and_then(|str_val| str_val.as_str())
            .map(|str_val| str_val.to_string()),
    };
    let seed_path: Vec<String> = cp
        .get("path")
        .and_then(|arr_val| arr_val.as_array())
        .map(|arr| arr.iter().filter_map(|item| item.as_str().map(|str_val| str_val.to_string())).collect())
        .unwrap_or_default();
    let pend = cp.get("pending_decision").cloned().unwrap_or(Value::Null);
    let pending_node = cp.get("pending_node").and_then(|path_val| path_val.as_str()).map(|str_val| str_val.to_string());

    let run_seeded = |start: String,
                      state_v: EngineValue,
                      seed_path: Vec<String>,
                      seed_steps: Vec<Step>,
                      mut agent_fn: AgentFn|
      -> Result<RunResult, CheckpointError> {
        let opts = RunOpts {
            max_steps,
            start: Some(start),
            state: Some(state_v),
            seed_path,
            seed_steps,
            type_gate,
            ..Default::default()
        };
        let fp = flow_path.to_string();
        let res = run_observed(&graph, &mut agent_fn, opts, |res, state, pending_node| {
            if write_back {
                let _ = save_checkpoint(checkpoint_path, &fp, res, state, pending_node, type_gate);
            }
        });
        res.map_err(|err| CheckpointError(err.to_string()))
    };

    if let Some(choose) = choose {
        let dnode = pend
            .get("node")
            .and_then(|node_val| node_val.as_str())
            .map(|str_val| str_val.to_string())
            .or(pending_node.clone())
            .ok_or(CheckpointError("checkpoint has no pending node".into()))?;
        let node = graph
            .nodes
            .get(&dnode)
            .ok_or(CheckpointError(format!("pending node {dnode:?} is not in the flow")))?;
        let valid: Vec<&String> = node.edges.iter().map(|(target, _)| target).collect();
        if !valid.iter().any(|target| **target == choose) {
            return cerr(format!(
                "choose {choose:?} is not an edge target of node {dnode:?}; valid: {valid:?}"
            ));
        }
        push_transcript(
            &mut state_v,
            EngineValue::Obj(vec![
                ("node".into(), EngineValue::Str(dnode.clone())),
                ("outcome".into(), EngineValue::Str(format!("[human chose -> {choose}]"))),
                ("decided_by".into(), EngineValue::Str("human".into())),
            ]),
        );
        let mut steps = prior_steps(&cp);
        steps.push(Step {
            node: dnode,
            outcome: "[human decision]".into(),
            target: choose.clone(),
            used: "human".into(),
            cond: None,
            score: None,
            margin: None,
            sims: None,
            locked: None,
            error_type: None,
            guard_errors: None,
        });
        return run_seeded(choose, state_v, seed_path, steps, agent);
    }

    if let Some(event) = event {
        let wnode = pend
            .get("node")
            .and_then(|node_val| node_val.as_str())
            .map(|str_val| str_val.to_string())
            .or(pending_node.clone())
            .ok_or(CheckpointError("checkpoint has no pending node".into()))?;
        let node = graph
            .nodes
            .get(&wnode)
            .ok_or(CheckpointError(format!("pending node {wnode:?} is not in the flow")))?;
        let target = node
            .edges
            .iter()
            .find(|(_, cond)| is_event(cond) && event_name(cond) == event)
            .map(|(target, _)| target.clone());
        let Some(target) = target else {
            let avail: Vec<String> = node
                .edges
                .iter()
                .filter(|(_, cond)| is_event(cond))
                .map(|(_, cond)| event_name(cond))
                .collect();
            return cerr(format!("no edge for event {event:?} on {wnode:?}; awaiting: {avail:?}"));
        };
        push_transcript(
            &mut state_v,
            EngineValue::Obj(vec![
                ("node".into(), EngineValue::Str(wnode.clone())),
                ("outcome".into(), EngineValue::Str(format!("[event: {event}]"))),
                ("event".into(), EngineValue::Str(event.to_string())),
            ]),
        );
        let mut steps = prior_steps(&cp);
        steps.push(Step {
            node: wnode,
            outcome: format!("[event: {event}]"),
            target: target.clone(),
            used: "event".into(),
            cond: None,
            score: None,
            margin: None,
            sims: None,
            locked: None,
            error_type: None,
            guard_errors: None,
        });
        return run_seeded(target, state_v, seed_path, steps, agent);
    }

    match stopped {
        "needs_human" => {
            let cands: Vec<String> = pend
                .get("candidates")
                .and_then(|c_val| c_val.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|c_item| c_item.get("target").and_then(|t_val| t_val.as_str()))
                        .map(|str_val| str_val.to_string())
                        .collect()
                })
                .unwrap_or_default();
            cerr(format!(
                "this run is suspended for a human decision - resume with choose=<edge> \
                 (candidates: {cands:?})"
            ))
        }
        "waiting" => {
            let awaiting = pend.get("awaiting").cloned().unwrap_or(Value::Null);
            cerr(format!(
                "this run is waiting for an event - resume with event=<name> (awaiting: {awaiting})"
            ))
        }
        "terminal" | "stuck" | "max_steps" => {
            cerr(format!("run already finished (stopped={stopped:?}); nothing to resume"))
        }
        _ => {
            let pending = pending_node
                .filter(|p_node| graph.nodes.contains_key(p_node))
                .ok_or(CheckpointError("checkpoint has no resumable pending node".into()))?;
            let prior = if seed_path.is_empty() {
                seed_path
            } else {
                seed_path[..seed_path.len() - 1].to_vec()
            };
            let steps = prior_steps(&cp);
            run_seeded(pending, state_v, prior, steps, agent)
        }
    }
}

// context ledger

pub const CONTEXT_GENESIS: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq)]
pub struct ContextSegment {
    pub idx: usize,
    pub role: String,
    pub leaf: String,
    pub salted: bool,
    pub chain: String,
}

#[derive(Debug, Default)]
pub struct ContextLedger {
    pub segments: Vec<ContextSegment>,
}

/// The context ledger's root: the RFC 6962 root (`crate::merkle`) over the hex leaves, None for none.
pub fn merkle_root_hex(leaves_hex: &[String]) -> Option<String> {
    let leaves: Vec<Vec<u8>> = leaves_hex.iter().map(|str_val| hex::decode(str_val).unwrap_or_default()).collect();
    crate::merkle::root_of_bytes(&leaves).map(hex::encode)
}

impl ContextLedger {
    pub fn commit(
        &mut self,
        role: &str,
        content: &str,
        salt_secret: Option<&str>,
    ) -> Result<&ContextSegment, CheckpointError> {
        let mut leaf = hex::encode(Sha256::digest(content.as_bytes()));
        let salted = salt_secret.is_some();
        if let Some(secret) = salt_secret {
            leaf = salt_leaf(&leaf, secret)?;
        }
        let prev = self.segments.last().map(|seg| seg.chain.clone()).unwrap_or_else(|| {
            CONTEXT_GENESIS.to_string()
        });
        let mut bytes = hex::decode(&prev).map_err(|err| CheckpointError(err.to_string()))?;
        bytes.extend(hex::decode(&leaf).map_err(|err| CheckpointError(err.to_string()))?);
        let chain = hex::encode(Sha256::digest(&bytes));
        self.segments.push(ContextSegment {
            idx: self.segments.len(),
            role: role.to_string(),
            leaf,
            salted,
            chain,
        });
        Ok(self.segments.last().expect("just pushed"))
    }

    pub fn leaves(&self) -> Vec<String> {
        self.segments.iter().map(|seg| seg.leaf.clone()).collect()
    }

    pub fn head(&self) -> String {
        self.segments.last().map(|seg| seg.chain.clone()).unwrap_or_else(|| CONTEXT_GENESIS.to_string())
    }

    pub fn root(&self) -> String {
        merkle_root_hex(&self.leaves()).unwrap_or_default()
    }

    pub fn attest(
        &self,
        policy_hash: Option<&str>,
        gate_id: Option<&str>,
        model_id: &str,
        created: &str,
    ) -> Value {
        let model_hash = format!("sha256:{}", hex::encode(Sha256::digest(model_id.as_bytes())));
        let leaves = self.leaves();
        let leaf_refs: Vec<&str> = leaves.iter().map(|str_val| str_val.as_str()).collect();
        provenance_manifest(
            &self.root(),
            &format!("context:chain:{}", self.head()),
            created,
            policy_hash,
            gate_id,
            &leaf_refs,
            Some(&model_hash),
        )
    }
}

pub fn verify_context_chain(segments: &[ContextSegment]) -> bool {
    let mut prev = CONTEXT_GENESIS.to_string();
    for (idx, seg) in segments.iter().enumerate() {
        if seg.idx != idx {
            return false;
        }
        let (Ok(mut bytes), Ok(leaf)) = (hex::decode(&prev), hex::decode(&seg.leaf)) else {
            return false;
        };
        bytes.extend(leaf);
        let expect = hex::encode(Sha256::digest(&bytes));
        if seg.chain != expect {
            return false;
        }
        prev = expect;
    }
    true
}

// attestation manifests (C1/C4)

/// sha256 over the canon/2 bytes of every field but `manifest_hash`. A manifest that does not name canon/2
/// is refused. `canon.manifest_hash`.
fn manifest_hash_of(manifest_val: &Value) -> Result<String, CanonicalError> {
    let mut body = manifest_val.clone();
    if let Value::Object(obj_map) = &mut body {
        obj_map.remove("manifest_hash");
    }
    encoding_of(manifest_val)?;
    Ok(hex::encode(Sha256::digest(canon2_bytes(&body)?)))
}

#[allow(clippy::too_many_arguments)]
pub fn provenance_manifest(
    root_hex: &str,
    label: &str,
    created: &str,
    policy_hash: Option<&str>,
    gate_id: Option<&str>,
    ingestion_hashes: &[&str],
    knowledge_base_hash: Option<&str>,
) -> Value {
    let mut manifest_val = serde_json::json!({
        "root": root_hex,
        "label": label,
        "created": created,
        "policy_hash": policy_hash,
        "gate_id": gate_id,
        "knowledge_base_hash": knowledge_base_hash,
        "ingestion_hashes": ingestion_hashes,
        "encoding": CANON2,
    });
    // the body holds only the strings and nulls passed in above, which always have a canonical form
    let manifest_sha = manifest_hash_of(&manifest_val).expect("a manifest of strings has a canonical form");
    manifest_val["manifest_hash"] = Value::String(manifest_sha);
    manifest_val
}

/// An override of `prior`, which may be any caller supplied manifest: a member of it with no canonical
/// form (a number beyond the double range) is refused with `CanonicalError`.
pub fn override_manifest(
    prior: &Value,
    overrider_id: &str,
    rationale: &str,
    new_root_hex: &str,
    new_label: Option<&str>,
    created: &str,
) -> Result<Value, CanonicalError> {
    let label = new_label.map(|lbl| lbl.to_string()).unwrap_or_else(|| {
        format!("override:{}", prior.get("label").and_then(|lbl| lbl.as_str()).unwrap_or(""))
    });
    let mut manifest_val = serde_json::json!({
        "kind": "override",
        "supersedes": prior.get("manifest_hash"),
        "prior_root": prior.get("root"),
        "prior_created": prior.get("created"),
        "overrider_id": overrider_id,
        "rationale": rationale,
        "root": new_root_hex,
        "label": label,
        "created": created,
        "policy_hash": prior.get("policy_hash"),
        "gate_id": prior.get("gate_id"),
        "knowledge_base_hash": prior.get("knowledge_base_hash"),
        "ingestion_hashes": prior.get("ingestion_hashes").cloned().unwrap_or(serde_json::json!([])),
        "encoding": CANON2,
    });
    let manifest_sha = manifest_hash_of(&manifest_val)?;
    manifest_val["manifest_hash"] = Value::String(manifest_sha);
    Ok(manifest_val)
}

/// A manifest with no canonical form does not verify.
pub fn verify_manifest(manifest_val: &Value) -> bool {
    match manifest_hash_of(manifest_val) {
        Ok(expected) => manifest_val.get("manifest_hash").and_then(|hash_val| hash_val.as_str()) == Some(expected.as_str()),
        Err(_) => false,
    }
}

pub fn salt_leaf(leaf_hex: &str, secret: &str) -> Result<String, CheckpointError> {
    use hmac::{Hmac, Mac};
    let leaf = hex::decode(leaf_hex).map_err(|err| CheckpointError(format!("bad leaf hex: {err}")))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|err| CheckpointError(err.to_string()))?;
    mac.update(&leaf);
    Ok(hex::encode(mac.finalize().into_bytes()))
}
