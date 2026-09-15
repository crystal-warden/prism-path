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
//!     the tamper-evidence primitives. `manifest_hash` is sha256 over Python's exact
//!     `json.dumps(..., sort_keys=True)` byte layout, reproduced here by `py_canonical_string`
//!     (also used compact for the policy-pack signatures), so a manifest built on either runtime
//!     verifies on the other.
//!
//! Deliberately NOT ported (ops tooling, not edge runtime): the OTS batch-forward relay, tar
//! bundling, and the RFC-3161/openssl subprocess tiers of `ledger_airgap.py`; the Mission Control
//! human-queue helpers of `checkpoint.py`; and the git Flow-Ledger (`ledger.py`).
//!
//! One honest divergence: Python's `type_gate` (worker-contract enforcement) has no Rust engine
//! counterpart yet: the flag is PERSISTED faithfully (so a Python resume of a Rust checkpoint
//! keeps the gate) but this kernel does not enforce it.

use crate::{
    event_name, is_event, parse, run_observed, EngineError, Pending, RunOpts, RunResult, RunState,
    Step, Value as EngineValue,
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

/// Python `json.dumps(obj, sort_keys=True)` byte-for-byte: sorted keys, `ensure_ascii` escaping,
/// ints as ints, floats with a `.0` when integral. `spaced=false` gives the
/// `separators=(",", ":")` compact form the policy-pack signatures use; `spaced=true` the default
/// `(", ", ": ")` form the manifests hash over.
pub fn py_canonical_string(val: &Value, spaced: bool) -> String {
    let (item_sep, key_sep) = if spaced { (", ", ": ") } else { (",", ":") };
    match val {
        Value::Null => "null".to_string(),
        Value::Bool(bool_val) => bool_val.to_string(),
        Value::Number(num_val) => {
            if let Some(i_val) = num_val.as_i64() {
                i_val.to_string()
            } else if let Some(u_val) = num_val.as_u64() {
                u_val.to_string()
            } else {
                let f_val = num_val.as_f64().unwrap_or(f64::NAN);
                if f_val.fract() == 0.0 && f_val.is_finite() && f_val.abs() < 1e16 {
                    format!("{f_val:.1}")
                } else {
                    format!("{f_val}")
                }
            }
        }
        Value::String(raw) => py_json_quote(raw),
        Value::Array(arr_val) => {
            let items: Vec<String> = arr_val.iter().map(|item| py_canonical_string(item, spaced)).collect();
            format!("[{}]", items.join(item_sep))
        }
        Value::Object(obj_map) => {
            let sorted: BTreeMap<&String, &Value> = obj_map.iter().collect();
            let items: Vec<String> = sorted
                .iter()
                .map(|(key, item)| format!("{}{}{}", py_json_quote(key), key_sep, py_canonical_string(item, spaced)))
                .collect();
            format!("{{{}}}", items.join(item_sep))
        }
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
    map_obj.insert(
        "transcript".to_string(),
        Value::Array(st.transcript.iter().map(EngineValue::to_json).collect()),
    );
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
            "used": step.used.split(':').next().unwrap_or(&step.used),
        })).collect::<Vec<_>>(),
    });
    atomic_write(path, &serde_json::to_string_pretty(&doc).map_err(|err| CheckpointError(err.to_string()))?)
}

pub fn load_checkpoint(path: &str) -> Result<Value, CheckpointError> {
    let text = std::fs::read_to_string(path).map_err(|err| CheckpointError(err.to_string()))?;
    let cp: Value = serde_json::from_str(&text).map_err(|err| CheckpointError(err.to_string()))?;
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

pub fn run_durable<AgentFn>(
    flow_path: &str,
    agent: AgentFn,
    checkpoint_path: &str,
    type_gate: bool,
    opts: RunOpts,
) -> Result<RunResult, EngineError>
where
    AgentFn: FnMut(&str, &str, &RunState) -> Result<EngineValue, String>,
{
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

pub fn resume<AgentFn>(
    checkpoint_path: &str,
    agent: AgentFn,
    choose: Option<&str>,
    event: Option<&str>,
    max_steps: usize,
    write_back: bool,
) -> Result<RunResult, CheckpointError>
where
    AgentFn: FnMut(&str, &str, &RunState) -> Result<EngineValue, String>,
{
    let cp = load_checkpoint(checkpoint_path)?;
    check_flow_unchanged(&cp)?;
    let flow_path =
        cp.get("flow_path").and_then(|path_val| path_val.as_str()).ok_or(CheckpointError("no flow_path".into()))?;
    let text = std::fs::read_to_string(flow_path)
        .map_err(|err| CheckpointError(format!("cannot read flow {flow_path:?}: {err}")))?;
    let graph = parse(&text);
    let mut state_v = EngineValue::from_json(cp.get("state").unwrap_or(&Value::Null));
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

pub fn merkle_root_hex(leaves_hex: &[String]) -> Option<String> {
    if leaves_hex.is_empty() {
        return None;
    }
    let mut layer: Vec<Vec<u8>> =
        leaves_hex.iter().map(|str_val| hex::decode(str_val).unwrap_or_default()).collect();
    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            layer.push(layer.last().expect("non-empty").clone());
        }
        layer = layer
            .chunks(2)
            .map(|pair| Sha256::digest([pair[0].as_slice(), pair[1].as_slice()].concat()).to_vec())
            .collect();
    }
    Some(hex::encode(&layer[0]))
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

fn manifest_hash_of(manifest_val: &Value) -> String {
    let mut body = manifest_val.clone();
    if let Value::Object(obj_map) = &mut body {
        obj_map.remove("manifest_hash");
    }
    hex::encode(Sha256::digest(py_canonical_string(&body, true).as_bytes()))
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
    });
    let manifest_sha = manifest_hash_of(&manifest_val);
    manifest_val["manifest_hash"] = Value::String(manifest_sha);
    manifest_val
}

pub fn override_manifest(
    prior: &Value,
    overrider_id: &str,
    rationale: &str,
    new_root_hex: &str,
    new_label: Option<&str>,
    created: &str,
) -> Value {
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
    });
    let manifest_sha = manifest_hash_of(&manifest_val);
    manifest_val["manifest_hash"] = Value::String(manifest_sha);
    manifest_val
}

pub fn verify_manifest(manifest_val: &Value) -> bool {
    manifest_val.get("manifest_hash").and_then(|hash_val| hash_val.as_str()) == Some(manifest_hash_of(manifest_val).as_str())
}

pub fn salt_leaf(leaf_hex: &str, secret: &str) -> Result<String, CheckpointError> {
    use hmac::{Hmac, Mac};
    let leaf = hex::decode(leaf_hex).map_err(|err| CheckpointError(format!("bad leaf hex: {err}")))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|err| CheckpointError(err.to_string()))?;
    mac.update(&leaf);
    Ok(hex::encode(mac.finalize().into_bytes()))
}
