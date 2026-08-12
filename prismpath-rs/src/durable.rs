//! durable.rs — durable execution + attestation manifests, feature `durable`.
//!
//! Faithful port of the runtime-relevant parts of `prismpath/checkpoint.py` and
//! `prismpath/ledger_airgap.py`:
//!
//!   * the JSON checkpoint — `run_durable` persists a sidecar at every step (atomic
//!     write-then-rename), `resume` re-parses the READ-ONLY `.md` and re-enters the engine at the
//!     pending node (crash), the human's chosen edge (`choose`), or the delivered event (`event`).
//!     The flow file is NEVER written; a resume against an edited flow is refused by content hash
//!     (`PRISMPATH_RESUME_ON_FLOW_CHANGE` = refuse | warn | allow, same contract as Python).
//!   * the content-addressed provenance/override manifests + `verify_manifest` + `salt_leaf` —
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
//! counterpart yet — the flag is PERSISTED faithfully (so a Python resume of a Rust checkpoint
//! keeps the gate) but this kernel does not enforce it.

use crate::{
    event_name, is_event, parse, run_observed, EngineError, Pending, RunOpts, RunResult, RunState,
    Step, V,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write;

pub const CHECKPOINT_VERSION: i64 = 1;

#[derive(Debug)]
pub struct CheckpointError(pub String);
impl std::fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for CheckpointError {}
fn cerr<T>(msg: impl Into<String>) -> Result<T, CheckpointError> {
    Err(CheckpointError(msg.into()))
}

// ------------------------------------------------------------- Python-parity canonical JSON

/// Python `json.dumps(obj, sort_keys=True)` byte-for-byte: sorted keys, `ensure_ascii` escaping,
/// ints as ints, floats with a `.0` when integral. `spaced=false` gives the
/// `separators=(",", ":")` compact form the policy-pack signatures use; `spaced=true` the default
/// `(", ", ": ")` form the manifests hash over.
pub fn py_canonical_string(v: &Value, spaced: bool) -> String {
    let (isep, ksep) = if spaced { (", ", ": ") } else { (",", ":") };
    match v {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.to_string()
            } else if let Some(u) = n.as_u64() {
                u.to_string()
            } else {
                let f = n.as_f64().unwrap_or(f64::NAN);
                if f.fract() == 0.0 && f.is_finite() && f.abs() < 1e16 {
                    format!("{f:.1}") // Python repr: 2.0 -> "2.0"
                } else {
                    format!("{f}") // shortest round-trip, same contract as Python repr
                }
            }
        }
        Value::String(s) => py_json_quote(s),
        Value::Array(a) => {
            let items: Vec<String> = a.iter().map(|x| py_canonical_string(x, spaced)).collect();
            format!("[{}]", items.join(isep))
        }
        Value::Object(o) => {
            let sorted: BTreeMap<&String, &Value> = o.iter().collect();
            let items: Vec<String> = sorted
                .iter()
                .map(|(k, x)| format!("{}{}{}", py_json_quote(k), ksep, py_canonical_string(x, spaced)))
                .collect();
            format!("{{{}}}", items.join(isep))
        }
    }
}

/// Python json's default string escaping (`ensure_ascii=True`): `"` `\` and control chars use the
/// short escapes, everything non-ASCII becomes `\uXXXX` (surrogate pairs above the BMP).
fn py_json_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c if (c as u32) < 0x7f => out.push(c),
            c => {
                let cp = c as u32;
                if cp <= 0xffff {
                    out.push_str(&format!("\\u{cp:04x}"));
                } else {
                    let v = cp - 0x10000;
                    out.push_str(&format!("\\u{:04x}\\u{:04x}", 0xd800 + (v >> 10), 0xdc00 + (v & 0x3ff)));
                }
            }
        }
    }
    out.push('"');
    out
}

// --------------------------------------------------------------------------------- hashes

/// Content hash of a flow file — the run's POLICY HASH ("sha256:<hex>"; "" if unreadable).
pub fn flow_hash(path: &str) -> String {
    match std::fs::read(path) {
        Ok(b) => format!("sha256:{}", hex::encode(Sha256::digest(&b))),
        Err(_) => String::new(),
    }
}

// ------------------------------------------------------- state / pending <-> checkpoint JSON

/// RunState -> the reference's state dict: engine fields under their Python names (`visits`,
/// `transcript`, `_errors`, `_outcomes`), host fields alongside.
pub fn state_to_json(st: &RunState) -> Value {
    let mut m = serde_json::Map::new();
    for (k, v) in &st.extra {
        m.insert(k.clone(), v.to_json());
    }
    let mut visits = serde_json::Map::new();
    for (k, n) in &st.visits {
        visits.insert(k.clone(), Value::Number((*n).into()));
    }
    m.insert("visits".to_string(), Value::Object(visits));
    m.insert(
        "transcript".to_string(),
        Value::Array(st.transcript.iter().map(V::to_json).collect()),
    );
    if !st.errors.is_empty() {
        let mut errs = serde_json::Map::new();
        for (k, n) in &st.errors {
            errs.insert(k.clone(), Value::Number((*n).into()));
        }
        m.insert("_errors".to_string(), Value::Object(errs));
    }
    if !st.outcomes.is_empty() {
        // `outcomes` holds each node's LAST outcome as its object entries — the reference's
        // `_outcomes: {node: outcome_dict}`.
        let mut outs = serde_json::Map::new();
        for (k, entries) in &st.outcomes {
            outs.insert(k.clone(), V::Obj(entries.clone()).to_json());
        }
        m.insert("_outcomes".to_string(), Value::Object(outs));
    }
    Value::Object(m)
}

/// Pending -> the evidence-packet dict the reference engine builds (shape depends on why the run
/// suspended; keys the reference omits are omitted here too).
pub fn pending_to_json(p: &Pending) -> Value {
    let mut m = serde_json::Map::new();
    m.insert("node".to_string(), Value::String(p.node.clone()));
    if p.wait {
        m.insert("wait".to_string(), Value::Bool(true));
        m.insert(
            "awaiting".to_string(),
            Value::Array(p.awaiting.iter().map(|a| Value::String(a.clone())).collect()),
        );
        m.insert(
            "timeout_s".to_string(),
            p.timeout_s.as_ref().map(V::to_json).unwrap_or(Value::Null),
        );
    } else if let Some(r) = &p.reason {
        m.insert("reason".to_string(), Value::String(r.clone()));
    }
    if let Some(wp) = &p.would_pick {
        m.insert("would_pick".to_string(), Value::String(wp.clone()));
    }
    let cands: Vec<Value> = match &p.scored_candidates {
        Some(scored) => scored
            .iter()
            .map(|(t, c, s)| {
                serde_json::json!({"target": t, "condition": c, "score": s})
            })
            .collect(),
        None => p
            .candidates
            .iter()
            .map(|(t, c)| serde_json::json!({"target": t, "condition": c}))
            .collect(),
    };
    m.insert("candidates".to_string(), Value::Array(cands));
    if let Some(sp) = &p.spawn {
        m.insert("spawn".to_string(), sp.to_json());
    }
    Value::Object(m)
}

// ------------------------------------------------------------------------------ checkpoint

fn atomic_write(path: &str, data: &str) -> Result<(), CheckpointError> {
    if let Some(dir) = std::path::Path::new(path).parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir).map_err(|e| CheckpointError(e.to_string()))?;
        }
    }
    let tmp = format!("{path}.tmp");
    {
        let mut f = std::fs::File::create(&tmp).map_err(|e| CheckpointError(e.to_string()))?;
        f.write_all(data.as_bytes()).map_err(|e| CheckpointError(e.to_string()))?;
        f.sync_all().map_err(|e| CheckpointError(e.to_string()))?;
    }
    // atomic on POSIX: a reader sees the old or new file, never a torn one
    std::fs::rename(&tmp, path).map_err(|e| CheckpointError(e.to_string()))
}

fn now_epoch() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
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
    let abs = std::fs::canonicalize(flow_path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| flow_path.to_string());
    let doc = serde_json::json!({
        "version": CHECKPOINT_VERSION,
        "flow_path": abs,
        "flow_hash": flow_hash(flow_path),
        "pending_node": pending_node,
        "stopped": result.stopped,
        "type_gate": type_gate,
        "saved_at": now_epoch(),
        "path": result.path,
        "state": state_to_json(state),
        "pending_decision": result.pending.as_ref().map(pending_to_json).unwrap_or(Value::Null),
        // The reference's `used` vocabulary is the bare tier name ("deterministic", "error",
        // "human", …); this kernel's in-memory Step embeds the condition after a colon — strip it
        // at the serialization boundary so the checkpoint format stays Python's.
        "steps": result.steps.iter().map(|s| serde_json::json!({
            "node": s.node, "target": s.target,
            "used": s.used.split(':').next().unwrap_or(&s.used),
        })).collect::<Vec<_>>(),
    });
    atomic_write(path, &serde_json::to_string_pretty(&doc).map_err(|e| CheckpointError(e.to_string()))?)
}

pub fn load_checkpoint(path: &str) -> Result<Value, CheckpointError> {
    let text = std::fs::read_to_string(path).map_err(|e| CheckpointError(e.to_string()))?;
    let cp: Value = serde_json::from_str(&text).map_err(|e| CheckpointError(e.to_string()))?;
    if cp.get("version").and_then(|v| v.as_i64()) != Some(CHECKPOINT_VERSION) {
        return cerr(format!(
            "unsupported checkpoint version {:?} (this build expects {CHECKPOINT_VERSION})",
            cp.get("version")
        ));
    }
    Ok(cp)
}

/// Guard resume against a flow edited while the run was suspended. Same env contract as Python:
/// PRISMPATH_RESUME_ON_FLOW_CHANGE = refuse (default) | warn | allow.
fn check_flow_unchanged(cp: &Value) -> Result<(), CheckpointError> {
    let old = cp.get("flow_hash").and_then(|h| h.as_str()).unwrap_or("");
    if old.is_empty() {
        return Ok(());
    }
    let flow_path = cp.get("flow_path").and_then(|p| p.as_str()).unwrap_or("");
    let now = flow_hash(flow_path);
    if !now.is_empty() && now == old {
        return Ok(());
    }
    let policy = std::env::var("PRISMPATH_RESUME_ON_FLOW_CHANGE")
        .unwrap_or_default()
        .to_lowercase();
    let msg = format!(
        "flow {flow_path:?} changed since this run was checkpointed (was {}…, now {}…)",
        &old[..old.len().min(23)],
        if now.is_empty() { "missing" } else { &now[..now.len().min(23)] },
    );
    match policy.as_str() {
        "allow" => Ok(()),
        "warn" => {
            eprintln!("  [checkpoint] WARNING: {msg} — resuming anyway");
            Ok(())
        }
        _ => cerr(format!(
            "{msg}. Refusing to resume against a changed flow — set \
             PRISMPATH_RESUME_ON_FLOW_CHANGE=warn (proceed) or =allow (silent) to override."
        )),
    }
}

// ------------------------------------------------------------------- run_durable / resume

/// Run a flow while persisting a checkpoint at every step (best-effort: a failing save disables
/// itself with a warning rather than break the run).
pub fn run_durable<F>(
    flow_path: &str,
    agent: F,
    checkpoint_path: &str,
    type_gate: bool,
    opts: RunOpts,
) -> Result<RunResult, EngineError>
where
    F: FnMut(&str, &str, &RunState) -> Result<V, String>,
{
    let text = std::fs::read_to_string(flow_path)
        .map_err(|e| EngineError::Unhandled(format!("cannot read flow {flow_path:?}: {e}")))?;
    let graph = parse(&text);
    let mut disabled = false;
    run_observed(&graph, agent, opts, |res, state, pending_node| {
        if disabled {
            return;
        }
        if let Err(e) = save_checkpoint(checkpoint_path, flow_path, res, state, pending_node, type_gate)
        {
            eprintln!("  [checkpoint] disabled for this run — {e}");
            disabled = true;
        }
    })
}

fn prior_steps(cp: &Value) -> Vec<Step> {
    cp.get("steps")
        .and_then(|s| s.as_array())
        .map(|arr| {
            arr.iter()
                .map(|s| Step {
                    node: s.get("node").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                    outcome: String::new(),
                    target: s.get("target").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                    used: s.get("used").and_then(|x| x.as_str()).unwrap_or("").to_string(),
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

fn push_transcript(state_v: &mut V, entry: V) {
    if let V::Obj(entries) = state_v {
        if let Some((_, V::List(items))) = entries.iter_mut().find(|(k, _)| k == "transcript") {
            items.push(entry);
            return;
        }
        entries.push(("transcript".to_string(), V::List(vec![entry])));
    }
}

/// Resume a run from its checkpoint. Mirrors the reference exactly:
/// * `choose` -> apply the human's edge after a `needs_human` suspension;
/// * `event`  -> deliver the named event after a `waiting` suspension;
/// * neither  -> re-enter at the pending node after a crash.
pub fn resume<F>(
    checkpoint_path: &str,
    agent: F,
    choose: Option<&str>,
    event: Option<&str>,
    max_steps: usize,
    write_back: bool,
) -> Result<RunResult, CheckpointError>
where
    F: FnMut(&str, &str, &RunState) -> Result<V, String>,
{
    let cp = load_checkpoint(checkpoint_path)?;
    check_flow_unchanged(&cp)?;
    let flow_path =
        cp.get("flow_path").and_then(|p| p.as_str()).ok_or(CheckpointError("no flow_path".into()))?;
    let text = std::fs::read_to_string(flow_path)
        .map_err(|e| CheckpointError(format!("cannot read flow {flow_path:?}: {e}")))?;
    let graph = parse(&text); // never written
    let mut state_v = V::from_json(cp.get("state").unwrap_or(&Value::Null));
    if !matches!(state_v, V::Obj(_)) {
        state_v = V::Obj(vec![]);
    }
    let stopped = cp.get("stopped").and_then(|s| s.as_str()).unwrap_or("");
    let type_gate = cp.get("type_gate").and_then(|t| t.as_bool()).unwrap_or(false);
    let choose: Option<String> = match choose {
        Some(c) => Some(c.to_string()),
        None => cp
            .get("decision")
            .and_then(|d| d.get("choose"))
            .and_then(|c| c.as_str())
            .map(|s| s.to_string()),
    };
    let seed_path: Vec<String> = cp
        .get("path")
        .and_then(|p| p.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    let pend = cp.get("pending_decision").cloned().unwrap_or(Value::Null);
    let pending_node = cp.get("pending_node").and_then(|p| p.as_str()).map(|s| s.to_string());

    let run_seeded = |start: String,
                      state_v: V,
                      seed_path: Vec<String>,
                      seed_steps: Vec<Step>,
                      mut agent: F|
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
        let res = run_observed(&graph, &mut agent, opts, |res, state, pending_node| {
            if write_back {
                let _ = save_checkpoint(checkpoint_path, &fp, res, state, pending_node, type_gate);
            }
        });
        res.map_err(|e| CheckpointError(e.to_string()))
    };

    if let Some(choose) = choose {
        let dnode = pend
            .get("node")
            .and_then(|n| n.as_str())
            .map(|s| s.to_string())
            .or(pending_node.clone())
            .ok_or(CheckpointError("checkpoint has no pending node".into()))?;
        let node = graph
            .nodes
            .get(&dnode)
            .ok_or(CheckpointError(format!("pending node {dnode:?} is not in the flow")))?;
        let valid: Vec<&String> = node.edges.iter().map(|(t, _)| t).collect();
        if !valid.iter().any(|t| **t == choose) {
            return cerr(format!(
                "choose {choose:?} is not an edge target of node {dnode:?}; valid: {valid:?}"
            ));
        }
        push_transcript(
            &mut state_v,
            V::Obj(vec![
                ("node".into(), V::Str(dnode.clone())),
                ("outcome".into(), V::Str(format!("[human chose -> {choose}]"))),
                ("decided_by".into(), V::Str("human".into())),
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
            .and_then(|n| n.as_str())
            .map(|s| s.to_string())
            .or(pending_node.clone())
            .ok_or(CheckpointError("checkpoint has no pending node".into()))?;
        let node = graph
            .nodes
            .get(&wnode)
            .ok_or(CheckpointError(format!("pending node {wnode:?} is not in the flow")))?;
        let target = node
            .edges
            .iter()
            .find(|(_, c)| is_event(c) && event_name(c) == event)
            .map(|(t, _)| t.clone());
        let Some(target) = target else {
            let avail: Vec<String> = node
                .edges
                .iter()
                .filter(|(_, c)| is_event(c))
                .map(|(_, c)| event_name(c))
                .collect();
            return cerr(format!("no edge for event {event:?} on {wnode:?}; awaiting: {avail:?}"));
        };
        push_transcript(
            &mut state_v,
            V::Obj(vec![
                ("node".into(), V::Str(wnode.clone())),
                ("outcome".into(), V::Str(format!("[event: {event}]"))),
                ("event".into(), V::Str(event.to_string())),
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
                .and_then(|c| c.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|c| c.get("target").and_then(|t| t.as_str()))
                        .map(|s| s.to_string())
                        .collect()
                })
                .unwrap_or_default();
            cerr(format!(
                "this run is suspended for a human decision — resume with choose=<edge> \
                 (candidates: {cands:?})"
            ))
        }
        "waiting" => {
            let awaiting = pend.get("awaiting").cloned().unwrap_or(Value::Null);
            cerr(format!(
                "this run is waiting for an event — resume with event=<name> (awaiting: {awaiting})"
            ))
        }
        "terminal" | "stuck" | "max_steps" => {
            cerr(format!("run already finished (stopped={stopped:?}); nothing to resume"))
        }
        _ => {
            let pending = pending_node
                .filter(|p| graph.nodes.contains_key(p))
                .ok_or(CheckpointError("checkpoint has no resumable pending node".into()))?;
            let prior = if seed_path.is_empty() {
                seed_path
            } else {
                seed_path[..seed_path.len() - 1].to_vec() // prior ends at pending (re-run)
            };
            let steps = prior_steps(&cp);
            run_seeded(pending, state_v, prior, steps, agent)
        }
    }
}

// -------------------------------------------------------- attestation manifests (C1/C4)

fn manifest_hash_of(m: &Value) -> String {
    let mut body = m.clone();
    if let Value::Object(o) = &mut body {
        o.remove("manifest_hash");
    }
    hex::encode(Sha256::digest(py_canonical_string(&body, true).as_bytes()))
}

/// C1: the provable chain of custody that travels with a Merkle root. `created` is injected
/// (Python defaults to now; explicit here for determinism) — pass an ISO-8601 UTC string.
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
    let mut m = serde_json::json!({
        "root": root_hex,
        "label": label,
        "created": created,
        "policy_hash": policy_hash,
        "gate_id": gate_id,
        "knowledge_base_hash": knowledge_base_hash,
        "ingestion_hashes": ingestion_hashes,
    });
    let h = manifest_hash_of(&m);
    m["manifest_hash"] = Value::String(h);
    m
}

/// Attest a HUMAN OVERRIDE of a prior decision as a SUPERSEDING commit (the prior manifest stays
/// immutable; provenance bindings carry forward).
pub fn override_manifest(
    prior: &Value,
    overrider_id: &str,
    rationale: &str,
    new_root_hex: &str,
    new_label: Option<&str>,
    created: &str,
) -> Value {
    let label = new_label.map(|l| l.to_string()).unwrap_or_else(|| {
        format!("override:{}", prior.get("label").and_then(|l| l.as_str()).unwrap_or(""))
    });
    let mut m = serde_json::json!({
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
    let h = manifest_hash_of(&m);
    m["manifest_hash"] = Value::String(h);
    m
}

/// Recompute the content-address over every bound field; any tampering flips this to false.
pub fn verify_manifest(m: &Value) -> bool {
    m.get("manifest_hash").and_then(|h| h.as_str()) == Some(manifest_hash_of(m).as_str())
}

/// C4: HMAC a (possibly low-entropy) unit hash with an in-enclave secret so a leaked hash can't
/// be confirmed by guessing the content.
pub fn salt_leaf(leaf_hex: &str, secret: &str) -> Result<String, CheckpointError> {
    use hmac::{Hmac, Mac};
    let leaf = hex::decode(leaf_hex).map_err(|e| CheckpointError(format!("bad leaf hex: {e}")))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|e| CheckpointError(e.to_string()))?;
    mac.update(&leaf);
    Ok(hex::encode(mac.finalize().into_bytes()))
}
