// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The PrismPath kernel execution engine.

use std::collections::HashMap;

use crate::causes;
use crate::contract::{derive_contract, py_str_repr, validate_output, ContractError};
use crate::condition::{
    error_expr, eval_condition, event_name, is_error, is_event, is_semantic, py_truthy,
};
use crate::parser::Graph;
use crate::value::Value;

pub fn reachable(graph: &Graph) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    let mut stack = vec![graph.start.clone()];
    while let Some(current_node) = stack.pop() {
        if seen.contains(&current_node) || !graph.nodes.contains_key(&current_node) {
            continue;
        }
        seen.push(current_node.clone());
        for (target, _) in &graph.nodes[&current_node].edges {
            if graph.nodes.contains_key(target) && !seen.contains(target) {
                stack.push(target.clone());
            }
        }
    }
    seen
}

/// What a worker reports when it fails: the error kind, which the error tier exposes to a flow as
/// `error_type` (the reference's exception class name, `type(exc).__name__`), and the message
/// (`error_message`). A plain message converts into one whose kind is `Error`; a worker that wants a flow
/// to route on its kind builds `WorkerError::new("ValueError", "bad input")`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerError {
    pub kind: String,
    pub message: String,
}

impl WorkerError {
    /// The kind a plain message carries.
    pub const PLAIN_KIND: &'static str = "Error";

    pub fn new(kind: impl Into<String>, message: impl Into<String>) -> WorkerError {
        WorkerError { kind: kind.into(), message: message.into() }
    }
}

impl From<String> for WorkerError {
    fn from(message: String) -> WorkerError {
        WorkerError { kind: WorkerError::PLAIN_KIND.to_string(), message }
    }
}

impl From<&str> for WorkerError {
    fn from(message: &str) -> WorkerError {
        WorkerError::from(message.to_string())
    }
}

impl std::fmt::Display for WorkerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.message)
    }
}

impl std::error::Error for WorkerError {}

#[derive(Debug, Clone)]
pub struct Violation {
    pub node: String,
    pub target: String,
    pub condition: String,
}

/// Every semantic edge on a reachable node: empty means the flow is in the portable subset.
pub fn portability_violations(graph: &Graph) -> Vec<Violation> {
    let mut names = reachable(graph);
    names.sort();
    let mut out = Vec::new();
    for name in names {
        let Some(flow_node) = graph.nodes.get(&name) else { continue };
        for (target, cond) in &flow_node.edges {
            if is_semantic(cond) {
                out.push(Violation { node: name.clone(), target: target.clone(), condition: cond.clone() });
            }
        }
    }
    out
}

/// Python str() for the JSON value kinds a worker can return.
pub fn py_str(val: &Value) -> String {
    match val {
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Null => "None".to_string(),
        Value::Str(str_val) => str_val.clone(),
        Value::List(arr_val) => {
            let inner: Vec<String> = arr_val.iter().map(py_repr).collect();
            format!("[{}]", inner.join(", "))
        }
        Value::Obj(obj_val) => {
            let inner: Vec<String> =
                obj_val.iter().map(|(key, item)| format!("'{key}': {}", py_repr(item))).collect();
            format!("{{{}}}", inner.join(", "))
        }
        Value::Num(num_val) => js_number_string(*num_val),
        Value::Ellipsis => "Ellipsis".to_string(),
    }
}

fn py_repr(val: &Value) -> String {
    match val {
        Value::Str(str_val) => py_str_repr(str_val),
        _ => py_str(val),
    }
}

/// JS String(number): no trailing ".0" on integral values; exponent form only past 1e21.
fn js_number_string(num_val: f64) -> String {
    if num_val.is_nan() {
        return "NaN".to_string();
    }
    if num_val.is_infinite() {
        return if num_val > 0.0 { "Infinity" } else { "-Infinity" }.to_string();
    }
    if num_val.fract() == 0.0 && num_val.abs() < 1e21 {
        return format!("{}", num_val as i128);
    }
    if num_val.abs() >= 1e21 {
        let str_val = format!("{num_val:e}");
        return if str_val.contains("e-") { str_val } else { str_val.replace('e', "e+") };
    }
    format!("{num_val}")
}

/// str(outcome.get("text", "")) + the fields dict: a PRESENT-but-null text is "None",
/// an absent one is "".
fn normalize(outcome: &Value) -> (String, Vec<(String, Value)>) {
    if let Value::Obj(entries) = outcome {
        let text = match Value::obj_get(entries, "text") {
            Some(text_val) => py_str(text_val),
            None => String::new(),
        };
        return (text, entries.clone());
    }
    let text = py_str(outcome);
    (text.clone(), vec![("text".to_string(), Value::Str(text))])
}

/// First matching deterministic edge, document order. An unsafe/unparseable predicate is
/// non-matching, never a crash.
pub fn first_deterministic<'a>(
    edges: &'a [(String, String)],
    ctx: &HashMap<String, Value>,
) -> Option<(&'a str, &'a str)> {
    for (target, cond) in edges {
        if !crate::condition::is_deterministic(cond) {
            continue;
        }
        if let Ok(true) = eval_condition(cond, ctx) {
            return Some((target, cond));
        }
    }
    None
}

/// The resume target for a delivered event ('__timeout__' for a timeout). None if the node has
/// no such edge.
pub fn event_target<'a>(graph: &'a Graph, node: &str, event: &str) -> Option<&'a str> {
    let flow_node = graph.nodes.get(node)?;
    for (target, cond) in &flow_node.edges {
        if is_event(cond) && event_name(cond) == event {
            return Some(target);
        }
    }
    None
}

#[derive(Debug, Clone, Default)]
pub struct RunState {
    pub visits: HashMap<String, i64>,
    pub transcript: Vec<Value>,
    pub errors: HashMap<String, i64>,
    pub outcomes: HashMap<String, Vec<(String, Value)>>,
    /// What the state bound dropped, per list (`transcript`, `path`, `steps`): the reference's
    /// `_state_dropped`, a deterministic count in place of a model written summary.
    pub dropped: HashMap<String, i64>,
    /// The error edge guards that could not be evaluated (SPEC section 5.3), each `{node, guard, error}` as the
    /// reference records them in `_guard_errors`: a guard that cannot be evaluated does not match, and a
    /// handler that never fires is visible here. Entries a resumed state brought are kept as they came.
    pub guard_errors: Vec<Value>,
    /// Host-supplied state fields the engine itself never reads, carried through untouched.
    pub extra: HashMap<String, Value>,
}

impl RunState {
    /// Ingest a host-provided initial state (the state option): visits and transcript are
    /// the engine's own fields and are adopted; everything else rides along in extra.
    pub fn from_v(val: &Value) -> RunState {
        let mut state = RunState::default();
        if let Value::Obj(entries) = val {
            for (key, item_val) in entries {
                match (key.as_str(), item_val) {
                    ("visits", Value::Obj(visit_map)) => {
                        for (node_name, visit_count) in visit_map {
                            if let Some(num_count) = as_num(visit_count) {
                                state.visits.insert(node_name.clone(), num_count as i64);
                            }
                        }
                    }
                    ("transcript", Value::List(items)) => state.transcript = items.clone(),
                    ("_errors", Value::Obj(err_map)) => {
                        for (node_name, err_count) in err_map {
                            if let Some(num_count) = as_num(err_count) {
                                state.errors.insert(node_name.clone(), num_count as i64);
                            }
                        }
                    }
                    ("_guard_errors", Value::List(items)) => state.guard_errors = items.clone(),
                    ("_state_dropped", Value::Obj(drop_map)) => {
                        for (list_name, drop_count) in drop_map {
                            if let Some(num_count) = as_num(drop_count) {
                                state.dropped.insert(list_name.clone(), num_count as i64);
                            }
                        }
                    }
                    ("_outcomes", Value::Obj(out_map)) => {
                        for (node_name, out_val) in out_map {
                            if let Value::Obj(out_entries) = out_val {
                                state.outcomes.insert(node_name.clone(), out_entries.clone());
                            }
                        }
                    }
                    _ => {
                        state.extra.insert(key.clone(), item_val.clone());
                    }
                }
            }
        }
        state
    }
}

fn as_num(val: &Value) -> Option<f64> {
    match val {
        Value::Num(num_val) => Some(*num_val),
        Value::Bool(bool_val) => Some(if *bool_val { 1.0 } else { 0.0 }),
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub struct Pending {
    pub node: String,
    pub wait: bool,
    pub reason: Option<String>,
    pub awaiting: Vec<String>,
    pub timeout_s: Option<Value>,
    pub candidates: Vec<(String, String)>,
    pub spawn: Option<Value>,
    pub would_pick: Option<String>,
    pub scored_candidates: Option<Vec<(String, String, f64)>>,
    /// Set iff the run stopped as `contract_violation`: the `type:` problems the type gate found.
    pub violations: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct Step {
    pub node: String,
    pub outcome: String,
    pub target: String,
    pub used: String,
    pub cond: Option<String>,
    pub score: Option<f64>,
    pub margin: Option<f64>,
    pub sims: Option<HashMap<String, f64>>,
    pub locked: Option<bool>,
    /// The worker's error kind, set on the step an error edge took (the reference's `info["error_type"]`).
    pub error_type: Option<String>,
    /// How many unevaluable error guards the state holds for this node, when there are any (the reference's
    /// `info["guard_errors"]`; the count is over the whole state, so a resumed run counts the earlier ones).
    pub guard_errors: Option<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct RunResult {
    pub path: Vec<String>,
    pub steps: Vec<Step>,
    pub stopped: String,
    pub pending: Option<Pending>,
    pub state: RunState,
    /// Why the run refused, parked or escalated, as a registry code (`causes`); `CAUSE_NONE` for a
    /// clean outcome. The two `needs_human` sites carry different causes.
    pub cause: u8,
}

#[derive(Debug, Clone)]
pub enum EngineError {
    /// A reachable semantic edge: the flow needs the embedding/LLM tier and this kernel REFUSES
    /// to guess at it (mirroring the reference's up-front rejection).
    NotPortable(Violation),
    /// A failure that is not a worker's (an unreadable flow file, a locked route with no edges).
    Unhandled(String),
    /// The worker raised and no error edge on the node matched: its error propagates, kind and message as
    /// the worker gave them (the reference re-raises the exception itself).
    Worker(WorkerError),
    /// A route led to a node the document does not define (an edge target, or the start). The reference raises a
    /// bare `KeyError` on the node's name here, and the JS kernel crashes; this is the Rust spelling, and
    /// `reference_exception` maps it to the `KeyError`. A run that spends its last step on the route stops
    /// as `max_steps` first, with the undefined node last in its path, in both engines. `validate` reports such a
    /// target as an `undefined-target` error before a run.
    MissingNode(String),
    /// A semantic condition is not covered by the lockfile.
    LockMissing(String),
    /// The flow breaks its own field definitions (SPEC section 4.5), so there is no policy to run.
    InvalidFlow(String),
    /// The type gate was asked for and the worker contract cannot be derived exactly.
    Contract(ContractError),
    /// A `@state_bound(transcript=N)` whose N is not a positive integer: a bound that silently failed to
    /// bind would be the worst outcome, so the run does not start.
    BadStateBound(String),
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineError::NotPortable(violation) => write!(
                formatter,
                "flow is not portable: semantic edge [{}] -> {} ({:?}) needs the embedding/LLM \
                 tier - run it on the Python engine, or rewrite the edge as a `when` predicate",
                violation.node, violation.target, violation.condition
            ),
            EngineError::Unhandled(msg) => write!(formatter, "{msg}"),
            EngineError::Worker(error) => write!(formatter, "{}", error.message),
            EngineError::MissingNode(node_name) => write!(formatter, "flow routes to undefined node {node_name:?}"),
            EngineError::LockMissing(cond) => write!(
                formatter,
                "condition not in lock: {cond:?} - the flow changed; re-run `prismpath lock`"
            ),
            EngineError::InvalidFlow(reason) => write!(formatter, "{reason}"),
            EngineError::Contract(error) => write!(formatter, "the worker contract cannot be derived: {error}"),
            EngineError::BadStateBound(reason) => write!(formatter, "{reason}"),
        }
    }
}
impl std::error::Error for EngineError {}

impl EngineError {
    /// The exception the reference engine raises where this engine returns this error, as its class name and
    /// `str()`; `None` where the reference has no counterpart at the same point (a flow it refuses at parse,
    /// a semantic edge it would hand to a live router, a contract it cannot derive).
    ///
    /// A worker's own error propagates as itself (its kind and message); a route into a node the flow does
    /// not define is the reference's bare `KeyError` on the node name, whose `str()` is the name's repr; a
    /// condition missing from the lock is a `KeyError` too; a malformed `@state_bound` is a `ValueError`.
    pub fn reference_exception(&self) -> Option<(String, String)> {
        match self {
            EngineError::Worker(error) => Some((error.kind.clone(), error.message.clone())),
            EngineError::MissingNode(node_name) => Some(("KeyError".to_string(), py_str_repr(node_name))),
            EngineError::LockMissing(cond) => Some((
                "KeyError".to_string(),
                py_str_repr(&format!("condition not in lock: {} - the flow changed; re-run `prismpath lock`", py_str_repr(cond))),
            )),
            EngineError::BadStateBound(reason) => Some(("ValueError".to_string(), reason.clone())),
            EngineError::Unhandled(_) | EngineError::NotPortable(_) | EngineError::InvalidFlow(_) | EngineError::Contract(_) => None,
        }
    }
}

pub struct RunOpts {
    pub max_steps: usize,
    pub start: Option<String>,
    pub state: Option<Value>,
    pub human_floor: Option<f64>,
    /// Validate each worker's output against the contract derived from the node's `when` edges
    /// (`contract::derive_contract`): a field of the wrong TYPE stops the run as `contract_violation`
    /// (cause 37) before routing acts on it.
    pub type_gate: bool,
    /// Keep only the last N entries of the growing history lists, overriding the flow's
    /// `@state_bound(transcript=N)`. Zero is no bound, as in the reference, and a negative number is refused
    /// before the run starts (`EngineError::BadStateBound`), as a negative annotation is.
    pub max_transcript: Option<i64>,
    /// Carried onto every routing decision record.
    pub run_id: Option<String>,
    pub seed_path: Vec<String>,
    pub seed_steps: Vec<Step>,
}

impl Default for RunOpts {
    fn default() -> Self {
        RunOpts {
            max_steps: 25,
            start: None,
            state: None,
            human_floor: None,
            type_gate: false,
            max_transcript: None,
            run_id: None,
            seed_path: Vec::new(),
            seed_steps: Vec::new(),
        }
    }
}

// P1: locked routing

#[derive(Debug, Clone)]
pub struct CentroidPin {
    pub vec: Vec<f32>,
    pub n: usize,
}

#[derive(Debug, Clone)]
pub struct Lock {
    pub conditions: HashMap<String, Vec<f32>>,
    pub centroids: Option<HashMap<String, CentroidPin>>,
    pub dim: usize,
}

impl Lock {
    pub fn condition_vec(&self, condition: &str) -> Option<&[f32]> {
        self.centroids
            .as_ref()
            .and_then(|centroid_map| centroid_map.get(condition).map(|pin| pin.vec.as_slice()))
            .or_else(|| self.conditions.get(condition).map(|v_slice| v_slice.as_slice()))
    }

    pub fn from_json(json_val: &serde_json::Value) -> Result<Lock, String> {
        let obj = json_val.as_object().ok_or("lock must be an object")?;
        let dim = obj
            .get("embedder")
            .and_then(|embedder_obj| embedder_obj.get("dim"))
            .and_then(|dim_val| dim_val.as_u64())
            .ok_or("lock.embedder.dim is required")? as usize;

        let conds_obj = obj
            .get("conditions")
            .and_then(|c_obj| c_obj.as_object())
            .ok_or("lock.conditions is required")?;
        let mut conditions = HashMap::new();
        for (key, val) in conds_obj {
            let b64 = val.as_str().ok_or_else(|| format!("condition {key:?}: expected base64 string"))?;
            conditions.insert(key.clone(), decode_b64_f32(b64)?);
        }

        let centroids = if let Some(cen_val) = obj.get("centroids") {
            let cen_obj = cen_val.as_object().ok_or("lock.centroids must be an object")?;
            let mut map = HashMap::new();
            for (key, val) in cen_obj {
                let pin_obj = val.as_object().ok_or_else(|| format!("centroid {key:?}: expected object"))?;
                let vec_b64 = pin_obj
                    .get("vec")
                    .and_then(|v_str| v_str.as_str())
                    .ok_or_else(|| format!("centroid {key:?}: missing vec"))?;
                let count_n = pin_obj.get("n").and_then(|n_val| n_val.as_u64()).unwrap_or(1) as usize;
                map.insert(key.clone(), CentroidPin { vec: decode_b64_f32(vec_b64)?, n: count_n });
            }
            Some(map)
        } else {
            None
        };

        Ok(Lock { conditions, centroids, dim })
    }
}

pub fn decode_b64_f32(b64: &str) -> Result<Vec<f32>, String> {
    const LUT: [u8; 256] = {
        let mut table = [255u8; 256];
        let mut idx = 0u8;
        while idx < 26 { table[(b'A' + idx) as usize] = idx; idx += 1; }
        idx = 0;
        while idx < 26 { table[(b'a' + idx) as usize] = 26 + idx; idx += 1; }
        idx = 0;
        while idx < 10 { table[(b'0' + idx) as usize] = 52 + idx; idx += 1; }
        table[b'+' as usize] = 62;
        table[b'/' as usize] = 63;
        table
    };
    let input = b64.as_bytes();
    let len = input.len();
    // A length that is not a whole number of quartets has no valid decode, and one to three
    // characters of padding would make `len / 4 * 3 - pad` underflow below before the decoded
    // length is ever checked. Refuse the input instead of computing a bogus capacity.
    if len % 4 != 0 {
        return Err(format!("base64 string of {len} chars is not a multiple of 4"));
    }
    let pad = if len >= 2 && input[len - 1] == b'=' {
        if input[len - 2] == b'=' { 2 } else { 1 }
    } else {
        0
    };
    let out_len = len / 4 * 3 - pad;
    let mut bytes = Vec::with_capacity(out_len);
    let mut pos = 0;
    while pos + 3 < len {
        let (val_a, val_b, val_c, val_d) = (LUT[input[pos] as usize], LUT[input[pos + 1] as usize],
                             LUT[input[pos + 2] as usize], LUT[input[pos + 3] as usize]);
        bytes.push((val_a << 2) | (val_b >> 4));
        if bytes.len() < out_len { bytes.push((val_b << 4) | (val_c >> 2)); }
        if bytes.len() < out_len { bytes.push((val_c << 6) | val_d); }
        pos += 4;
    }
    if bytes.len() % 4 != 0 {
        return Err(format!("base64 decoded to {} bytes, not a multiple of 4 (f32)", bytes.len()));
    }
    let floats: Vec<f32> = bytes
        .chunks_exact(4)
        .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect();
    Ok(floats)
}

fn cosine_sim(left: &[f32], right: &[f32]) -> f64 {
    left.iter().zip(right).map(|(x_val, y_val)| (*x_val as f64) * (*y_val as f64)).sum()
}

/// One locked-routing decision. Public for consumers building suggestion layers.
#[derive(Debug, Clone)]
pub struct RouteDecision {
    pub target: String,
    pub score: f64,
    pub margin: f64,
    pub sims: HashMap<String, f64>,
}

/// Route one text against a node's semantic edges using the lock's pinned vectors.
pub fn locked_route(
    text: &str,
    sem_edges: &[(String, String)],
    lock: &Lock,
    embed: &mut dyn FnMut(&str) -> Vec<f32>,
) -> Result<RouteDecision, EngineError> {
    // Exported, so a consumer outside this engine can reach it with a node that has no semantic
    // edges. The in-engine caller guards on is_empty() first; without this the empty score list
    // would index order[0] out of bounds and panic inside a library call.
    if sem_edges.is_empty() {
        return Err(EngineError::Unhandled(
            "locked_route: no semantic edges to route".to_string(),
        ));
    }
    let query_vec = embed(text);
    let mut scores = Vec::with_capacity(sem_edges.len());
    let mut sims_map = HashMap::new();
    for (target, cond) in sem_edges {
        let cond_vec = lock
            .condition_vec(cond)
            .ok_or_else(|| EngineError::LockMissing(cond.clone()))?;
        let sim = cosine_sim(&query_vec, cond_vec);
        scores.push(sim);
        sims_map.insert(target.clone(), sim);
    }
    let mut order: Vec<usize> = (0..scores.len()).collect();
    order.sort_by(|idx_a, idx_b| scores[*idx_b].partial_cmp(&scores[*idx_a]).unwrap_or(std::cmp::Ordering::Equal));
    let top1 = order[0];
    let margin = if order.len() > 1 { scores[order[0]] - scores[order[1]] } else { 1.0 };
    Ok(RouteDecision {
        target: sem_edges[top1].0.clone(),
        score: scores[top1],
        margin,
        sims: sims_map,
    })
}

fn js_truthy(val: &Value) -> bool {
    match val {
        Value::Null => false,
        Value::Bool(bool_val) => *bool_val,
        Value::Num(num_val) => *num_val != 0.0 && !num_val.is_nan(),
        Value::Str(str_val) => !str_val.is_empty(),
        Value::List(_) | Value::Obj(_) | Value::Ellipsis => true,
    }
}

/// One routing decision record, handed to the `on_decision` observer when the semantic tier routes (the
/// reference's Sprint 0 record, `kernel/engine.py`): what was routed, the candidates and their scores, and
/// what was chosen. The deterministic tier and every stop leave no record.
#[derive(Debug, Clone)]
pub struct Decision {
    pub run_id: Option<String>,
    pub flow: String,
    pub node: String,
    pub outcome_text: String,
    /// The worker's fields other than `text`.
    pub outcome_fields: Vec<(String, Value)>,
    /// Each semantic edge as (target, condition, score).
    pub candidates: Vec<(String, String, Option<f64>)>,
    pub top1: Option<f64>,
    pub top2: Option<f64>,
    pub margin: Option<f64>,
    pub chosen: String,
    /// `embed`, what the reference records for a router that scores by embedding, which a locked route is.
    pub mechanism: String,
    pub escalated: bool,
    pub llm_choice: Option<String>,
    pub label: Option<String>,
    pub label_source: Option<String>,
}

impl Decision {
    /// The reference's record as a JSON object (`None` as null).
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "run_id": self.run_id,
            "flow": self.flow,
            "node": self.node,
            "outcome_text": self.outcome_text,
            "outcome_fields": self.outcome_fields.iter().map(|(key, val)| (key.clone(), val.to_json())).collect::<serde_json::Map<_, _>>(),
            "candidates": self.candidates.iter().map(|(target, condition, score)| serde_json::json!({
                "target": target, "condition": condition, "score": score})).collect::<Vec<_>>(),
            "top1": self.top1,
            "top2": self.top2,
            "margin": self.margin,
            "chosen": self.chosen,
            "mechanism": self.mechanism,
            "escalated": self.escalated,
            "llm_choice": self.llm_choice,
            "label": self.label,
            "label_source": self.label_source,
        })
    }
}

pub fn run<WorkErr, AgentFn>(graph: &Graph, agent: AgentFn, opts: RunOpts) -> Result<RunResult, EngineError>
where
    AgentFn: FnMut(&str, &str, &RunState) -> Result<Value, WorkErr>,
    WorkErr: Into<WorkerError>,
{
    run_observed(graph, agent, opts, |_, _, _| {})
}

pub fn run_observed<WorkErr, AgentFn, ObserverFn>(
    graph: &Graph,
    mut agent: AgentFn,
    opts: RunOpts,
    on_step: ObserverFn,
) -> Result<RunResult, EngineError>
where
    AgentFn: FnMut(&str, &str, &RunState) -> Result<Value, WorkErr>,
    WorkErr: Into<WorkerError>,
    ObserverFn: FnMut(&RunResult, &RunState, Option<&str>),
{
    run_core(graph, &mut agent, None, opts, on_step, &mut |_| {})
}

pub fn run_locked<WorkErr, AgentFn, EmbedFn>(
    graph: &Graph,
    agent: AgentFn,
    embed: EmbedFn,
    lock: &Lock,
    opts: RunOpts,
) -> Result<RunResult, EngineError>
where
    AgentFn: FnMut(&str, &str, &RunState) -> Result<Value, WorkErr>,
    WorkErr: Into<WorkerError>,
    EmbedFn: FnMut(&str) -> Vec<f32>,
{
    run_locked_observed(graph, agent, embed, lock, opts, |_, _, _| {})
}

pub fn run_locked_observed<WorkErr, AgentFn, EmbedFn, ObserverFn>(
    graph: &Graph,
    mut agent: AgentFn,
    mut embed: EmbedFn,
    lock: &Lock,
    opts: RunOpts,
    on_step: ObserverFn,
) -> Result<RunResult, EngineError>
where
    AgentFn: FnMut(&str, &str, &RunState) -> Result<Value, WorkErr>,
    WorkErr: Into<WorkerError>,
    EmbedFn: FnMut(&str) -> Vec<f32>,
    ObserverFn: FnMut(&RunResult, &RunState, Option<&str>),
{
    run_core(graph, &mut agent, Some((lock, &mut embed as &mut dyn FnMut(&str) -> Vec<f32>)), opts, on_step, &mut |_| {})
}

/// `run_locked_observed` with the routing decision observer: `on_decision` is called once for each node the
/// locked semantic tier routes, after the human floor has passed it and before the step is recorded.
pub fn run_locked_decided<WorkErr, AgentFn, EmbedFn, ObserverFn, DecisionFn>(
    graph: &Graph,
    mut agent: AgentFn,
    mut embed: EmbedFn,
    lock: &Lock,
    opts: RunOpts,
    on_step: ObserverFn,
    mut on_decision: DecisionFn,
) -> Result<RunResult, EngineError>
where
    AgentFn: FnMut(&str, &str, &RunState) -> Result<Value, WorkErr>,
    WorkErr: Into<WorkerError>,
    EmbedFn: FnMut(&str) -> Vec<f32>,
    ObserverFn: FnMut(&RunResult, &RunState, Option<&str>),
    DecisionFn: FnMut(&Decision),
{
    run_core(
        graph,
        &mut agent,
        Some((lock, &mut embed as &mut dyn FnMut(&str) -> Vec<f32>)),
        opts,
        on_step,
        &mut on_decision,
    )
}

pub(crate) type SemanticCtx<'a, 'b> = (&'a Lock, &'b mut dyn FnMut(&str) -> Vec<f32>);

fn error_tier(
    node: &str,
    failure: &WorkerError,
    edges: &[(String, String)],
    state: &mut RunState,
) -> Result<(Step, String), EngineError> {
    let count = {
        let err_count = state.errors.entry(node.to_string()).or_insert(0);
        *err_count = err_count.saturating_add(1);
        *err_count
    };
    let err_ctx: HashMap<String, Value> = [
        ("error".to_string(), Value::Bool(true)),
        ("error_type".to_string(), Value::Str(failure.kind.clone())),
        ("error_message".to_string(), Value::Str(failure.message.clone())),
        ("error_count".to_string(), Value::Num(count as f64)),
        ("visits".to_string(), Value::Num(state.visits[node] as f64)),
    ]
    .into_iter()
    .collect();

    let mut err_target: Option<&str> = None;
    for (target, cond) in edges {
        if !is_error(cond) {
            continue;
        }
        let expr = error_expr(cond);
        if expr.is_empty() {
            err_target = Some(target);
            break;
        }
        match eval_condition(&expr, &err_ctx) {
            Ok(true) => {
                err_target = Some(target);
                break;
            }
            Ok(false) => {}
            // the guard itself cannot be evaluated: it does not match, as in the deterministic tier, but it is
            // recorded, so a handler that never fires is visible in the run's state
            Err(guard_error) => state.guard_errors.push(Value::Obj(vec![
                ("node".to_string(), Value::Str(node.to_string())),
                ("guard".to_string(), Value::Str(expr.clone())),
                ("error".to_string(), Value::Str(guard_error.0)),
            ])),
        }
    }
    let Some(etarget) = err_target else {
        return Err(EngineError::Worker(failure.clone()));
    };
    let err_text = format!("[error: {}: {}]", failure.kind, failure.message);
    state.transcript.push(Value::Obj(vec![
        ("node".to_string(), Value::Str(node.to_string())),
        ("outcome".to_string(), Value::Str(err_text.clone())),
        ("error".to_string(), Value::Bool(true)),
    ]));
    let guard_errors = state
        .guard_errors
        .iter()
        .filter(|entry| matches!(entry, Value::Obj(fields) if matches!(Value::obj_get(fields, "node"), Some(Value::Str(name)) if name == node)))
        .count();
    let step = Step {
        node: node.to_string(),
        outcome: err_text,
        target: etarget.to_string(),
        used: "error".to_string(),
        cond: None,
        score: None,
        margin: None,
        sims: None,
        locked: None,
        error_type: Some(failure.kind.clone()),
        guard_errors: Some(guard_errors).filter(|count| *count > 0),
    };
    Ok((step, etarget.to_string()))
}

fn human_handoff(
    node: &str,
    text: &str,
    fields: &[(String, Value)],
    edges: &[(String, String)],
) -> Option<Pending> {
    if Value::obj_get(fields, "needs_human").is_some_and(py_truthy) {
        let reason = match Value::obj_get(fields, "reason") {
            Some(reason_val) if js_truthy(reason_val) => py_str(reason_val),
            _ => text.to_string(),
        };
        Some(Pending {
            node: node.to_string(),
            wait: false,
            reason: Some(reason),
            awaiting: Vec::new(),
            timeout_s: None,
            candidates: edges.to_vec(),
            spawn: None,
            would_pick: None,
            scored_candidates: None,
            violations: None,
        })
    } else {
        None
    }
}

fn wait_suspend(
    node: &str,
    fields: &[(String, Value)],
    edges: &[(String, String)],
) -> Option<Pending> {
    let spawn = Value::obj_get(fields, "spawn").filter(|val| !matches!(val, Value::Null));
    if Value::obj_get(fields, "wait").is_some_and(py_truthy) || spawn.is_some() {
        let events: Vec<&(String, String)> =
            edges.iter().filter(|(_, cond)| is_event(cond)).collect();
        Some(Pending {
            node: node.to_string(),
            wait: true,
            reason: None,
            awaiting: events.iter().map(|(_, cond)| event_name(cond)).collect(),
            timeout_s: Value::obj_get(fields, "timeout_s").cloned(),
            candidates: events.iter().map(|item| (*item).clone()).collect(),
            spawn: spawn.cloned(),
            would_pick: None,
            scored_candidates: None,
            violations: None,
        })
    } else {
        None
    }
}

enum RouteOutcome {
    Step(Step, String),
    Stuck,
    HumanFloor(Pending),
}

/// What routing needs besides the node's outcome: the floor below which a semantic route goes to a human,
/// and where a routing decision record goes.
struct RouteEnv<'a> {
    human_floor: Option<f64>,
    flow: &'a str,
    run_id: Option<&'a str>,
    on_decision: &'a mut dyn FnMut(&Decision),
}

fn route_once(
    node: &str,
    text: &str,
    fields: &[(String, Value)],
    edges: &[(String, String)],
    state: &RunState,
    semantic_ctx: &mut Option<SemanticCtx<'_, '_>>,
    env: &mut RouteEnv<'_>,
) -> Result<RouteOutcome, EngineError> {
    let mut ctx: HashMap<String, Value> = fields.iter().cloned().collect();
    ctx.insert("visits".to_string(), Value::Num(state.visits[node] as f64));

    let mut target: Option<String> = None;
    let mut step_used = String::new();
    let mut step_cond: Option<String> = None;
    let mut step_score: Option<f64> = None;
    let mut step_margin: Option<f64> = None;
    let mut step_sims: Option<HashMap<String, f64>> = None;
    let mut step_locked: Option<bool> = None;

    if let Some((dt, dc)) = first_deterministic(edges, &ctx) {
        target = Some(dt.to_string());
        step_used = "deterministic".to_string();
        step_cond = Some(dc.to_string());
    }

    if target.is_none() {
        if let Some((lock, ref mut embed_fn)) = semantic_ctx {
            let sem: Vec<(String, String)> = edges.iter()
                .filter(|(_, cond)| is_semantic(cond))
                .cloned()
                .collect();
            if !sem.is_empty() {
                let decision = locked_route(text, &sem, lock, *embed_fn)?;
                if let Some(floor) = env.human_floor {
                    if decision.score < floor {
                        let pending = Pending {
                            node: node.to_string(),
                            wait: false,
                            reason: Some(format!(
                                "router confidence {:.3} < human_floor {floor}",
                                decision.score
                            )),
                            awaiting: Vec::new(),
                            timeout_s: None,
                            candidates: sem.clone(),
                            spawn: None,
                            would_pick: Some(decision.target.clone()),
                            scored_candidates: Some(
                                sem.iter()
                                    .map(|(tgt, cond)| {
                                        let sim_score = decision.sims.get(tgt).copied().unwrap_or(0.0);
                                        (tgt.clone(), cond.clone(), sim_score)
                                    })
                                    .collect(),
                            ),
                            violations: None,
                        };
                        return Ok(RouteOutcome::HumanFloor(pending));
                    }
                }
                let scored_edges = |edge_list: &[(String, String)]| -> Vec<(String, String, Option<f64>)> {
                    edge_list.iter().map(|(tgt, cond)| (tgt.clone(), cond.clone(), decision.sims.get(tgt).copied())).collect()
                };
                let mut scored: Vec<f64> = sem.iter().filter_map(|(tgt, _)| decision.sims.get(tgt).copied()).collect();
                scored.sort_by(|left, right| right.partial_cmp(left).unwrap_or(std::cmp::Ordering::Equal));
                (env.on_decision)(&Decision {
                    run_id: env.run_id.map(str::to_string),
                    flow: env.flow.to_string(),
                    node: node.to_string(),
                    outcome_text: text.to_string(),
                    outcome_fields: fields.iter().filter(|(key, _)| key != "text").cloned().collect(),
                    candidates: scored_edges(&sem),
                    top1: scored.first().copied(),
                    top2: scored.get(1).copied(),
                    margin: Some(decision.margin),
                    chosen: decision.target.clone(),
                    mechanism: "embed".to_string(),
                    escalated: false,
                    llm_choice: None,
                    label: None,
                    label_source: None,
                });
                target = Some(decision.target);
                // a locked route is the reference's embedding router told to score against pinned vectors, so
                // its step says `embed` and carries `locked`, as the info of the reference's step does
                step_used = "embed".to_string();
                step_score = Some(decision.score);
                step_margin = Some(decision.margin);
                step_sims = Some(decision.sims);
                step_locked = Some(true);
            }
        }
    }

    let Some(target_node) = target else {
        return Ok(RouteOutcome::Stuck);
    };

    let step = Step {
        node: node.to_string(),
        outcome: text.to_string(),
        target: target_node.clone(),
        used: step_used,
        cond: step_cond,
        score: step_score,
        margin: step_margin,
        sims: step_sims,
        locked: step_locked,
        error_type: None,
        guard_errors: None,
    };
    Ok(RouteOutcome::Step(step, target_node))
}

/// A decimal integer as Python's `int()` reads it from a string: optional sign, ASCII digits with single
/// underscores between them. Returns whether it is negative and its digits without leading zeros. (Python
/// also reads the digits of other scripts; those are refused here.)
pub(crate) fn py_int_text(raw: &str) -> Option<(bool, String)> {
    let trimmed = crate::condition::py_trim(raw);
    let (negative, body) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    if body.is_empty() || body.starts_with('_') || body.ends_with('_') || body.contains("__") {
        return None;
    }
    if !body.chars().all(|ch| ch.is_ascii_digit() || ch == '_') {
        return None;
    }
    let digits: String = body.chars().filter(|ch| *ch != '_').collect();
    let trimmed_digits = digits.trim_start_matches('0');
    Some((negative, if trimmed_digits.is_empty() { "0".to_string() } else { trimmed_digits.to_string() }))
}

/// The flow declared bound on persisted state: the first `@state_bound(transcript=N)` in document order (the
/// annotation is flow scoped, any node may carry it). N must be a positive integer, and a malformed one is
/// refused at run start rather than treated as inert. A bound too large to hold is a bound never reached.
fn flow_state_bound(graph: &Graph) -> Result<Option<usize>, EngineError> {
    for name in &graph.order {
        let Some(node) = graph.nodes.get(name) else { continue };
        let Some(args) = node.annotations.get("state_bound") else { continue };
        let raw: Option<&str> = args.get("transcript").and_then(|val| val.as_deref());
        let Some((negative, digits)) = raw.and_then(py_int_text) else {
            return Err(EngineError::BadStateBound(format!(
                "@state_bound(transcript={}) on node {}: transcript must be a positive integer",
                raw.map(py_str_repr).unwrap_or_else(|| "None".to_string()),
                py_str_repr(name)
            )));
        };
        if negative || digits == "0" {
            let shown = if negative && digits != "0" { format!("-{digits}") } else { digits };
            return Err(EngineError::BadStateBound(format!(
                "@state_bound(transcript={shown}) on node {}: must be >= 1",
                py_str_repr(name)
            )));
        }
        return Ok(Some(digits.parse::<usize>().unwrap_or(usize::MAX)));
    }
    Ok(None)
}

/// Slide a growing history list to its last `keep` entries, counting what was dropped in the state's
/// dropped map: a deterministic summary in place of a model written one, so the engine stays pure.
/// Routing never reads these lists.
fn bound_list<T>(items: &mut Vec<T>, key: &str, keep: Option<usize>, dropped: &mut HashMap<String, i64>) {
    let Some(keep) = keep else { return };
    if items.len() > keep {
        let excess = items.len() - keep;
        let count = dropped.entry(key.to_string()).or_insert(0);
        *count = count.saturating_add(excess as i64);
        items.drain(..excess);
    }
}

fn run_core<WorkErr, AgentFn, ObserverFn>(
    graph: &Graph,
    agent: &mut AgentFn,
    mut semantic_ctx: Option<SemanticCtx<'_, '_>>,
    opts: RunOpts,
    mut on_step: ObserverFn,
    on_decision: &mut dyn FnMut(&Decision),
) -> Result<RunResult, EngineError>
where
    AgentFn: FnMut(&str, &str, &RunState) -> Result<Value, WorkErr>,
    WorkErr: Into<WorkerError>,
    ObserverFn: FnMut(&RunResult, &RunState, Option<&str>),
{
    if let Some(reason) = graph.refusal() {
        return Err(EngineError::InvalidFlow(reason.to_string()));
    }
    let violations = portability_violations(graph);
    if !violations.is_empty() {
        if let Some((lock, _)) = semantic_ctx {
            for violation in &violations {
                if lock.condition_vec(&violation.condition).is_none() {
                    return Err(EngineError::LockMissing(violation.condition.clone()));
                }
            }
        } else {
            return Err(EngineError::NotPortable(
                violations.into_iter().next().expect("violations non-empty"),
            ));
        }
    }

    // The contract is derived before the run starts, as in the reference, so a flow whose contract cannot
    // be derived exactly does not begin.
    let contracts = if opts.type_gate { Some(derive_contract(graph).map_err(EngineError::Contract)?) } else { None };

    let mut current_node = opts.start.clone().unwrap_or_else(|| graph.start.clone());
    let mut state = match &opts.state {
        Some(val) => RunState::from_v(val),
        None => RunState::default(),
    };
    // The bound on persisted state: the kwarg when given, else the flow's `@state_bound`; zero is none.
    if let Some(keep) = opts.max_transcript.filter(|keep| *keep < 0) {
        return Err(EngineError::BadStateBound(format!("max_transcript={keep}: must be >= 0 (0 is no bound)")));
    }
    let bound = match opts.max_transcript {
        Some(keep) => Some(keep as usize),
        None => flow_state_bound(graph)?,
    }
    .filter(|keep| *keep > 0);
    // a resume may arrive with an oversized transcript, and the re-seeded history is bounded too, which is
    // what keeps a persisted payload flat across unlimited resumes
    bound_list(&mut state.transcript, "transcript", bound, &mut state.dropped);
    let mut seed_path = opts.seed_path.clone();
    let mut seed_steps = opts.seed_steps.clone();
    bound_list(&mut seed_path, "path", bound, &mut state.dropped);
    bound_list(&mut seed_steps, "steps", bound, &mut state.dropped);
    let mut res = RunResult {
        path: {
            seed_path.push(current_node.clone());
            seed_path
        },
        steps: seed_steps,
        ..Default::default()
    };

    for _step_idx in 0..opts.max_steps {
        let flow_node = graph
            .nodes
            .get(&current_node)
            .ok_or_else(|| EngineError::MissingNode(current_node.clone()))?
            .clone();

        if flow_node.edges.is_empty() {
            res.stopped = "terminal".to_string();
            on_step(&res, &state, None);
            break;
        }
        on_step(&res, &state, Some(&current_node));
        let visit_count = state.visits.entry(current_node.clone()).or_insert(0);
        *visit_count = visit_count.saturating_add(1);

        let outcome = match agent(&current_node, &flow_node.instruction, &state) {
            Ok(out) => out,
            Err(failure) => {
                let failure: WorkerError = failure.into();
                let (err_step, err_target) = error_tier(&current_node, &failure, &flow_node.edges, &mut state)?;
                bound_list(&mut state.transcript, "transcript", bound, &mut state.dropped);
                res.steps.push(err_step);
                current_node = err_target;
                res.path.push(current_node.clone());
                continue;
            }
        };

        let (text, fields) = normalize(&outcome);
        state.transcript.push(Value::Obj(vec![
            ("node".to_string(), Value::Str(current_node.clone())),
            ("outcome".to_string(), Value::Str(text.clone())),
        ]));
        bound_list(&mut state.transcript, "transcript", bound, &mut state.dropped);
        state.outcomes.insert(current_node.clone(), fields.clone());

        // Type gate (opt in): a worker output whose field TYPE contradicts what this node's `when` edges
        // read is a contract violation, and the run stops before routing acts on the malformed field.
        if let Some(contracts) = &contracts {
            let node_contract = contracts.get(&current_node).map(Vec::as_slice).unwrap_or(&[]);
            let violations: Vec<String> =
                validate_output(node_contract, &fields).into_iter().filter(|problem| problem.starts_with("type:")).collect();
            if !violations.is_empty() {
                res.stopped = "contract_violation".to_string();
                res.cause = causes::ROUTE_CONTRACT_VIOLATION;
                res.pending = Some(Pending {
                    node: current_node.clone(),
                    wait: false,
                    reason: Some("worker output violates the derived contract".to_string()),
                    awaiting: Vec::new(),
                    timeout_s: None,
                    candidates: Vec::new(),
                    spawn: None,
                    would_pick: None,
                    scored_candidates: None,
                    violations: Some(violations),
                });
                on_step(&res, &state, Some(&current_node));
                break;
            }
        }

        if let Some(pending) = human_handoff(&current_node, &text, &fields, &flow_node.edges) {
            res.stopped = "needs_human".to_string();
            res.cause = causes::ROUTE_NEEDS_HUMAN;
            res.pending = Some(pending);
            on_step(&res, &state, Some(&current_node));
            break;
        }

        if let Some(pending) = wait_suspend(&current_node, &fields, &flow_node.edges) {
            res.stopped = "waiting".to_string();
            res.pending = Some(pending);
            on_step(&res, &state, Some(&current_node));
            break;
        }

        match route_once(
            &current_node,
            &text,
            &fields,
            &flow_node.edges,
            &state,
            &mut semantic_ctx,
            &mut RouteEnv {
                human_floor: opts.human_floor,
                flow: &graph.name,
                run_id: opts.run_id.as_deref(),
                on_decision: &mut *on_decision,
            },
        )? {
            RouteOutcome::Step(step, target_node) => {
                res.steps.push(step);
                current_node = target_node;
                res.path.push(current_node.clone());
            }
            RouteOutcome::Stuck => {
                res.stopped = "stuck".to_string();
                res.cause = causes::ROUTE_STUCK;
                // the reference checkpoints a stuck run at the node it stuck on, as it does every other stop
                on_step(&res, &state, Some(&current_node));
                break;
            }
            RouteOutcome::HumanFloor(pending) => {
                res.stopped = "needs_human".to_string();
                res.cause = causes::ROUTE_BELOW_HUMAN_FLOOR;
                res.pending = Some(pending);
                on_step(&res, &state, Some(&current_node));
                break;
            }
        }
    }

    if res.stopped.is_empty() {
        res.stopped = "max_steps".to_string();
        res.cause = causes::ROUTE_MAX_STEPS;
    }
    res.state = state;
    Ok(res)
}
