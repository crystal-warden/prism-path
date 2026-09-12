// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The PrismPath kernel execution engine.

use std::collections::HashMap;

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
        Value::Str(str_val) => format!("'{str_val}'"),
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
}

#[derive(Debug, Clone, Default)]
pub struct RunResult {
    pub path: Vec<String>,
    pub steps: Vec<Step>,
    pub stopped: String,
    pub pending: Option<Pending>,
    pub state: RunState,
}

#[derive(Debug, Clone)]
pub enum EngineError {
    /// A reachable semantic edge: the flow needs the embedding/LLM tier and this kernel REFUSES
    /// to guess at it (mirroring the reference's up-front rejection).
    NotPortable(Violation),
    /// The agent raised and no error edge on the node matched: the error propagates.
    Unhandled(String),
    /// A route led to a node the document does not define. The JS kernel crashes here;
    /// an explicit error is the Rust spelling of that.
    MissingNode(String),
    /// A semantic condition is not covered by the lockfile.
    LockMissing(String),
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
            EngineError::MissingNode(node_name) => write!(formatter, "flow routes to undefined node {node_name:?}"),
            EngineError::LockMissing(cond) => write!(
                formatter,
                "condition not in lock: {cond:?} - the flow changed; re-run `prismpath lock`"
            ),
        }
    }
}
impl std::error::Error for EngineError {}

pub struct RunOpts {
    pub max_steps: usize,
    pub start: Option<String>,
    pub state: Option<Value>,
    pub human_floor: Option<f64>,
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

pub fn run<AgentFn>(graph: &Graph, agent: AgentFn, opts: RunOpts) -> Result<RunResult, EngineError>
where
    AgentFn: FnMut(&str, &str, &RunState) -> Result<Value, String>,
{
    run_observed(graph, agent, opts, |_, _, _| {})
}

pub fn run_observed<AgentFn, ObserverFn>(
    graph: &Graph,
    mut agent: AgentFn,
    opts: RunOpts,
    on_step: ObserverFn,
) -> Result<RunResult, EngineError>
where
    AgentFn: FnMut(&str, &str, &RunState) -> Result<Value, String>,
    ObserverFn: FnMut(&RunResult, &RunState, Option<&str>),
{
    run_core(graph, &mut agent, None, opts, on_step)
}

pub fn run_locked<AgentFn, EmbedFn>(
    graph: &Graph,
    agent: AgentFn,
    embed: EmbedFn,
    lock: &Lock,
    opts: RunOpts,
) -> Result<RunResult, EngineError>
where
    AgentFn: FnMut(&str, &str, &RunState) -> Result<Value, String>,
    EmbedFn: FnMut(&str) -> Vec<f32>,
{
    run_locked_observed(graph, agent, embed, lock, opts, |_, _, _| {})
}

pub fn run_locked_observed<AgentFn, EmbedFn, ObserverFn>(
    graph: &Graph,
    mut agent: AgentFn,
    mut embed: EmbedFn,
    lock: &Lock,
    opts: RunOpts,
    on_step: ObserverFn,
) -> Result<RunResult, EngineError>
where
    AgentFn: FnMut(&str, &str, &RunState) -> Result<Value, String>,
    EmbedFn: FnMut(&str) -> Vec<f32>,
    ObserverFn: FnMut(&RunResult, &RunState, Option<&str>),
{
    run_core(graph, &mut agent, Some((lock, &mut embed as &mut dyn FnMut(&str) -> Vec<f32>)), opts, on_step)
}

pub(crate) type SemanticCtx<'a, 'b> = (&'a Lock, &'b mut dyn FnMut(&str) -> Vec<f32>);

fn error_tier(
    node: &str,
    msg: &str,
    edges: &[(String, String)],
    state: &mut RunState,
) -> Result<(Step, String), EngineError> {
    let count = {
        let err_count = state.errors.entry(node.to_string()).or_insert(0);
        *err_count += 1;
        *err_count
    };
    let err_ctx: HashMap<String, Value> = [
        ("error".to_string(), Value::Bool(true)),
        ("error_type".to_string(), Value::Str("Error".to_string())),
        ("error_message".to_string(), Value::Str(msg.to_string())),
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
        if let Ok(true) = eval_condition(&expr, &err_ctx) {
            err_target = Some(target);
            break;
        }
    }
    let Some(etarget) = err_target else {
        return Err(EngineError::Unhandled(msg.to_string()));
    };
    let err_text = format!("[error: Error: {msg}]");
    state.transcript.push(Value::Obj(vec![
        ("node".to_string(), Value::Str(node.to_string())),
        ("outcome".to_string(), Value::Str(err_text.clone())),
        ("error".to_string(), Value::Bool(true)),
    ]));
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

fn route_once(
    node: &str,
    text: &str,
    fields: &[(String, Value)],
    edges: &[(String, String)],
    state: &RunState,
    semantic_ctx: &mut Option<SemanticCtx<'_, '_>>,
    human_floor: Option<f64>,
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
        step_used = format!("deterministic: {dc}");
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
                if let Some(floor) = human_floor {
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
                        };
                        return Ok(RouteOutcome::HumanFloor(pending));
                    }
                }
                target = Some(decision.target);
                step_used = "locked".to_string();
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
    };
    Ok(RouteOutcome::Step(step, target_node))
}

fn run_core<AgentFn, ObserverFn>(
    graph: &Graph,
    agent: &mut AgentFn,
    mut semantic_ctx: Option<SemanticCtx<'_, '_>>,
    opts: RunOpts,
    mut on_step: ObserverFn,
) -> Result<RunResult, EngineError>
where
    AgentFn: FnMut(&str, &str, &RunState) -> Result<Value, String>,
    ObserverFn: FnMut(&RunResult, &RunState, Option<&str>),
{
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

    let mut current_node = opts.start.clone().unwrap_or_else(|| graph.start.clone());
    let mut state = match &opts.state {
        Some(val) => RunState::from_v(val),
        None => RunState::default(),
    };
    let mut res = RunResult {
        path: {
            let mut path_vec = opts.seed_path.clone();
            path_vec.push(current_node.clone());
            path_vec
        },
        steps: opts.seed_steps.clone(),
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
        *state.visits.entry(current_node.clone()).or_insert(0) += 1;

        let outcome = match agent(&current_node, &flow_node.instruction, &state) {
            Ok(out) => out,
            Err(msg) => {
                let (err_step, err_target) = error_tier(&current_node, &msg, &flow_node.edges, &mut state)?;
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
        state.outcomes.insert(current_node.clone(), fields.clone());

        if let Some(pending) = human_handoff(&current_node, &text, &fields, &flow_node.edges) {
            res.stopped = "needs_human".to_string();
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
            opts.human_floor,
        )? {
            RouteOutcome::Step(step, target_node) => {
                res.steps.push(step);
                current_node = target_node;
                res.path.push(current_node.clone());
            }
            RouteOutcome::Stuck => {
                res.stopped = "stuck".to_string();
                on_step(&res, &state, None);
                break;
            }
            RouteOutcome::HumanFloor(pending) => {
                res.stopped = "needs_human".to_string();
                res.pending = Some(pending);
                on_step(&res, &state, Some(&current_node));
                break;
            }
        }
    }

    if res.stopped.is_empty() {
        res.stopped = "max_steps".to_string();
    }
    res.state = state;
    Ok(res)
}
