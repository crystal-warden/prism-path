// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! compose.rs: the MINIMAL in-process fan-out driver (feature `durable`).
//!
//! The engine stays pure: a worker returning a `spawn` spec suspends the run `waiting` with the
//! spec recorded in `pending` (exactly like the reference). This driver is the smallest harness
//! that completes the composition protocol IN PROCESS: run each child flow with the item seeded
//! as `state._item`, aggregate the child outcomes into the parent's state under `_children`, and
//! resume the parent by delivering the `all_done` join event through the durable checkpoint:
//! the same `resume(event=...)` path the reference composer uses.
//!
//! Join policies mirror the reference's single source of truth (`predicates.spawn_join_event` +
//! `composer._quorum_threshold`): `all_done` (default), `any`, and `quorum:k` / `quorum:frac`
//! (ceil of a fraction, clamped to [1, n]; a malformed X behaves like all_done rather than firing
//! early on a typo). A child counts as done iff it reached a terminal node; stragglers and failed
//! children are never cancelled: they are reported in the aggregation, and if the join threshold
//! is not met the driver refuses with the counts rather than guessing.
//!
//! Deliberately NOT here (the reference `composer.py`'s durable machinery, a named follow-on):
//! out-of-band child checkpoints under `<parent>.children/`, crash re-scan, retry caps, and
//! `done_when` gating.

use crate::durable::{resume, run_durable, CheckpointError};
use crate::{parse, run, RunOpts, RunResult, RunState, Value};
use serde_json::Value as JsonValue;

/// Outcome of one child run. A failed child records `stopped: "error"` and its message.
#[derive(Debug)]
pub struct ChildResult {
    pub item: JsonValue,
    pub path: Vec<String>,
    pub stopped: String,
}

/// `predicates.spawn_join_event`: the event NAME a join policy resolves to.
pub fn spawn_join_event(join: &str) -> &'static str {
    let join_str = join.trim().to_lowercase();
    if join_str.starts_with("quorum") {
        "quorum"
    } else if join_str == "any" {
        "any"
    } else {
        "all_done"
    }
}

/// `composer._quorum_threshold`: int count or fraction-of-n (ceil), clamped to [1, n];
/// malformed -> n (behaves like all_done rather than firing early on a typo).
pub fn quorum_threshold(join: &str, total_count: usize) -> usize {
    let spec = join.split_once(':').map(|(_, spec_str)| spec_str.trim()).unwrap_or("");
    let Ok(parsed_val) = spec.parse::<f64>() else { return total_count };
    let threshold = if parsed_val > 0.0 && parsed_val < 1.0 { (parsed_val * total_count as f64).ceil() as usize } else { parsed_val as usize };
    threshold.clamp(1, total_count.max(1))
}

/// `composer._join_event`: given each child's done-ness, the join event to deliver, or None.
pub fn join_event(join: &str, done_flags: &[bool]) -> Option<&'static str> {
    if done_flags.is_empty() {
        return None;
    }
    let count_done = done_flags.iter().filter(|is_done| **is_done).count();
    match spawn_join_event(join) {
        "any" => (count_done >= 1).then_some("any"),
        "quorum" => (count_done >= quorum_threshold(join, done_flags.len())).then_some("quorum"),
        _ => done_flags.iter().all(|is_done| *is_done).then_some("all_done"),
    }
}

/// Run `parent_flow` to its spawn point, fan out the children in process, deliver `all_done`.
/// `child_flow_of` resolves the spec's `flow` name to a flow TEXT (the caller owns file layout).
pub fn run_fanout<AgentFn, FactoryFn, ResolverFn>(
    parent_flow_path: &str,
    checkpoint_path: &str,
    parent_agent: AgentFn,
    mut child_agent_factory: FactoryFn,
    mut child_flow_of: ResolverFn,
) -> Result<(RunResult, Vec<ChildResult>), CheckpointError>
where
    AgentFn: FnMut(&str, &str, &RunState) -> Result<Value, String>,
    FactoryFn: FnMut() -> Box<dyn FnMut(&str, &str, &RunState) -> Result<Value, String>>,
    ResolverFn: FnMut(&str) -> Result<String, String>,
{
    let first = run_durable(parent_flow_path, parent_agent, checkpoint_path, false, RunOpts::default())
        .map_err(|err| CheckpointError(err.to_string()))?;
    if first.stopped != "waiting" {
        return Ok((first, Vec::new()));
    }
    let Some(spawn) = first.pending.as_ref().and_then(|pending_spec| pending_spec.spawn.as_ref()) else {
        return Err(CheckpointError(
            "parent is waiting but recorded no spawn spec - deliver its event externally".into(),
        ));
    };
    let spec = spawn.to_json();
    let flow_name = spec
        .get("flow")
        .and_then(|flow_val| flow_val.as_str())
        .ok_or(CheckpointError("spawn spec has no `flow`".into()))?;
    let items: Vec<JsonValue> = spec
        .get("items")
        .and_then(|items_val| items_val.as_array())
        .cloned()
        .unwrap_or_default();
    let join = spec.get("join").and_then(|join_val| join_val.as_str()).unwrap_or("all_done").to_string();
    let child_text = child_flow_of(flow_name).map_err(CheckpointError)?;
    let child_graph = parse(&child_text);

    let mut children = Vec::new();
    for item in items {
        let state = Value::Obj(vec![("_item".to_string(), Value::from_json(&item))]);
        let mut agent = child_agent_factory();
        match run(&child_graph, &mut *agent, RunOpts { state: Some(state), ..Default::default() }) {
            Ok(res) => children.push(ChildResult { item, path: res.path, stopped: res.stopped }),
            Err(err) => children.push(ChildResult {
                item,
                path: Vec::new(),
                stopped: format!("error: {err}"),
            }),
        }
    }

    let done_flags: Vec<bool> = children.iter().map(|child| child.stopped == "terminal").collect();
    let Some(event) = join_event(&join, &done_flags) else {
        let count_done = done_flags.iter().filter(|is_done| **is_done).count();
        return Err(CheckpointError(format!(
            "join {join:?} not satisfied: {count_done}/{} children done - parent stays suspended",
            done_flags.len()
        )));
    };

    let summary: Vec<JsonValue> = children
        .iter()
        .map(|child| {
            serde_json::json!({"item": child.item, "path": child.path, "stopped": child.stopped})
        })
        .collect();
    inject_children(checkpoint_path, &JsonValue::Array(summary))?;

    let mut agent = child_agent_factory();
    let final_res = resume(checkpoint_path, &mut *agent, None, Some(event), 25, true)?;
    Ok((final_res, children))
}

/// Write the aggregated child summary into the parent checkpoint's state under `_children`.
fn inject_children(checkpoint_path: &str, summary: &JsonValue) -> Result<(), CheckpointError> {
    let text =
        std::fs::read_to_string(checkpoint_path).map_err(|err| CheckpointError(err.to_string()))?;
    let mut checkpoint_val: JsonValue =
        serde_json::from_str(&text).map_err(|err| CheckpointError(err.to_string()))?;
    checkpoint_val["state"]["_children"] = summary.clone();
    std::fs::write(checkpoint_path, serde_json::to_string_pretty(&checkpoint_val).map_err(|err| CheckpointError(err.to_string()))?)
        .map_err(|err| CheckpointError(err.to_string()))
}
