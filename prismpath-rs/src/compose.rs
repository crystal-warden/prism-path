//! compose.rs — the MINIMAL in-process fan-out driver (feature `durable`).
//!
//! The engine stays pure: a worker returning a `spawn` spec suspends the run `waiting` with the
//! spec recorded in `pending` (exactly like the reference). This driver is the smallest harness
//! that completes the composition protocol IN PROCESS: run each child flow with the item seeded
//! as `state._item`, aggregate the child outcomes into the parent's state under `_children`, and
//! resume the parent by delivering the `all_done` join event through the durable checkpoint —
//! the same `resume(event=…)` path the reference composer uses.
//!
//! Deliberately NOT here (the reference `composer.py`'s durable machinery, a named follow-on):
//! out-of-band child checkpoints under `<parent>.children/`, crash re-scan, retry caps,
//! `quorum:k` joins, and `done_when` gating. `all_done` is the one join family this driver
//! completes.

use crate::durable::{resume, run_durable, CheckpointError};
use crate::{parse, run, RunOpts, RunResult, RunState, V};
use serde_json::Value;

/// Outcome of one child run.
#[derive(Debug)]
pub struct ChildResult {
    pub item: Value,
    pub path: Vec<String>,
    pub stopped: String,
}

/// Run `parent_flow` to its spawn point, fan out the children in process, deliver `all_done`.
/// `child_flow_of` resolves the spec's `flow` name to a flow TEXT (the caller owns file layout).
pub fn run_fanout<F, G, R>(
    parent_flow_path: &str,
    checkpoint_path: &str,
    parent_agent: F,
    mut child_agent_factory: G,
    mut child_flow_of: R,
) -> Result<(RunResult, Vec<ChildResult>), CheckpointError>
where
    F: FnMut(&str, &str, &RunState) -> Result<V, String>,
    G: FnMut() -> Box<dyn FnMut(&str, &str, &RunState) -> Result<V, String>>,
    R: FnMut(&str) -> Result<String, String>,
{
    let first = run_durable(parent_flow_path, parent_agent, checkpoint_path, false, RunOpts::default())
        .map_err(|e| CheckpointError(e.to_string()))?;
    if first.stopped != "waiting" {
        return Ok((first, Vec::new())); // nothing spawned — the run simply finished
    }
    let Some(spawn) = first.pending.as_ref().and_then(|p| p.spawn.as_ref()) else {
        return Err(CheckpointError(
            "parent is waiting but recorded no spawn spec — deliver its event externally".into(),
        ));
    };
    let spec = spawn.to_json();
    let flow_name = spec
        .get("flow")
        .and_then(|f| f.as_str())
        .ok_or(CheckpointError("spawn spec has no `flow`".into()))?;
    let items: Vec<Value> = spec
        .get("items")
        .and_then(|i| i.as_array())
        .cloned()
        .unwrap_or_default();
    let child_text = child_flow_of(flow_name).map_err(CheckpointError)?;
    let child_graph = parse(&child_text);

    let mut children = Vec::new();
    for item in items {
        let state = V::Obj(vec![("_item".to_string(), V::from_json(&item))]);
        let mut agent = child_agent_factory();
        let res = run(
            &child_graph,
            &mut *agent,
            RunOpts { state: Some(state), ..Default::default() },
        )
        .map_err(|e| CheckpointError(format!("child failed: {e}")))?;
        children.push(ChildResult { item, path: res.path, stopped: res.stopped });
    }

    // Aggregate into the parent's checkpointed state, then deliver the join event.
    let summary: Vec<Value> = children
        .iter()
        .map(|c| {
            serde_json::json!({"item": c.item, "path": c.path, "stopped": c.stopped})
        })
        .collect();
    inject_children(checkpoint_path, &Value::Array(summary))?;

    let mut agent = child_agent_factory(); // parent post-join nodes run with a fresh agent
    let final_res = resume(checkpoint_path, &mut *agent, None, Some("all_done"), 25, true)?;
    Ok((final_res, children))
}

/// Write the aggregated child summary into the parent checkpoint's state under `_children`.
fn inject_children(checkpoint_path: &str, summary: &Value) -> Result<(), CheckpointError> {
    let text =
        std::fs::read_to_string(checkpoint_path).map_err(|e| CheckpointError(e.to_string()))?;
    let mut cp: Value =
        serde_json::from_str(&text).map_err(|e| CheckpointError(e.to_string()))?;
    cp["state"]["_children"] = summary.clone();
    std::fs::write(checkpoint_path, serde_json::to_string_pretty(&cp).map_err(|e| CheckpointError(e.to_string()))?)
        .map_err(|e| CheckpointError(e.to_string()))
}
