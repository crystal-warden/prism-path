"""checkpoint.py — durable execution for prismpath (Area 6, Slice 0: the JSON checkpoint).

The engine (engine.py) is pure and its `state` is ephemeral — thrown away when run() returns.
This module makes a run DURABLE and RESUMABLE without ever touching the read-only flow `.md`:
it serializes the run's state to a JSON sidecar (atomic os.replace) at each step and at a
suspension point, and resumes by RE-PARSING the read-only `.md` and re-entering the engine with
the restored state.

  run_durable(flow, agent, ckpt)         # run, checkpointing every step
  resume(ckpt, agent)                     # after a crash: re-enter at the pending node, re-run it
  resume(ckpt, agent, choose="stage_x")   # after a needs_human suspension: apply the human's edge

Design guarantees:
  * The flow `.md` is NEVER written — durable state lives only in the sidecar. The single
    read-only-source invariant is preserved (indeed this is why we checkpoint to JSON, not to a
    checkbox back in the doc).
  * Deterministic replay: same checkpoint + same choice => identical continuation (the engine's
    deterministic-first routing is a pure function of the restored state).
  * Off the critical path: if the state is not JSON-serializable, checkpointing disables itself
    with a warning rather than breaking the run.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Optional

from prismpath.engine import RunResult, StepLog, run
from prismpath.parser import parse_file

CHECKPOINT_VERSION = 1


def _flow_hash(flow_path) -> str:
    """Content hash of the flow file — bound into the checkpoint so a resume can detect that the
    .md was edited while the run was suspended."""
    try:
        with open(flow_path, "rb") as f:
            return "sha256:" + hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return ""


class CheckpointError(Exception):
    pass


def _atomic_write(path, data: str) -> None:
    path = os.fspath(path)
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)   # atomic on POSIX: a reader sees the old or new file, never a torn one


def save_checkpoint(path, flow_path, result: RunResult, pending_node: Optional[str],
                    type_gate: bool = False) -> None:
    """Serialize the run to `path` atomically. `pending_node` is where a resume re-enters."""
    doc = {
        "version": CHECKPOINT_VERSION,
        "flow_path": os.path.abspath(os.fspath(flow_path)),
        "flow_hash": _flow_hash(flow_path),
        "pending_node": pending_node,
        "stopped": result.stopped,
        "type_gate": type_gate,                     # persisted so resume keeps the gate on (never dropped)
        "saved_at": time.time(),                    # UTC epoch; the scheduler reads this for `on timeout`
        "path": list(result.path),
        "state": result.state,
        "pending_decision": result.pending,        # the evidence packet for a human, if suspended
        "steps": [{"node": s.node, "target": s.target, "used": s.info.get("used")}
                  for s in result.steps],
    }
    try:
        data = json.dumps(doc, indent=2)
    except TypeError as e:
        raise CheckpointError(
            f"run state is not JSON-serializable ({e}); keep checkpointed state to JSON types "
            f"(str/int/float/bool/list/dict/None)") from e
    _atomic_write(path, data)


def load_checkpoint(path) -> dict:
    with open(path) as f:
        cp = json.load(f)
    if cp.get("version") != CHECKPOINT_VERSION:
        raise CheckpointError(f"unsupported checkpoint version {cp.get('version')!r} "
                              f"(this build expects {CHECKPOINT_VERSION})")
    return cp


def _check_flow_unchanged(cp: dict) -> None:
    """Guard resume against a flow edited while the run was suspended (which version governs?).
    Policy from PRISMPATH_RESUME_ON_FLOW_CHANGE: 'refuse' (default — raise, the audit-safe choice),
    'warn' (proceed + print), 'allow' (proceed silently). A checkpoint predating flow-hashing (no
    `flow_hash`) is not blocked."""
    old = cp.get("flow_hash")
    if not old:
        return
    now = _flow_hash(cp.get("flow_path", ""))
    if now and now == old:
        return
    policy = os.environ.get("PRISMPATH_RESUME_ON_FLOW_CHANGE", "refuse").lower()
    msg = (f"flow {cp.get('flow_path')!r} changed since this run was checkpointed "
           f"(was {old[:23]}…, now {(now or 'missing')[:23]}…)")
    if policy == "allow":
        return
    if policy == "warn":
        print(f"  [checkpoint] WARNING: {msg} — resuming anyway "
              f"(PRISMPATH_RESUME_ON_FLOW_CHANGE=warn)")
        return
    raise CheckpointError(
        msg + ". Refusing to resume against a changed flow — set "
        "PRISMPATH_RESUME_ON_FLOW_CHANGE=warn (proceed) or =allow (silent) to override.")


def run_durable(flow_path, agent, checkpoint_path, router=None, human_floor: Optional[float] = None,
                type_gate: bool = False, max_steps: int = 25, state: Optional[dict] = None) -> RunResult:
    """Run a flow while persisting a checkpoint at every step. On a crash, `resume(checkpoint_path,
    agent)` continues from the pending node. Checkpointing is best-effort — it disables itself (with
    a warning) rather than break the run if the state can't be serialized.

    `state` seeds the run's initial state — the composition harness uses it to hand a spawned child its
    per-item payload (e.g. state={'_item': {...}}) so a fan-out child knows which item it is processing."""
    graph = parse_file(flow_path)
    disabled = {"v": False}

    def on_step(res: RunResult, pending_node: Optional[str]) -> None:
        if disabled["v"]:
            return
        try:
            save_checkpoint(checkpoint_path, flow_path, res, pending_node, type_gate=type_gate)
        except CheckpointError as e:
            print(f"  [checkpoint] disabled for this run — {e}")
            disabled["v"] = True

    return run(graph, agent, router=router, human_floor=human_floor, type_gate=type_gate,
               max_steps=max_steps, on_step=on_step, state=state)


def resume(checkpoint_path, agent, router=None, choose: Optional[str] = None,
           event: Optional[str] = None, human_floor: Optional[float] = None, max_steps: int = 25,
           write_back: bool = True, type_gate: Optional[bool] = None) -> RunResult:
    """Resume a run from its checkpoint. Re-parses the READ-ONLY .md and re-enters the engine.

    * `choose` given  -> resume a `needs_human` suspension: apply the human's edge and continue.
    * `event` given   -> resume a `waiting` suspension: deliver the event (a signal name, or
      '__timeout__') and continue from the matching `on event`/`on timeout` edge.
    * neither         -> resume a crash (or a `contract_violation`): re-enter at the pending node and
      re-run it, idempotently and STILL TYPE-GATED (the gate persists across every resume).

    `type_gate` defaults to the value the checkpoint was saved with, so the gate is never silently
    dropped on resume; pass True/False to override.
    """
    from prismpath import predicates
    cp = load_checkpoint(checkpoint_path)
    _check_flow_unchanged(cp)                           # refuse to resume against a silently-edited flow
    graph = parse_file(cp["flow_path"])                 # never written
    state = cp.get("state") or {}
    stopped = cp.get("stopped", "")
    tg = cp.get("type_gate", False) if type_gate is None else type_gate
    if choose is None and cp.get("decision"):           # a decision recorded from the queue UI
        choose = cp["decision"].get("choose")

    on_step = None
    if write_back:
        flow_path = cp["flow_path"]

        def on_step(res, pending_node):                 # keep the sidecar fresh for re-resume
            try:
                save_checkpoint(checkpoint_path, flow_path, res, pending_node, type_gate=tg)
            except CheckpointError:
                pass

    if choose is not None:
        decision = cp.get("pending_decision") or {}
        dnode = decision.get("node", cp.get("pending_node"))
        if dnode not in graph.nodes:
            raise CheckpointError(f"pending node {dnode!r} is not in the flow")
        valid = [t for t, _ in graph.nodes[dnode].edges]
        if choose not in valid:
            raise CheckpointError(
                f"--choose {choose!r} is not an edge target of node {dnode!r}; valid: {valid}")
        state.setdefault("transcript", []).append(
            {"node": dnode, "outcome": f"[human chose -> {choose}]", "decided_by": "human"})
        seed_steps = _prior_steps(cp) + [StepLog(dnode, "[human decision]", choose, {"used": "human"})]
        return run(graph, agent, router=router, start=choose, state=state,
                   human_floor=human_floor, type_gate=tg, max_steps=max_steps, on_step=on_step,
                   _seed_path=cp.get("path", []), _seed_steps=seed_steps)

    if event is not None:
        wnode = (cp.get("pending_decision") or {}).get("node") or cp.get("pending_node")
        if wnode not in graph.nodes:
            raise CheckpointError(f"pending node {wnode!r} is not in the flow")
        target = next((t for t, c in graph.nodes[wnode].edges
                       if predicates.is_event(c) and predicates.event_name(c) == event), None)
        if target is None:
            avail = [predicates.event_name(c) for _, c in graph.nodes[wnode].edges
                     if predicates.is_event(c)]
            raise CheckpointError(f"no edge for event {event!r} on {wnode!r}; awaiting: {avail}")
        state.setdefault("transcript", []).append(
            {"node": wnode, "outcome": f"[event: {event}]", "event": event})
        seed_steps = _prior_steps(cp) + [StepLog(wnode, f"[event: {event}]", target, {"used": "event"})]
        return run(graph, agent, router=router, start=target, state=state,
                   human_floor=human_floor, type_gate=tg, max_steps=max_steps, on_step=on_step,
                   _seed_path=cp.get("path", []), _seed_steps=seed_steps)

    if stopped == "needs_human":
        cands = [c.get("target") for c in (cp.get("pending_decision") or {}).get("candidates", [])]
        raise CheckpointError(
            f"this run is suspended for a human decision — resume with choose=<edge> "
            f"(candidates: {cands})")
    if stopped == "waiting":
        awaiting = (cp.get("pending_decision") or {}).get("awaiting", [])
        raise CheckpointError(
            f"this run is waiting for an event — resume with event=<name> (awaiting: {awaiting})")
    if stopped in ("terminal", "stuck", "max_steps"):
        raise CheckpointError(f"run already finished (stopped={stopped!r}); nothing to resume")

    pending = cp.get("pending_node")
    if pending is None or pending not in graph.nodes:
        raise CheckpointError(f"checkpoint has no resumable pending node ({pending!r})")
    prior = cp.get("path", [])
    return run(graph, agent, router=router, start=pending, state=state,
               human_floor=human_floor, max_steps=max_steps, on_step=on_step,
               _seed_path=prior[:-1], _seed_steps=_prior_steps(cp))   # prior ends at pending (re-run)


def _prior_steps(cp: dict):
    """Reconstruct lightweight StepLogs from a checkpoint's stored step summaries (outcome text is
    not persisted, so it's best-effort — enough to keep RunResult.path and .steps consistent)."""
    return [StepLog(s.get("node"), "", s.get("target"), {"used": s.get("used")})
            for s in cp.get("steps", [])]


# --- the human queue (Mission Control) --------------------------------------------------

def queue_dir() -> str:
    """Where suspended-run checkpoints wait for a human. PRISMPATH_QUEUE_DIR overrides; else
    $XDG_STATE_HOME/prismpath/queue (~/.local/state/prismpath/queue)."""
    override = os.environ.get("PRISMPATH_QUEUE_DIR")
    if override:
        return override
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    return os.path.join(base, "prismpath", "queue")


def list_queue(qdir=None) -> list:
    """Evidence packets for every suspended (needs_human) checkpoint in the queue dir, newest first.
    Each item: {id, path, flow, node, reason, would_pick, candidates[], decision, ts}."""
    qdir = qdir or queue_dir()
    out = []
    if not os.path.isdir(qdir):
        return out
    # Walk RECURSIVELY: spawned fan-out children live in `<parent>.children/` subdirs, and a child that
    # suspends `needs_human` must still be visible to an operator (else the parent fan-out blocks with no
    # surfaced work item). Each item carries `child_of` when it is a spawned child. NOTE: Mission
    # Control's decide endpoint currently resolves ids as a basename under the queue dir, so ACTIONING a
    # nested child needs a follow-on there; discovery (this) is the load-bearing half.
    for root, _dirs, files in os.walk(qdir):
        for name in files:
            if not name.endswith(".json"):
                continue
            path = os.path.join(root, name)
            try:
                cp = load_checkpoint(path)
            except Exception:
                continue
            if cp.get("stopped") != "needs_human":
                continue
            pend = cp.get("pending_decision") or {}
            flow = os.path.basename(cp.get("flow_path", ""))
            if flow.endswith(".md"):
                flow = flow[:-3]
            rel = os.path.relpath(path, qdir)
            parent_dir = os.path.basename(os.path.dirname(path))
            child_of = parent_dir[:-len(".children")] if parent_dir.endswith(".children") else None
            out.append({
                "id": name[:-5] if child_of is None else rel[:-5],   # top-level ids unchanged
                "path": path,
                "flow": flow,
                "node": pend.get("node") or cp.get("pending_node"),
                "reason": pend.get("reason"),
                "would_pick": pend.get("would_pick"),
                "candidates": pend.get("candidates", []),
                "decision": cp.get("decision"),
                "child_of": child_of,
                "ts": os.path.getmtime(path),
            })
    out.sort(key=lambda x: x["ts"], reverse=True)
    return out


def resolve_queue_item(item_id: str, qdir=None) -> str:
    """Resolve a queue-item id from `list_queue` to its checkpoint path, SAFELY: ids may now be
    relative paths into a fan-out's `<parent>.children/` subdir (e.g. 'p.children/a.py'), so a plain
    basename() would break child actioning — but unrestricted joining would allow path traversal.
    The resolved path must stay inside the queue dir and exist; anything else raises."""
    qdir = os.path.realpath(qdir or queue_dir())
    cand = os.path.realpath(os.path.join(qdir, item_id + ".json"))
    if cand != qdir and not cand.startswith(qdir + os.sep):
        raise CheckpointError(f"queue item {item_id!r} escapes the queue dir")
    if not os.path.isfile(cand):
        raise CheckpointError(f"queue item {item_id!r} not found")
    return cand


def record_decision(checkpoint_path, choose: str, decided_by: str = "human") -> dict:
    """Record a human's chosen edge into a suspended checkpoint (atomic). A later `resume()` with no
    explicit `choose` applies it. Validates `choose` against the pending candidates."""
    cp = load_checkpoint(checkpoint_path)
    if cp.get("stopped") != "needs_human":
        raise CheckpointError(f"checkpoint is not awaiting a human (stopped={cp.get('stopped')!r})")
    pend = cp.get("pending_decision") or {}
    cands = [c.get("target") for c in pend.get("candidates", [])]
    if choose not in cands:
        raise CheckpointError(f"choose {choose!r} is not a candidate edge; valid: {cands}")
    cp["decision"] = {"choose": choose, "decided_by": decided_by}
    _atomic_write(checkpoint_path, json.dumps(cp, indent=2))
    return cp
