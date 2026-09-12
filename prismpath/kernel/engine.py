# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The graph engine: a LangGraph replacement driven by a markdown graph.

run(graph, worker): start at graph.start; at each node, hand the worker the node instruction
and running state; the worker returns an OUTCOME (a string, or a dict with structured fields
plus 'text'). Routing then chooses the next node by a SPECTRUM:
  1. DETERMINISTIC edges (`-> target: condition`) are evaluated against the outcome fields (+ a
     `visits` counter) - first match wins. Logic where logic exists.
  2. Otherwise, the SEMANTIC edges are routed by the router (embedding / hybrid / LLM) over
     the outcome text. Intent where logic doesn't.
Repeat until a terminal node (no edges), a stuck state, needs_human, or max_steps.

The worker is any callable (node, instruction, state) -> outcome, so the engine is independent
of who runs the work (a real LLM agent, the swarm, a pipeline coder, a mock, a shell step).
The second parameter was called `agent` before the dictionary settled on worker; `agent=` still
works as a deprecated keyword alias, and no first party caller uses it.

Suspension (durable execution: see prismpath.checkpoint). The engine is PURE (no I/O of its own):
  * A run suspends with stopped=='needs_human' when the worker asks for a human (it returns a
    dict with `needs_human` truthy) OR a semantic route's confidence falls below `human_floor`.
    `RunResult.pending` then carries the decision awaiting a human (node + candidate edges + any
    scores). The absolute-score floor becomes a first-class "route this to a person" outcome.
  * A run can RE-ENTER mid-graph via `start=` and a restored `state=` (so a checkpoint can resume
    without ever touching the read-only .md), and an `on_step` callback lets a caller persist a
    checkpoint at each step. The engine itself neither reads nor writes any file.
"""
from __future__ import annotations

import warnings
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

from prismpath.kernel.parser import Graph
from prismpath.kernel import causes
from prismpath.kernel import predicates
@dataclass
class StepLog:
    node: str
    outcome: str
    target: str
    info: dict


@dataclass
class RunResult:
    path: List[str]
    steps: List[StepLog] = field(default_factory=list)
    stopped: str = ""   # 'terminal'|'stuck'|'needs_human'|'waiting'|'max_steps'|'contract_violation'|''
    state: dict = field(default_factory=dict)
    pending: Optional[dict] = None   # set iff stopped=='needs_human': the decision awaiting a human
    cause: int = causes.CAUSE_NONE   # WHY the run refused/parked/escalated (spec-cause-codes.md);
                                     # 0 for clean outcomes (terminal, waiting). Finer than `stopped`:
                                     # the two needs_human sites carry DIFFERENT causes
                                     # (worker-requested vs below the calibrated floor).


def _normalize(outcome) -> Tuple[str, dict]:
    """Agent may return a str or a dict. Return (text, fields)."""
    if isinstance(outcome, dict):
        return str(outcome.get("text", "")), dict(outcome)
    return str(outcome), {"text": str(outcome)}


def first_deterministic(edges, ctx):
    """The deterministic tier: return (target, condition) of the first `when` edge whose predicate
    matches - document order, first-true-wins - or (None, None). An unsafe/unparseable predicate
    (which `validate` catches) is treated as non-matching, never a crash. Shared by `run()` and
    `prismpath test` so the two can never disagree on how a node routes."""
    for target, condition in edges:
        if not predicates.is_deterministic(condition):
            continue
        try:
            if predicates.eval_condition(condition, ctx):
                return target, condition
        except predicates.PredicateError:
            pass
    return None, None


def _flow_state_bound(graph) -> Optional[int]:
    """The flow-declared bound on persisted state: the first `@state_bound(transcript=N)` annotation
    in document order (the annotation is flow-scoped; any node may carry it). N must be a positive
    integer - a declared bound that silently failed to bind would be the worst outcome, so a
    malformed value raises at run start rather than being treated as inert."""
    for name, node_obj in graph.nodes.items():
        args = node_obj.annotations.get("state_bound")
        if args is None:
            continue
        raw = args.get("transcript")
        try:
            keep = int(raw)
        except (TypeError, ValueError):
            raise ValueError(f"@state_bound(transcript={raw!r}) on node {name!r}: "
                             f"transcript must be a positive integer")
        if keep < 1:
            raise ValueError(f"@state_bound(transcript={keep}) on node {name!r}: must be >= 1")
        return keep
    return None


def _count_drop(state: dict, key: str, count: int) -> None:
    dropped_map = state.setdefault("_state_dropped", {})
    dropped_map[key] = dropped_map.get(key, 0) + count


def _bound_list(state: dict, key: str, keep: Optional[int]) -> None:
    """Sliding-window a growing state list to its last `keep` entries, counting what was dropped in
    `state['_state_dropped']` - a deterministic summary in place of a model-generated one (the
    engine stays pure). The routing-relevant history (visits / error counters) lives in separate
    per-node ints and is never touched."""
    if not keep:
        return
    seq = state.get(key) or []
    if len(seq) > keep:
        _count_drop(state, key, len(seq) - keep)
        state[key] = seq[-keep:]


def run(graph: Graph, worker: Optional[Callable[[str, str, dict], object]] = None, router=None,
        max_steps: int = 25, verbose: bool = False, *,
        start: Optional[str] = None, state: Optional[dict] = None,
        human_floor: Optional[float] = None, type_gate: bool = False,
        max_transcript: Optional[int] = None,
        on_step: Optional[Callable[["RunResult", Optional[str]], None]] = None,
        on_decision: Optional[Callable[[dict], None]] = None,
        run_id: Optional[str] = None,
        agent: Optional[Callable[[str, str, dict], object]] = None,
        _seed_path=None, _seed_steps=None) -> RunResult:
    # `agent` is what `worker` was called before the rename, kept so an outside caller written
    # against the old signature keeps running instead of raising on an unexpected keyword.
    if agent is not None:
        warnings.warn("run(agent=...) is now run(worker=...); the agent keyword goes away in a "
                      "later release", DeprecationWarning, stacklevel=2)
        if worker is None:
            worker = agent
    if worker is None:
        raise TypeError("run() needs a worker: run(graph, worker)")
    if router is None:
        from prismpath.routing.router import EmbeddingRouter
        router = EmbeddingRouter()
    # type_gate: validate each worker's output against the contract derived from the node's `when`
    # edges (prismpath.contract) — a pure check, no I/O, so the engine stays pure. A wrong-TYPE emitted
    # field stops the run with stopped='contract_violation' before routing acts on it.
    _contracts = {}
    if type_gate:
        from prismpath.kernel import contract as _contract_mod
        _contracts = _contract_mod.derive_contract(graph)
    node = start if start is not None else graph.start
    if state is None:
        state = {"transcript": [], "visits": {}}
    state.setdefault("transcript", [])
    state.setdefault("visits", {})
    # Bound on persisted state: a flow-declared @state_bound(transcript=N) (or the kwarg override)
    # sliding-windows the growing history lists. Routing NEVER reads them — predicates see fields +
    # the visits/error counters, which are per-node ints and untouched — so the window cannot change
    # a routing decision; what it bounds is the checkpoint payload of a long-lived resumable run.
    bound = max_transcript if max_transcript is not None else _flow_state_bound(graph)
    _bound_list(state, "transcript", bound)     # a resume may arrive with an oversized transcript
    if _seed_path and bound and len(_seed_path) > bound:   # bound the RE-SEEDED history too: this is
        _count_drop(state, "path", len(_seed_path) - bound)     # what keeps the persisted payload
        _seed_path = list(_seed_path)[-bound:]                  # flat across unlimited resumes
    if _seed_steps and bound and len(_seed_steps) > bound:
        _count_drop(state, "steps", len(_seed_steps) - bound)
        _seed_steps = list(_seed_steps)[-bound:]
    res = RunResult(path=[node], state=state)
    if _seed_path:                          # resume: prepend the pre-suspension history so this
        res.path = list(_seed_path) + res.path   # run's result AND its checkpoints carry full path
    if _seed_steps:
        res.steps = list(_seed_steps) + res.steps

    def checkpoint(pending_node):
        if on_step is not None:
            on_step(res, pending_node)

    for _ in range(max_steps):
        node_obj = graph.nodes[node]
        if node_obj.terminal:
            res.stopped = "terminal"
            checkpoint(None)
            break
        checkpoint(node)                       # about to run `node` with the current state
        state["visits"][node] = state["visits"].get(node, 0) + 1

        try:
            outcome = worker(node, node_obj.instruction, state)
        except Exception as exc:                 # error tier: `-> target: on error [when …]`
            error_counts = state.setdefault("_errors", {})
            error_counts[node] = error_counts.get(node, 0) + 1
            err_ctx = {"error": True, "error_type": type(exc).__name__, "error_message": str(exc),
                       "error_count": error_counts[node], "visits": state["visits"][node]}
            etarget = None
            for edge_target, edge_cond in node_obj.edges:
                if not predicates.is_error(edge_cond):
                    continue
                expr = predicates.error_expr(edge_cond)
                try:
                    if not expr or predicates.eval_condition(expr, err_ctx):
                        etarget = edge_target
                        break
                except predicates.PredicateError as guard_err:
                    # the guard itself cannot be evaluated: treated as not satisfied, like the deterministic
                    # tier does, but recorded, so a handler that never fires is visible in the run's state
                    state.setdefault("_guard_errors", []).append(
                        {"node": node, "guard": expr, "error": str(guard_err)})
            if etarget is None:
                raise                          # no handler -> propagate (backward compatible)
            etext = f"[error: {type(exc).__name__}: {exc}]"
            state["transcript"].append({"node": node, "outcome": etext, "error": True})
            _bound_list(state, "transcript", bound)
            step_info = {"used": "error", "error_type": type(exc).__name__}
            guard_errors = [g for g in state.get("_guard_errors", []) if g["node"] == node]
            if guard_errors:
                step_info["guard_errors"] = len(guard_errors)
            res.steps.append(StepLog(node, etext, etarget, step_info))
            if verbose:
                print(f"  [{node}] --error--> {etarget}   | {etext[:70]!r}")
            node = etarget
            res.path.append(node)
            continue

        text, fields = _normalize(outcome)
        state["transcript"].append({"node": node, "outcome": text})
        _bound_list(state, "transcript", bound)
        state.setdefault("_outcomes", {})[node] = dict(fields)   # latest structured outcome per node
        # (_outcomes is last-write-per-node - bounded by |nodes| by construction, no window needed)

        # Type gate (opt-in): a worker output whose field TYPE contradicts what this node's `when`
        # edges read is a contract violation - stop before routing acts on the malformed field.
        if type_gate:
            from prismpath.kernel import contract as _contract_mod
            violations = [p for p in _contract_mod.validate_output(_contracts.get(node, {}), fields)
                          if p.startswith("type:")]
            if violations:
                res.stopped = "contract_violation"
                res.cause = causes.NAMES["route:contract-violation"]
                res.pending = {"node": node, "reason": "worker output violates the derived contract",
                               "violations": violations}
                checkpoint(node)
                break

        # Worker-requested human handoff: suspend before routing (the worker owns this decision).
        if fields.get("needs_human"):
            res.stopped = "needs_human"
            res.cause = causes.NAMES["route:needs-human"]
            res.pending = {"node": node, "reason": fields.get("reason") or text,
                           "candidates": [{"target": edge_target, "condition": edge_cond} for edge_target, edge_cond in node_obj.edges]}
            checkpoint(node)
            break

        # Wait-for-event: the worker asks to pause until an external signal (a webhook, a timer).
        # The node's `on event <name>` / `on timeout` edges say where each resumes to. A `spawn` spec
        # IMPLIES wait - fanning out is meaningless without suspending for the join - so a worker
        # returning spawn without wait isn't silently dropped (a real authoring footgun otherwise).
        if fields.get("wait") or fields.get("spawn") is not None:
            events = [(edge_target, edge_cond) for edge_target, edge_cond in node_obj.edges if predicates.is_event(edge_cond)]
            res.stopped = "waiting"
            res.pending = {"node": node, "wait": True,
                           "awaiting": [predicates.event_name(edge_cond) for _, edge_cond in events],
                           "timeout_s": fields.get("timeout_s"),
                           "candidates": [{"target": edge_target, "condition": edge_cond} for edge_target, edge_cond in events]}
            # Fan-out / sub-flow composition: the worker may hand the harness a DATA spec of children to
            # spawn (child flow, item list, join policy). The engine stays PURE - it only records the
            # spec in `pending` (so the checkpoint carries it); composer.py, out-of-band, does the actual
            # spawning and delivers the `all_done`/`quorum` event that resumes this node's event edge.
            if fields.get("spawn") is not None:
                res.pending["spawn"] = fields["spawn"]
            checkpoint(node)
            break

        sem = [(edge_target, edge_cond) for edge_target, edge_cond in node_obj.edges if predicates.is_semantic(edge_cond)]
        ctx = {**fields, "visits": state["visits"][node]}

        target, info = None, {}
        dt, dc = first_deterministic(node_obj.edges, ctx)   # deterministic tier (doc order, first-true)
        if dt is not None:
            target, info = dt, {"used": "deterministic", "cond": dc}
        if target is None:
            if sem:
                route_decision = router.route(text, sem, node_obj.instruction)
                # Absolute-confidence floor -> route to a human instead of guessing.
                score = route_decision.info.get("score")
                if human_floor is not None and score is not None and score < human_floor:
                    sims = route_decision.info.get("sims", {})
                    res.stopped = "needs_human"
                    res.cause = causes.NAMES["route:below-human-floor"]
                    res.pending = {
                        "node": node,
                        "reason": f"router confidence {score:.3f} < human_floor {human_floor}",
                        "would_pick": route_decision.target,
                        "candidates": [{"target": edge_target, "condition": edge_cond, "score": sims.get(edge_target)}
                                       for edge_target, edge_cond in sem]}
                    checkpoint(node)
                    break
                target, info = route_decision.target, route_decision.info
                if on_decision is not None:    # Sprint-0 routing-decision record (semantic tier)
                    sims = route_decision.info.get("sims", {})
                    scored = sorted((score_val for score_val in (sims.get(edge_target) for edge_target, _ in sem) if score_val is not None),
                                    reverse=True)
                    on_decision({
                        "run_id": run_id, "flow": graph.name, "node": node,
                        "outcome_text": text,
                        "outcome_fields": {key: val for key, val in fields.items() if key != "text"},
                        "candidates": [{"target": edge_target, "condition": edge_cond, "score": sims.get(edge_target)}
                                       for edge_target, edge_cond in sem],
                        "top1": scored[0] if scored else None,
                        "top2": scored[1] if len(scored) > 1 else None,
                        "margin": route_decision.info.get("margin", route_decision.info.get("embed_margin")),
                        "chosen": route_decision.target, "mechanism": route_decision.info.get("used"),
                        "escalated": bool(route_decision.info.get("escalated", False)),
                        "llm_choice": route_decision.target if route_decision.info.get("escalated") else None,
                        "label": None, "label_source": None})
            else:
                res.stopped = "stuck"          # deterministic-only node, nothing matched
                res.cause = causes.NAMES["route:stuck"]
                checkpoint(node)
                break

        res.steps.append(StepLog(node, text, target, info))
        if verbose:
            print(f"  [{node}] --{info.get('used','?')}--> {target}   | {text[:70]!r}")
        node = target
        res.path.append(node)
    else:
        res.stopped = "max_steps"
        res.cause = causes.NAMES["route:max-steps"]
    return res
