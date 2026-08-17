# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The graph engine — a LangGraph replacement driven by a markdown graph.

run(graph, agent): start at graph.start; at each node, hand the agent the node instruction
and running state; the agent returns an OUTCOME (a string, or a dict with structured fields
plus 'text'). Routing then chooses the next node by a SPECTRUM:
  1. DETERMINISTIC edges (`-> t: when <expr>`) are evaluated against the outcome fields (+ a
     `visits` counter) — first match wins. Logic where logic exists.
  2. Otherwise, the SEMANTIC edges are routed by the router (embedding / hybrid / LLM) over
     the outcome text. Intent where logic doesn't.
Repeat until a terminal node (no edges), a stuck state, needs_human, or max_steps.

The agent is any callable (node, instruction, state) -> outcome, so the engine is independent
of who runs the work (a real LLM agent, the swarm, a pipeline coder, a mock, a shell step).

Suspension (durable execution — see prismpath.checkpoint). The engine is PURE (no I/O of its own):
  * A run suspends with stopped=='needs_human' when the worker asks for a human (it returns a
    dict with `needs_human` truthy) OR a semantic route's confidence falls below `human_floor`.
    `RunResult.pending` then carries the decision awaiting a human (node + candidate edges + any
    scores). The absolute-score floor becomes a first-class "route this to a person" outcome.
  * A run can RE-ENTER mid-graph via `start=` and a restored `state=` (so a checkpoint can resume
    without ever touching the read-only .md), and an `on_step` callback lets a caller persist a
    checkpoint at each step. The engine itself neither reads nor writes any file.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

from prismpath.parser import Graph
from prismpath.router import EmbeddingRouter
from prismpath import predicates


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


def _normalize(outcome) -> Tuple[str, dict]:
    """Agent may return a str or a dict. Return (text, fields)."""
    if isinstance(outcome, dict):
        return str(outcome.get("text", "")), dict(outcome)
    return str(outcome), {"text": str(outcome)}


def first_deterministic(edges, ctx):
    """The deterministic tier: return (target, condition) of the first `when` edge whose predicate
    matches — document order, first-true-wins — or (None, None). An unsafe/unparseable predicate
    (which `validate` catches) is treated as non-matching, never a crash. Shared by `run()` and
    `prismpath test` so the two can never disagree on how a node routes."""
    for t, c in edges:
        if not predicates.is_deterministic(c):
            continue
        try:
            if predicates.eval_condition(c, ctx):
                return t, c
        except predicates.PredicateError:
            pass
    return None, None


def _flow_state_bound(graph) -> Optional[int]:
    """The flow-declared bound on persisted state: the first `@state_bound(transcript=N)` annotation
    in document order (the annotation is flow-scoped; any node may carry it). N must be a positive
    integer — a declared bound that silently failed to bind would be the worst outcome, so a
    malformed value raises at run start rather than being treated as inert."""
    for name, n in graph.nodes.items():
        args = n.annotations.get("state_bound")
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


def _count_drop(state: dict, key: str, n: int) -> None:
    d = state.setdefault("_state_dropped", {})
    d[key] = d.get(key, 0) + n


def _bound_list(state: dict, key: str, keep: Optional[int]) -> None:
    """Sliding-window a growing state list to its last `keep` entries, counting what was dropped in
    `state['_state_dropped']` — a deterministic summary in place of a model-generated one (the
    engine stays pure). The routing-relevant history (visits / error counters) lives in separate
    per-node ints and is never touched."""
    if not keep:
        return
    seq = state.get(key) or []
    if len(seq) > keep:
        _count_drop(state, key, len(seq) - keep)
        state[key] = seq[-keep:]


def run(graph: Graph, agent: Callable[[str, str, dict], object], router=None,
        max_steps: int = 25, verbose: bool = False, *,
        start: Optional[str] = None, state: Optional[dict] = None,
        human_floor: Optional[float] = None, type_gate: bool = False,
        max_transcript: Optional[int] = None,
        on_step: Optional[Callable[["RunResult", Optional[str]], None]] = None,
        on_decision: Optional[Callable[[dict], None]] = None,
        run_id: Optional[str] = None,
        _seed_path=None, _seed_steps=None) -> RunResult:
    if router is None:
        router = EmbeddingRouter()
    # type_gate: validate each worker's output against the contract derived from the node's `when`
    # edges (prismpath.contract) — a pure check, no I/O, so the engine stays pure. A wrong-TYPE emitted
    # field stops the run with stopped='contract_violation' before routing acts on it.
    _contracts = {}
    if type_gate:
        from prismpath import contract as _contract_mod
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
        n = graph.nodes[node]
        if n.terminal:
            res.stopped = "terminal"
            checkpoint(None)
            break
        checkpoint(node)                       # about to run `node` with the current state
        state["visits"][node] = state["visits"].get(node, 0) + 1

        try:
            outcome = agent(node, n.instruction, state)
        except Exception as e:                 # error tier: `-> t: on error [when …]`
            ec = state.setdefault("_errors", {})
            ec[node] = ec.get(node, 0) + 1
            err_ctx = {"error": True, "error_type": type(e).__name__, "error_message": str(e),
                       "error_count": ec[node], "visits": state["visits"][node]}
            etarget = None
            for t, c in n.edges:
                if not predicates.is_error(c):
                    continue
                expr = predicates.error_expr(c)
                try:
                    if not expr or predicates.eval_condition(expr, err_ctx):
                        etarget = t
                        break
                except predicates.PredicateError:
                    pass
            if etarget is None:
                raise                          # no handler -> propagate (backward compatible)
            etext = f"[error: {type(e).__name__}: {e}]"
            state["transcript"].append({"node": node, "outcome": etext, "error": True})
            _bound_list(state, "transcript", bound)
            res.steps.append(StepLog(node, etext, etarget,
                                     {"used": "error", "error_type": type(e).__name__}))
            if verbose:
                print(f"  [{node}] --error--> {etarget}   | {etext[:70]!r}")
            node = etarget
            res.path.append(node)
            continue

        text, fields = _normalize(outcome)
        state["transcript"].append({"node": node, "outcome": text})
        _bound_list(state, "transcript", bound)
        state.setdefault("_outcomes", {})[node] = dict(fields)   # latest structured outcome per node
        # (_outcomes is last-write-per-node — bounded by |nodes| by construction, no window needed)

        # Type gate (opt-in): a worker output whose field TYPE contradicts what this node's `when`
        # edges read is a contract violation — stop before routing acts on the malformed field.
        if type_gate:
            from prismpath import contract as _contract_mod
            violations = [p for p in _contract_mod.validate_output(_contracts.get(node, {}), fields)
                          if p.startswith("type:")]
            if violations:
                res.stopped = "contract_violation"
                res.pending = {"node": node, "reason": "worker output violates the derived contract",
                               "violations": violations}
                checkpoint(node)
                break

        # Worker-requested human handoff: suspend before routing (the worker owns this decision).
        if fields.get("needs_human"):
            res.stopped = "needs_human"
            res.pending = {"node": node, "reason": fields.get("reason") or text,
                           "candidates": [{"target": t, "condition": c} for t, c in n.edges]}
            checkpoint(node)
            break

        # Wait-for-event: the worker asks to pause until an external signal (a webhook, a timer).
        # The node's `on event <name>` / `on timeout` edges say where each resumes to. A `spawn` spec
        # IMPLIES wait — fanning out is meaningless without suspending for the join — so a worker
        # returning spawn without wait isn't silently dropped (a real authoring footgun otherwise).
        if fields.get("wait") or fields.get("spawn") is not None:
            events = [(t, c) for t, c in n.edges if predicates.is_event(c)]
            res.stopped = "waiting"
            res.pending = {"node": node, "wait": True,
                           "awaiting": [predicates.event_name(c) for _, c in events],
                           "timeout_s": fields.get("timeout_s"),
                           "candidates": [{"target": t, "condition": c} for t, c in events]}
            # Fan-out / sub-flow composition: the worker may hand the harness a DATA spec of children to
            # spawn (child flow, item list, join policy). The engine stays PURE — it only records the
            # spec in `pending` (so the checkpoint carries it); composer.py, out-of-band, does the actual
            # spawning and delivers the `all_done`/`quorum` event that resumes this node's event edge.
            if fields.get("spawn") is not None:
                res.pending["spawn"] = fields["spawn"]
            checkpoint(node)
            break

        sem = [(t, c) for t, c in n.edges if predicates.is_semantic(c)]
        ctx = {**fields, "visits": state["visits"][node]}

        target, info = None, {}
        dt, dc = first_deterministic(n.edges, ctx)   # deterministic tier (doc order, first-true)
        if dt is not None:
            target, info = dt, {"used": "deterministic", "cond": dc}
        if target is None:
            if sem:
                d = router.route(text, sem, n.instruction)
                # Absolute-confidence floor -> route to a human instead of guessing.
                score = d.info.get("score")
                if human_floor is not None and score is not None and score < human_floor:
                    sims = d.info.get("sims", {})
                    res.stopped = "needs_human"
                    res.pending = {
                        "node": node,
                        "reason": f"router confidence {score:.3f} < human_floor {human_floor}",
                        "would_pick": d.target,
                        "candidates": [{"target": t, "condition": c, "score": sims.get(t)}
                                       for t, c in sem]}
                    checkpoint(node)
                    break
                target, info = d.target, d.info
                if on_decision is not None:    # Sprint-0 routing-decision record (semantic tier)
                    sims = d.info.get("sims", {})
                    scored = sorted((s for s in (sims.get(t) for t, _ in sem) if s is not None),
                                    reverse=True)
                    on_decision({
                        "run_id": run_id, "flow": graph.name, "node": node,
                        "outcome_text": text,
                        "outcome_fields": {k: v for k, v in fields.items() if k != "text"},
                        "candidates": [{"target": t, "condition": c, "score": sims.get(t)}
                                       for t, c in sem],
                        "top1": scored[0] if scored else None,
                        "top2": scored[1] if len(scored) > 1 else None,
                        "margin": d.info.get("margin", d.info.get("embed_margin")),
                        "chosen": d.target, "mechanism": d.info.get("used"),
                        "escalated": bool(d.info.get("escalated", False)),
                        "llm_choice": d.target if d.info.get("escalated") else None,
                        "label": None, "label_source": None})
            else:
                res.stopped = "stuck"          # deterministic-only node, nothing matched
                checkpoint(node)
                break

        res.steps.append(StepLog(node, text, target, info))
        if verbose:
            print(f"  [{node}] --{info.get('used','?')}--> {target}   | {text[:70]!r}")
        node = target
        res.path.append(node)
    else:
        res.stopped = "max_steps"
    return res
