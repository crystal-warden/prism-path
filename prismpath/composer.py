"""composer.py — the fan-out / sub-flow composition harness (roadmap item #4).

The engine suspends a fan-out node as `waiting` and records a `spawn` DATA spec in the checkpoint
(engine.py stays PURE — it spawns nothing, does no I/O). This module is the out-of-band harness that
acts on that spec, mirroring `scheduler.fire_due_timeouts` exactly: a dependency-free, RESTARTABLE
scan — no daemon — that

  1. finds `waiting` parent checkpoints carrying a `spawn` spec,
  2. runs one DURABLE child run per item (an ordinary `run_durable` checkpoint) under a DETERMINISTIC
     id — so a harness restart re-derives the same ids and NEVER double-spawns; a child already
     terminal is skipped, a crashed child is resumed, a child blocked on its own event/human is left,
  3. when the join condition holds (`all_done` for now; `quorum:k` in a later tranche), aggregates the
     child terminal outcomes into the parent's state and resumes the parent by delivering the join
     event via `checkpoint.resume(event=...)` — taking the parent's `-> …: on event all_done` edge.

Concurrency MECHANICS live here; fan-in SEMANTICS live in the flow document (the `on event` edges the
engine already routes on). Sub-flow composition is the N==1 case of the same code path. The git ledger
dedups child UNITS across parents for free (a child flow's per-unit proof is shared by every fan-out
that spawns it — see ledger_runner).

    from prismpath import composer
    acted = composer.advance_fanouts(agent)     # scan the default queue once; spawn/poll/join

This is the reference harness (single process, sequential child stepping) — not a production
scheduler (which would add real concurrency, leasing, and at-least-once delivery). The durability and
idempotency guarantees are what make those safe to add later.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
from typing import List, Optional

from prismpath import checkpoint, predicates
from prismpath.checkpoint import load_checkpoint, run_durable, resume, _atomic_write
from prismpath.ledger import _safe


# --- spec + identity ------------------------------------------------------------------
def _items(spec: dict) -> list:
    """The list of items a fan-out spawns over. `items` is the explicit list; a spec may instead be a
    single-child composition (no `items`) which is treated as a one-item fan-out over `item` (or {})."""
    if isinstance(spec.get("items"), list):
        return list(spec["items"])
    if "item" in spec:
        return [spec["item"]]
    return [{}]


def item_id(item, field: Optional[str] = None) -> str:
    """A STABLE, deterministic id for one fan-out item — the crux of restart-safe (no-double-spawn)
    child identity. Precedence: an explicit `field` of a dict item; else a scalar item's own value;
    else a content hash of the item's canonical JSON (reorder-independent, and duplicate items collapse
    to one child — free dedup)."""
    if field and isinstance(item, dict) and field in item:
        return str(item[field])
    if isinstance(item, (str, int, float, bool)):
        return str(item)
    blob = json.dumps(item, sort_keys=True, default=str).encode()
    return "h" + hashlib.sha256(blob).hexdigest()[:16]


def _stem(iid: str) -> str:
    """A filesystem-safe, COLLISION-FREE stem for an item id. `_safe` alone is non-injective (it maps
    every char outside [A-Za-z0-9_.-] to '_', so 'a/b' and 'a_b' would collide and silently share one
    child); when sanitization is lossy we disambiguate with a short hash of the raw id, so distinct ids
    never collapse while a genuinely-identical id still maps to the same child (intended dedup)."""
    safe = _safe(iid)
    if safe == iid:
        return safe
    return f"{safe}-{hashlib.sha256(iid.encode()).hexdigest()[:8]}"


def child_run_id(parent_id: str, node: str, iid: str) -> str:
    """Deterministic child run-id: a pure function of (parent id, fan-out node, item id) — NO timestamp
    or randomness (deliberately unlike ledger.new_run_id), so re-scanning after a crash re-derives the
    SAME id and re-attaches to the existing child instead of spawning a second one. Uses a collision-free
    stem so two distinct item ids never map to one child."""
    return f"{_safe(parent_id)}.{_safe(node)}.{_stem(iid)}"


def _parent_id(parent_ckpt_path: str) -> str:
    """The parent run's stable identity for child-id derivation — its checkpoint's stem (same file
    across restarts)."""
    return os.path.splitext(os.path.basename(parent_ckpt_path))[0]


def _children_dir(parent_ckpt_path: str) -> str:
    """Child checkpoints live in a sibling `<parent>.children/` dir, so the parent scan (which globs
    `*.json` FILES in the queue) never mistakes a child for a parent."""
    return os.path.splitext(parent_ckpt_path)[0] + ".children"


def _child_ckpt_path(parent_ckpt_path: str, iid: str) -> str:
    return os.path.join(_children_dir(parent_ckpt_path), _stem(iid) + ".json")


def _resolve_child_flow(parent_flow_path: str, child: str) -> str:
    """A child flow path is resolved relative to the PARENT flow's directory (or used as-is if
    absolute)."""
    if os.path.isabs(child):
        return child
    return os.path.normpath(os.path.join(os.path.dirname(parent_flow_path), child))


# a child is in a STABLE state (won't be re-run by the harness) once it reaches a terminal node, a
# dead end, needs a human/event, violates its contract, OR is marked errored (see _mark_child_error).
_STABLE = ("terminal", "stuck", "max_steps", "waiting", "needs_human", "contract_violation", "error")


def _mark_child_error(child_ckpt_path: str, base: dict, reason: str) -> dict:
    """Persist a STABLE `error` checkpoint for a child that cannot converge or serialize its state (e.g.
    a non-JSON outcome disabled its checkpointing). Without this the harness would resume it on every
    scan forever; with it the join sees a failed (not-done) child and the parent times out / escalates
    instead of hanging invisibly."""
    cp = dict(base or {})
    cp.update({"version": checkpoint.CHECKPOINT_VERSION, "stopped": "error", "pending_node": None,
               "child_error": reason, "flow_path": cp.get("flow_path", ""),
               "flow_hash": cp.get("flow_hash", ""), "state": cp.get("state", {}),
               "path": cp.get("path", [])})
    os.makedirs(os.path.dirname(child_ckpt_path), exist_ok=True)
    _atomic_write(child_ckpt_path, json.dumps(cp, indent=2))
    return cp


def _advance_child(child_ckpt_path: str, child_flow: str, agent, item, iid: str,
                   router=None) -> dict:
    """Idempotently bring one child forward by one attempt and return its checkpoint dict.

    - no checkpoint yet   -> run_durable from a fresh state seeded with `_item` (its payload)
    - stable (terminal / needs_human / waiting / error / …) -> leave as-is (a needs_human/waiting child
      isn't done, so the parent join stays open; it resolves through its own resume path)
    - crashed / mid-run   -> resume (re-enter the pending node)

    A child that runs but cannot PERSIST a stable state is recorded as `error` rather than resumed
    endlessly (a non-converging / non-serializable child must not spin the scan forever)."""
    if os.path.exists(child_ckpt_path):
        cp = load_checkpoint(child_ckpt_path)
        if cp.get("stopped") in _STABLE:
            return cp
        resume(child_ckpt_path, agent, router=router)      # crashed/mid-run -> re-enter
        cp = load_checkpoint(child_ckpt_path)
        return cp if cp.get("stopped") in _STABLE else _mark_child_error(
            child_ckpt_path, cp, "child did not reach a stable state on resume")
    os.makedirs(os.path.dirname(child_ckpt_path), exist_ok=True)
    seed = {"transcript": [], "visits": {}, "_item": item, "_item_id": iid}
    res = run_durable(child_flow, agent, child_ckpt_path, router=router, state=seed)
    cp = load_checkpoint(child_ckpt_path) if os.path.exists(child_ckpt_path) else {}
    if cp.get("stopped") in _STABLE:
        return cp
    return _mark_child_error(child_ckpt_path, {"path": list(res.path)},
                             "child state not checkpointable")


def _child_done(child_cp: dict, gate: Optional[str]) -> bool:
    """A child counts as done for the join iff it reached a terminal node — and, when the spec names a
    `gate` field, its terminal outcome carries that field truthy (a successful, not merely finished,
    child)."""
    if child_cp.get("stopped") != "terminal":
        return False
    if not gate:
        return True
    outcomes = (child_cp.get("state") or {}).get("_outcomes", {})
    return any(bool(o.get(gate)) for o in outcomes.values())


# --- join policy ----------------------------------------------------------------------
import math


def _quorum_threshold(join: str, n: int) -> int:
    """The number of done children a `quorum:X` join requires. X is an integer count (`quorum:2`) or a
    fraction of N (`quorum:0.6` -> ceil(0.6*N)). Clamped to [1, n]; a malformed X falls back to N (i.e.
    behaves like all_done rather than firing early on a typo)."""
    _, _, spec = join.partition(":")
    spec = spec.strip()
    try:
        v = float(spec)
    except ValueError:
        return n
    k = math.ceil(v * n) if 0 < v < 1 else int(v)
    return max(1, min(n, k))


def _join_event(spec: dict, done_flags: List[bool]) -> Optional[str]:
    """Given each child's done-ness, return the join EVENT NAME to deliver, or None (not ready yet).
    The event name matches the join family so the parent's `on event <name>` edge is unambiguous:
      * `all_done` (default) -> every child done             -> 'all_done'
      * `any`                -> at least one child done        -> 'any'
      * `quorum:k` / `quorum:frac` -> >= threshold done        -> 'quorum'
    Stragglers are never cancelled: once the threshold fires and the parent resumes, unfinished children
    are simply left as durable checkpoints (the aggregation still reports them)."""
    if not done_flags:
        return None
    join = (spec.get("join") or "all_done").strip()
    n, n_done = len(done_flags), sum(1 for d in done_flags if d)
    name = predicates.spawn_join_event(join)             # shared with analysis.py — never drifts
    if name == "any":
        return name if n_done >= 1 else None
    if name == "quorum":
        return name if n_done >= _quorum_threshold(join, n) else None
    return name if all(done_flags) else None             # all_done (and any unrecognized policy)


# --- aggregation + parent resume ------------------------------------------------------
def _aggregate(children: List[dict], gate: Optional[str] = None) -> dict:
    """Fold the children's state into a JSON summary the parent's post-join node reads from
    parent_state['_spawned'][node]. `done` uses the SAME success criterion as the join (terminal, and
    gate-truthy when a `gate` is set), so the parent's view can't disagree with the join decision;
    `terminal` is the raw reached-a-terminal count, kept alongside for reference."""
    kids = []
    for iid, cp in children:
        state = cp.get("state") or {}
        kids.append({
            "item_id": iid,
            "stopped": cp.get("stopped"),
            "path": cp.get("path"),
            "outcomes": state.get("_outcomes", {}),
        })
    done = sum(1 for _, cp in children if _child_done(cp, gate))
    terminal = sum(1 for _, cp in children if cp.get("stopped") == "terminal")
    return {"children": kids, "n": len(kids), "done": done, "terminal": terminal}


def _inject_and_resume(parent_ckpt_path: str, node: str, agg: dict, event: str, agent,
                       router=None, human_floor: Optional[float] = None):
    """Write the aggregation into the parent checkpoint's state (so the resumed post-join node can read
    it) and deliver the join event — atomically ordered: state first, then resume."""
    cp = load_checkpoint(parent_ckpt_path)
    state = cp.setdefault("state", {})
    state.setdefault("_spawned", {})[node] = agg
    _atomic_write(parent_ckpt_path, json.dumps(cp, indent=2))
    return resume(parent_ckpt_path, agent, router=router, event=event, human_floor=human_floor)


def _effective_spec(cp: dict, node: str, spec: dict):
    """Reconcile the runtime worker `spec` with the fan-out node's `@spawn` ANNOTATION. The annotation
    (the DOCUMENT) is authoritative for control STRUCTURE — child flow, join policy, item_id field,
    gate — so exactly what the static analyzer and lockfile checked is what runs: no annotation/runtime
    drift (the deadlock hole where a worker's `join` diverges from the declared one). The worker supplies
    only the runtime ITEM LIST — `spec['items']`/`spec['item']`, or, when the annotation names
    `over=<state-key>`, the list at parent_state[over]. Returns (effective_spec, parsed_graph_or_None)."""
    from prismpath.parser import parse_file
    eff = dict(spec or {})
    graph, ann = None, None
    try:
        graph = parse_file(cp.get("flow_path", ""))
        n = graph.nodes.get(node) if node else None
        ann = n.annotations.get("spawn") if n else None
    except Exception:                                    # noqa: BLE001 - degrade to the runtime spec
        pass
    if ann:
        for k in ("child", "join", "item_id", "gate"):
            if ann.get(k) is not None:
                eff[k] = ann[k]
        over = ann.get("over")
        if "items" not in eff and "item" not in eff and over:
            items = (cp.get("state") or {}).get(over)
            if isinstance(items, list):
                eff["items"] = items
    return eff, graph


# --- the scan (mirrors scheduler.fire_due_timeouts) -----------------------------------
def advance_fanout(parent_ckpt_path: str, agent, router=None,
                   human_floor: Optional[float] = None) -> dict:
    """Advance ONE fan-out parent: spawn/poll its children (driving any nested sub-fan-outs), and if the
    join is ready, aggregate + resume the parent. Returns a record: {path, node, spawned, done,
    joined(bool), event, result?}."""
    cp = load_checkpoint(parent_ckpt_path)
    pend = cp.get("pending_decision") or {}
    spec = pend.get("spawn")
    node = pend.get("node") or cp.get("pending_node")
    # NB: `spawn: {}` is a VALID spec (the @spawn annotation supplies child/join/items via `over`),
    # so the guard is `is None`, not falsiness.
    if cp.get("stopped") != "waiting" or spec is None:
        return {"path": parent_ckpt_path, "node": node, "spawned": 0, "joined": False,
                "skipped": "not a waiting fan-out"}
    spec, graph = _effective_spec(cp, node, spec)        # annotation is authoritative for structure
    child_flow = _resolve_child_flow(cp.get("flow_path", ""), spec.get("child", ""))
    gate = spec.get("gate")
    idfield = spec.get("item_id")

    children, done_flags = [], []
    for item in _items(spec):
        iid = item_id(item, idfield)
        cpath = _child_ckpt_path(parent_ckpt_path, iid)
        ccp = _advance_child(cpath, child_flow, agent, item, iid, router=router)
        # NESTED composition: a child that is itself a waiting fan-out — drive its whole subtree now
        # (depth-first), so composition works to any depth, not just one level.
        if ccp.get("stopped") == "waiting" and (ccp.get("pending_decision") or {}).get("spawn") is not None:
            advance_fanout(cpath, agent, router=router, human_floor=human_floor)
            ccp = load_checkpoint(cpath)
        children.append((iid, ccp))
        done_flags.append(_child_done(ccp, gate))

    rec = {"path": parent_ckpt_path, "node": node, "spawned": len(children),
           "done": sum(done_flags), "joined": False, "event": None}
    event = _join_event(spec, done_flags)
    if event is not None:
        # The join event MUST have a matching edge, or resume() would raise and we'd strand a partial
        # aggregation on a deadlocked run. Guard here and record a clean error instead (analysis.py
        # flags this statically as spawn-no-join-edge when the join is declared in the annotation).
        edges = graph.nodes[node].edges if (graph and node in graph.nodes) else []
        have = {predicates.event_name(c) for _, c in edges if predicates.is_event(c)}
        if event not in have:
            rec["error"] = f"join fired {event!r} but node {node!r} has no `on event {event}` edge"
            return rec
        res = _inject_and_resume(parent_ckpt_path, node, _aggregate(children, gate), event, agent,
                                 router=router, human_floor=human_floor)
        rec.update(joined=True, event=event, result=res)
    return rec


def advance_fanouts(agent, qdir: Optional[str] = None, router=None,
                    human_floor: Optional[float] = None) -> List[dict]:
    """Scan a queue dir once and advance every `waiting` parent that carries a `spawn` spec. Returns
    one record per fan-out touched. Restartable and idempotent: re-scanning re-attaches to existing
    children (deterministic ids) rather than re-spawning, and only resumes a parent whose join is
    ready. Non-fan-out checkpoints are ignored."""
    qdir = qdir or checkpoint.queue_dir()
    out: List[dict] = []
    for path in sorted(glob.glob(os.path.join(qdir, "*.json"))):
        if not os.path.isfile(path):
            continue
        try:
            cp = load_checkpoint(path)
        except Exception:
            continue                                  # not a checkpoint / unreadable — skip
        if cp.get("stopped") != "waiting" or (cp.get("pending_decision") or {}).get("spawn") is None:
            continue
        try:
            out.append(advance_fanout(path, agent, router=router, human_floor=human_floor))
        except Exception as e:                        # noqa: BLE001 - one malformed fan-out (e.g. a
            # missing `on event` join edge — caught statically by analysis.py) must not abort the whole
            # scan; record it and move on, like scheduler.fire_due_timeouts skips bad checkpoints.
            out.append({"path": path, "error": repr(e), "joined": False})
    return out
