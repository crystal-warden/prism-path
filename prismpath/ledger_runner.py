"""ledger_runner.py — drive a routing flow as a per-item loop with a git proof per item (Slice 2).

The sprint control plane (run_sprint.py) already has a gate-green seam to hang the Flow-Ledger on.
A *routing* flow (SOC triage, ticket queues) doesn't — it runs `engine.run` once per item and
edits no code. This runner gives those flows the same durable-proof + resume story:

  * A flow marks ONE node with `@checkpoint(unit=<state-key>, proof=<state-key>, gate=<field>)` —
    the node whose success means "this item is fully handled." `unit` is the ITEM id (an alert /
    ticket id from runtime state, NOT the node name, which collides across items); `proof` is the
    produced artifact to content-hash; `gate` (optional) is an outcome field that must be truthy.
  * `run_ledgered_loop` runs the flow once per item; when the checkpoint node is reached (and its
    gate is green) it writes one proof-commit for that item.
  * RESUME-FROM-LEDGER: each pass seeds `state['_done_units']` from `ledger.done_set()`, so the
    flow's own `observe`/`fetch` node skips items already proven in git. A run stopped mid-stream
    restarts at the first item with no green commit — no separate processed-list to keep in sync.

`upsert_jsonl` makes a side-effecting handler idempotent so a replayed item doesn't double-append.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from prismpath.engine import run
from prismpath.ledger import LedgerError, sha256_files
from prismpath.parser import parse_file


def find_checkpoint(graph):
    """Return (node_name, annotation_args) for the flow's single @checkpoint node, or (None, None)."""
    for name, n in graph.nodes.items():
        if "checkpoint" in n.annotations:
            return name, n.annotations["checkpoint"]
    return None, None


def _resolve(key: Optional[str], state: dict):
    """Read a dotted path out of state, e.g. 'alert.id' -> state['alert']['id']. None if absent."""
    if not key:
        return None
    cur = state
    for part in key.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _outcome_field(state: dict, node: str, field: str):
    return (state.get("_outcomes", {}).get(node) or {}).get(field)


def _to_bytes(v) -> bytes:
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    if isinstance(v, str):
        return v.encode()
    return json.dumps(v, sort_keys=True, default=str).encode()


def run_ledgered_loop(flow_path, agent, ledger, *, router=None, max_items: int = 1000,
                      max_steps: int = 25) -> List[str]:
    """Run `flow_path` once per item, committing a proof at its @checkpoint node. Returns the list
    of item ids committed this call. Resumes from the ledger: already-proven items are skipped."""
    graph = parse_file(flow_path)
    cp_node, ann = find_checkpoint(graph)
    if cp_node is None:
        raise LedgerError("flow has no @checkpoint node; cannot ledger a routing flow")
    unit_key = ann.get("unit")
    if not unit_key:
        raise LedgerError("@checkpoint requires a `unit=<state-key>` naming the item id")
    proof_key = ann.get("proof")
    gate_field = ann.get("gate")

    committed: List[str] = []
    blocked: set = set()                             # items that reached the checkpoint gate-red this run
    for _ in range(max_items):
        done = ledger.done_set()
        # skip both proven items AND items that gate-failed earlier this run, so one red item can't
        # head-of-line-block the whole queue (it's retried on a *later* run, not re-fetched forever).
        seed = {"transcript": [], "visits": {}, "_done_units": set(done) | blocked}
        res = run(graph, agent, router=router, state=seed, max_steps=max_steps)

        if cp_node not in res.path:
            break                                    # idle/terminal without a checkpoint -> done
        unit = _resolve(unit_key, res.state)
        if unit is None:
            break                                    # checkpoint reached but no item id -> stop safely
        unit = str(unit)
        if unit in done or unit in blocked:
            break                                    # observe failed to skip -> avoid a spin
        if gate_field is not None and not _outcome_field(res.state, cp_node, gate_field):
            blocked.add(unit)                        # gate red: skip THIS item, keep draining the queue
            continue

        proof_val = _resolve(proof_key, res.state) if proof_key else _outcome_field(res.state, cp_node, "text")
        # the checkpoint node's chosen out-edge (not the run's last step, which may be downstream)
        cp_step = next((s for s in reversed(res.steps) if s.node == cp_node), None)
        files = {f"{unit}.proof": _to_bytes(proof_val)} if proof_val is not None else {}
        ledger.commit_unit(unit, node=cp_node, gate="green", gate_name=(gate_field or cp_node),
                           files=files, edge=(cp_step.target if cp_step else None))
        committed.append(unit)
    return committed


def upsert_jsonl(path, record: dict, key) -> bool:
    """Append `record` to a JSONL file only if no existing record matches on the `key` field(s).
    Makes an append-based side effect idempotent under replay. Returns True if it wrote a new line."""
    keys = [key] if isinstance(key, str) else list(key)
    kv = tuple(record.get(k) for k in keys)
    p = Path(path)
    if p.exists():
        for line in p.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if tuple(r.get(k) for k in keys) == kv:
                return False
    with open(p, "a") as f:
        f.write(json.dumps(record) + "\n")
    return True
