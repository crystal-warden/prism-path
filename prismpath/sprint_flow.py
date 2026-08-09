"""sprint_flow.py — the sprint loop AS A FLOW (roadmap item #6, the dogfood).

`run_sprint.py`'s inner loop — pick unit, execute, gate, retry ×3, escalate — was a fixed
Python loop orchestrating prismpath. This module runs the SAME loop as `flows/sprint_loop.md`:
gates route on deterministic fields, the 3×-same-error rule is an `on error when
error_count >= …` edge, escalation is an ordinary `needs_human` suspension, and every
gate-green unit is a `@checkpoint` proof-commit in the git Flow-Ledger. The control plane
that builds prismpath is itself an prismpath flow — the credibility argument, self-demonstrating.

The concrete work (what "pick"/"build"/"gate"/"fix"/"escalate" DO) stays out of the flow, in
a `SprintSeams` bundle of callables over the run state:

    seams = SprintSeams(pick=..., build=..., gate=..., fix=..., escalate=...)
    committed = run_sprint_flow(seams, ledger=Ledger("sprint", run_id))

`run_sprint.py` builds its seams from its existing machinery (kg_next,
cecli_build/build, validate_fn, help_escalate) behind SPRINT_FLOW=1 — same behavior, but the
loop's SEMANTICS now live in the document, inspectable by `prismpath validate`/`graph` like any
other flow, while the wall-clock / pause / heartbeat machinery stays in the driver where
harness concerns belong.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

from prismpath.ledger_runner import run_ledgered_loop

DEFAULT_FLOW = str(Path(__file__).parent / "flows" / "sprint_loop.md")


class GateRed(Exception):
    """The deterministic gate failed. Raised by the gate seam so retries ride the flow's ERROR
    tier — `on error when error_count < 3` -> fix, else escalate — instead of driver code."""


@dataclass
class SprintSeams:
    """The five operations the sprint flow orchestrates. Each takes the RUN STATE dict and
    returns the node's outcome fields (or raises, for `gate` on red).

      pick(state)     -> {"done": bool, ...} — choose the next unit; MUST set
                         state["unit"] = {"id": <stable unit id>} when not done (the
                         @checkpoint annotation reads `unit.id` for the ledger proof) and put
                         instruction/target into its outcome for `build` to read.
      build(state)    -> executes the unit's instruction against the real tree.
      gate(state)     -> {"gate_green": True, ...} on green — and SHOULD set
                         state["gate_report"] (the @checkpoint proof); raises GateRed on red.
      fix(state)      -> smallest change to satisfy the gate (reads the last error from
                         state["transcript"]).
      escalate(state) -> out-of-band escalation (write HELP.md etc.); its outcome is
                         auto-suspended: needs_human is set for it if it doesn't set one.
    """
    pick: Callable[[dict], dict]
    build: Callable[[dict], dict]
    gate: Callable[[dict], dict]
    fix: Callable[[dict], dict]
    escalate: Callable[[dict], dict]


def make_agent(seams: SprintSeams):
    """The flow worker: dispatch each sprint_loop.md node to its seam. Terminal narration nodes
    (proved/abandon/done_sprint) answer inline."""
    def agent(node: str, instruction: str, state: dict):
        if node == "pick_unit":
            return seams.pick(state)
        if node == "build":
            return seams.build(state)
        if node == "gate":
            return seams.gate(state)
        if node == "fix":
            return seams.fix(state)
        if node == "escalate":
            out = seams.escalate(state)
            out = dict(out) if isinstance(out, dict) else {"text": str(out)}
            out.setdefault("needs_human", True)      # escalation always suspends for a supervisor
            out.setdefault("reason", "gate failed 3x on this unit")
            return out
        return {"text": node}
    return agent


def run_sprint_flow(seams: SprintSeams, ledger=None, flow_path: Optional[str] = None,
                    router=None, max_items: int = 1000, max_steps: int = 40) -> List[str]:
    """Drive the sprint as a per-unit ledgered loop over flows/sprint_loop.md: each pass runs
    the flow once (pick -> build -> gate[-> fix ...]) and, when the gate node goes green, the
    runner writes ONE proof-commit for that unit. Already-proven units are skipped via the
    ledger's done-set (resume-from-git). Returns the unit ids committed this call.

    Without a ledger, falls back to a throwaway one under $XDG_STATE_HOME (proofs still
    recorded, just not wired to a named run)."""
    if ledger is None:
        from prismpath.ledger import Ledger, new_run_id
        ledger = Ledger(flow="sprint_loop", run_id=new_run_id())
    return run_ledgered_loop(flow_path or DEFAULT_FLOW, make_agent(seams), ledger,
                             router=router, max_items=max_items, max_steps=max_steps)
