"""routelog.py — a durable log of routing decisions (Sprint 0), and a labeling workbench.

Every semantic-tier routing decision a run makes can be appended to a JSONL file: the outcome, the
candidate edges with their scores, the margin, what was chosen, whether it escalated. That log is
the raw material for calibrating the escalation threshold (Area 1) and for growing the benchmark
(Area 4) from *real* runs rather than only synthetic cases. The engine stays pure — it emits each
record through the `on_decision` callback; this module supplies the sink and the workbench.

  run_logged(graph, agent, "routes.jsonl")   # run, appending a record per semantic decision
  # then hand-label the unlabeled records:
  python -m prismpath.cli label routes.jsonl

A record (see engine.run) has: run_id, flow, node, outcome_text, outcome_fields, candidates
[{target, condition, score}], top1, top2, margin, chosen, mechanism, escalated, llm_choice, label,
label_source. `label` is filled in later by a human (or `flow_test`), turning a run into training
data.
"""
from __future__ import annotations

import json
import os
from typing import Callable, List, Optional


def jsonl_sink(path) -> Callable[[dict], None]:
    """Return an `on_decision` callback that appends each routing record to `path` (JSONL)."""
    path = os.fspath(path)

    def sink(record: dict) -> None:
        d = os.path.dirname(os.path.abspath(path))
        if d:
            os.makedirs(d, exist_ok=True)
        with open(path, "a") as f:
            f.write(json.dumps(record) + "\n")
    return sink


def run_logged(graph, agent, log_path, router=None, run_id: Optional[str] = None, **kw):
    """Run a flow while appending a routing-decision record per semantic decision. Extra kwargs pass
    through to engine.run."""
    from prismpath.engine import run
    return run(graph, agent, router=router, on_decision=jsonl_sink(log_path), run_id=run_id, **kw)


def load_records(path) -> List[dict]:
    out = []
    if not os.path.exists(path):
        return out
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    return out


def save_records(path, records: List[dict]) -> None:
    tmp = os.fspath(path) + ".tmp"
    with open(tmp, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    os.replace(tmp, os.fspath(path))


def label_records(records: List[dict], ask: Callable[[dict, List[str]], Optional[str]],
                  source: str = "human") -> int:
    """Fill in `label` for every unlabeled record by calling `ask(record, candidate_targets)` — which
    returns the chosen edge target, or None to skip. Returns the count newly labeled. Pure and
    testable; the CLI supplies an interactive `ask`."""
    n = 0
    for r in records:
        if r.get("label"):
            continue
        targets = [c.get("target") for c in r.get("candidates", [])]
        choice = ask(r, targets)
        if choice in targets:
            r["label"] = choice
            r["label_source"] = source
            n += 1
    return n


def label_stats(records: List[dict]) -> dict:
    labeled = sum(1 for r in records if r.get("label"))
    correct = sum(1 for r in records if r.get("label") and r.get("label") == r.get("chosen"))
    return {"total": len(records), "labeled": labeled, "unlabeled": len(records) - labeled,
            "router_correct_on_labeled": correct}
