# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
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
from prismpath import canon

def jsonl_sink(path) -> Callable[[dict], None]:
    """Return an `on_decision` callback that appends each routing record to `path` (JSONL)."""
    path = os.fspath(path)

    def sink(record: dict) -> None:
        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(path, "a") as handle:
            handle.write(json.dumps(record) + "\n")
    return sink


def run_logged(graph, agent, log_path, router=None, run_id: Optional[str] = None, **kw):
    """Run a flow while appending a routing-decision record per semantic decision. Extra kwargs pass
    through to engine.run."""
    from prismpath.kernel.engine import run
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
    canon.atomic_write(path, "".join(json.dumps(routing_record) + "\n" for routing_record in records))


def label_records(records: List[dict], ask: Callable[[dict, List[str]], Optional[str]],
                  source: str = "human") -> int:
    """Fill in `label` for every unlabeled record by calling `ask(record, candidate_targets)` — which
    returns the chosen edge target, or None to skip. Returns the count newly labeled. Pure and
    testable; the CLI supplies an interactive `ask`."""
    labeled_count = 0
    for routing_record in records:
        if routing_record.get("label"):
            continue
        targets = [candidate.get("target") for candidate in routing_record.get("candidates", [])]
        choice = ask(routing_record, targets)
        if choice in targets:
            routing_record["label"] = choice
            routing_record["label_source"] = source
            labeled_count += 1
    return labeled_count


def label_stats(records: List[dict]) -> dict:
    labeled = sum(1 for routing_record in records if routing_record.get("label"))
    correct = sum(1 for routing_record in records
                  if routing_record.get("label")
                  and routing_record.get("label") == routing_record.get("chosen"))
    return {"total": len(records), "labeled": labeled, "unlabeled": len(records) - labeled,
            "router_correct_on_labeled": correct}
