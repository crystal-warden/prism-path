# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The glass lens over interactions.jsonl: who said what to which model, and what the run retrieved.

Two views of the same artifact the run appends to as it works. `interactions` labels each recorded
call with its sender, its receiver and the substage it belongs to; `retrievals` reads the same file
for the Retrieval port's side of it.
"""
import json
import os

try:
    from prismpath.orchestration.swarm_exporter import _fold                # reuse the prompt/output folder
except Exception:                                             # pragma: no cover
    from swarm_exporter import _fold

from .status import status

def _worker_label(event):
    """Who answered a call, as the record says: its `model` field when the producer wrote one, else its
    `worker`, else the kind of call it was. The console names no model of its own."""
    for key in ("model", "worker"):
        value = event.get(key)
        if isinstance(value, str) and value:
            return value
    return event.get("kind") or "?"


def _dialogue(event):
    """Derive (sender, receiver, substage): who sent the message and who received it, from the record's
    own `role`, `kind` and `model` fields, situated in propose->accept->build->test.

    This is the console's own sense of a message's path, not the dictionary's `route` (choosing an edge).
    """
    kind, role, prompt = event.get("kind"), event.get("role", ""), event.get("prompt", "")
    receiver = _worker_label(event)
    if kind == "retriever":
        return role or "retriever", receiver, "retrieve"
    if kind == "cecli":
        return f"cecli·{role}", receiver, role
    sub = role
    if "Vote for the SINGLE best" in prompt:
        sub = "vote"
    elif "propose THE single highest" in prompt or "\nACTION:" in prompt:
        sub = "propose"
    return role or kind or "?", receiver, sub


def interactions(state, limit=300):
    """The last `limit` recorded calls, folded for display, with the status summary they belong to."""
    proj = state["proj"]
    path = os.path.join(proj, "interactions.jsonl")
    events = []
    if os.path.isfile(path):
        for ln in open(path, errors="ignore").read().splitlines()[-limit:]:
            try:
                event = json.loads(ln)
            except Exception:
                continue
            folded_prompt, folded_output = _fold(event.get("prompt", "")), _fold(event.get("output", ""),
                                                                    head=0, tail=2200)
            sender, receiver, sub = _dialogue(event)
            events.append({"ts": event.get("ts"), "kind": event.get("kind", "?"),
                           "role": event.get("role", ""),
                           "phase": event.get("phase", ""), "dur_ms": event.get("dur_ms", 0),
                           "from": sender, "to": receiver, "substage": sub, "rc": event.get("rc"),
                           "prompt_len": event.get("prompt_len", 0),
                           "output_len": event.get("output_len", 0),
                           "prompt": folded_prompt["preview"], "output": folded_output["preview"]})
    return {"summary": status(state), "events": events}


def retrievals(state, limit=200):
    """Observe the Retrieval port: which RAG chunks a run pulled, per turn. Reads the recorded
    `phase="retrieve"` interactions; surfaces structured hits (`hits_meta`: source/path/score) when the
    producer emitted them, else the count. Empty/degraded cleanly when a run used no RAG."""
    proj = state["proj"]
    path = os.path.join(proj, "interactions.jsonl")
    out = []
    if os.path.isfile(path):
        for ln in open(path, errors="ignore").read().splitlines():
            try:
                event = json.loads(ln)
            except Exception:
                continue
            if event.get("kind") != "retriever" and event.get("phase") != "retrieve":
                continue
            out.append({"ts": event.get("ts"), "query": (event.get("prompt") or "")[:300],
                        "n": event.get("hits", len(event.get("hits_meta", []) or [])),
                        "hits": event.get("hits_meta", [])})
    return {"retrievals": out[-limit:]}
