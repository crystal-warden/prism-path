"""adapter.py — run Lindquist's `mdflow` tasks as PrismPath worker nodes.

Thin layer over `prismpath.cli_worker`, specialized to mdflow's documented machine-facing
contract (Flow UX Protocol v1, github.com/johnlindquist/mdflow, MIT):

  `mdflow <task.<engine>.md> --json`  ->  one JSON object
      {"exitCode": int, "command": str, "args": [...], "stdout": str, "stderr": str}

The generic CliWorker treats a program's *own* stdout as the outcome; mdflow's `--json`
instead ENVELOPES the engine result, so this adapter unwraps it: the engine's `stdout` becomes
the PrismPath outcome text, a nonzero `exitCode` raises onto the error tier, and if the engine's
stdout is itself a JSON object its fields feed `when` predicates directly. That envelope-unwrap
is the whole difference between "any CLI as a worker" and "an mdflow task as a worker."

Honesty boundary: validated against `mock_mdflow.py`, a stub that reproduces this documented
`--json` envelope — not the real binary (which invokes real engine CLIs needing keys + network).
Validating against the real `mdflow` is the open item.
"""
from __future__ import annotations

import json
from typing import Dict, Sequence

from prismpath.cli_worker import CliWorker, CliWorkerError


class MdflowError(CliWorkerError):
    """An mdflow task reported a nonzero exitCode (or unparseable envelope) — routes on the error tier."""


def _unwrap(envelope_text: str):
    """mdflow --json envelope -> PrismPath outcome. Raises MdflowError on a failed task."""
    try:
        env = json.loads(envelope_text)
    except json.JSONDecodeError as e:
        raise MdflowError(f"mdflow did not return a JSON envelope: {e}")
    if not isinstance(env, dict) or "exitCode" not in env:
        raise MdflowError(f"unexpected mdflow envelope: {envelope_text[:200]}")
    if env["exitCode"] != 0:
        tail = (env.get("stderr") or "").strip()[-400:]
        raise MdflowError(f"mdflow task exit {env['exitCode']}: {tail}")
    out = (env.get("stdout") or "").strip()
    try:                                    # engine emitted structured fields -> feed predicates
        fields = json.loads(out)
        if isinstance(fields, dict):
            fields.setdefault("text", out)
            return fields
    except json.JSONDecodeError:
        pass
    return out                              # plain engine text -> semantic-routing outcome text


def mdflow_agent(task_map: Dict[str, Sequence[str]], **kw):
    """Engine-ready agent mapping PrismPath nodes -> `mdflow <task> --json` invocations.

    task_map: {node_name: argv} where argv runs mdflow with a task and `--json`, e.g.
        {"draft": ["mdflow", "flows/draft.claude.md", "--json"]}
    (tests pass the mock binary in place of `mdflow`). Returns (node, instruction, state) -> outcome.
    """
    workers = {n: CliWorker(cmd, **kw) for n, cmd in task_map.items()}

    def agent(node: str, instruction: str, state: dict):
        w = workers.get(node)
        if w is None:
            raise MdflowError(f"no mdflow task mapped for node {node!r}")
        raw = w(node, instruction, state)               # CliWorker returns text or dict
        text = raw if isinstance(raw, str) else json.dumps(raw)
        return _unwrap(text)
    return agent
