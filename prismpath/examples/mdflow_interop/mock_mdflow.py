#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""mock_mdflow.py — a stand-in for Lindquist's `mdflow` task runner, for interop testing ONLY.

This is NOT mdflow. It is a small deterministic stub that mimics mdflow's *documented* CLI
contract (a single Markdown task: YAML frontmatter selecting an engine + flags, prose as the
prompt; run it, emit the result) so PrismPath's CLI-worker seam can be exercised end-to-end
without the real binary and without an LLM. It exists so `test_mdflow_interop.py` can GATE the
claim "an mdflow task composes as a PrismPath worker node" instead of merely asserting it.

Contract reconstructed from the public description (see README.md) — pending confirmation from
the real tool:
  usage: mock_mdflow.py <task.md>
  stdin: the caller's prompt + JSON context (PrismPath sends the node instruction here)
  stdout: JSON object {"text": ..., <fields>...}  ->  PrismPath's DICT outcome
  exit:   0 on success; nonzero on failure (rides PrismPath's error tier)

The stub "runs" a task by reading a `mock:` block in the task's frontmatter that declares the
outcome to emit — deterministic, no model — so tests are reproducible.
"""
from __future__ import annotations

import json
import sys


def _parse_frontmatter(text: str) -> dict:
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end == -1:
        return {}
    fm = {}
    for line in text[3:end].splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            fm[k.strip()] = v.strip()
    return fm


def main() -> int:
    if len(sys.argv) != 2:
        sys.stderr.write("usage: mock_mdflow.py <task.md>\n")
        return 2
    try:
        text = open(sys.argv[1], encoding="utf-8").read()
    except OSError as e:
        sys.stderr.write(f"mock_mdflow: cannot read task: {e}\n")
        return 2
    fm = _parse_frontmatter(text)
    _ = sys.stdin.read()                       # PrismPath's prompt+context arrives here; ignored by the stub

    # `mock_fail: true` -> exit nonzero (exercises the error tier). Otherwise emit the declared
    # outcome fields: every `mock_*` frontmatter key becomes an outcome field (minus the prefix),
    # with a couple of type coercions so `when` predicates see real bools/ints.
    if fm.get("mock_fail", "").lower() == "true":
        sys.stderr.write(f"mock_mdflow: task '{fm.get('name', '?')}' failed as declared\n")
        return 1
    outcome = {"text": fm.get("mock_text", fm.get("name", "done"))}
    for k, v in fm.items():
        if not k.startswith("mock_") or k in ("mock_text", "mock_fail"):
            continue
        field = k[len("mock_"):]
        if v.lower() in ("true", "false"):
            outcome[field] = v.lower() == "true"
        elif v.lstrip("-").isdigit():
            outcome[field] = int(v)
        else:
            outcome[field] = v
    sys.stdout.write(json.dumps(outcome))
    return 0


if __name__ == "__main__":
    sys.exit(main())
