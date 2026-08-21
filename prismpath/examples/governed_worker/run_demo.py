# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Governed worker demo: gates decide, claims are advisory, a lying worker is caught.

Three simulated worker runs go through the governed_worker flow. No model, no network, fully
deterministic; the "worker" is a stub whose claim and whose actual gate outcomes we script. The
interesting case is the liar: it claims success while the gates fail, and the flow routes it to
``reject_lie`` where the claim is recorded and nothing merges.

    PYTHONPATH=prismpath/examples/governed_worker \
      python prismpath/examples/governed_worker/run_demo.py

Requires Linux + bwrap (the code-node sandbox). Exits nonzero if any verdict is wrong, so this
demo doubles as its own regression test.
"""
import os
import sys

import worker_handlers  # importable module (dotted path) so the sandbox child can load it

from prismpath.code_nodes import code_agent
from prismpath.engine import run
from prismpath.parser import parse_file
from prismpath.sandbox import SandboxRunner

HERE = os.path.dirname(os.path.abspath(__file__))
FLOW = os.path.join(HERE, "governed_worker.md")

# (label, worker's claim, scripted gate results, expected verdict)
SCENARIOS = [
    ("liar: claims success, gates fail", True,
     [{"cmd": "unit tests", "rc": 1, "tail": "2 failed"}], "reject_lie"),
    ("honest success: claims success, gates pass", True,
     [{"cmd": "unit tests", "rc": 0, "tail": "all passed"}], "accept"),
    ("honest failure: reports failure, gates fail", False,
     [{"cmd": "unit tests", "rc": 1, "tail": "3 failed"}], "reject"),
]


def never(node, instruction, state):
    raise AssertionError(f"non-code node executed: {node}")


def main() -> int:
    graph = parse_file(FLOW)
    agent = code_agent(graph, {"verify": worker_handlers.verify},
                       runner=SandboxRunner(), base=never)
    failures = 0
    for label, claimed, gates, expected in SCENARIOS:
        state = {"claimed_success": claimed, "precomputed_gates": gates,
                 "transcript": [], "visits": {}}
        res = run(graph, agent, state=state)
        verdict = res.path[-1]
        ok = verdict == expected
        failures += 0 if ok else 1
        mark = "ok " if ok else "WRONG"
        print(f"[{mark}] {label:46} -> {' -> '.join(res.path)}")
    if failures:
        print(f"{failures} verdict(s) wrong")
        return 1
    print("all verdicts correct: the gates decided, the claim never routed anything")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
