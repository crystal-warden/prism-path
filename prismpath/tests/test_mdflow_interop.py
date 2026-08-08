"""mdflow interop — the paper's "composes naturally as a node's worker" claim, gated.

Related Work (paper §2) says a task-level Markdown runner like Lindquist's `mdflow` "can serve
as a node's worker through the generic CLI-worker contract ... while our system routes between
tasks by outcome." This test enforces that claim end-to-end: a PrismPath flow routes BETWEEN
mdflow tasks, each task run as a CLI worker, with the task's stdout JSON feeding `when`
predicates and a task's nonzero exit landing on the error tier.

Honesty boundary: the worker here is `mock_mdflow.py`, a stub reconstructed from mdflow's
DOCUMENTED contract (see examples/mdflow_interop/README.md), not the real binary. This gates the
*mechanism*; validation against the real tool is the open item (and the reason for the outreach).
"""
import os
import sys

import pytest

from prismpath.parser import parse_file
from prismpath.engine import run
from prismpath.cli_worker import cli_agent

HERE = os.path.dirname(__file__)
EX = os.path.abspath(os.path.join(HERE, "..", "examples", "mdflow_interop"))
MOCK = os.path.join(EX, "mock_mdflow.py")
TASKS = os.path.join(EX, "tasks")


def _agent():
    # per-node commands: each PrismPath node's worker is an mdflow task run through the CLI seam
    return cli_agent({
        "draft":  [sys.executable, MOCK, os.path.join(TASKS, "draft.md")],
        "review": [sys.executable, MOCK, os.path.join(TASKS, "review.md")],
        "revise": [sys.executable, MOCK, os.path.join(TASKS, "flaky.md")],
    })


def test_mock_mdflow_contract_directly():
    """The stub honors the contract PrismPath's CliWorker expects: JSON stdout, exit codes."""
    import subprocess
    ok = subprocess.run([sys.executable, MOCK, os.path.join(TASKS, "draft.md")],
                        input="", capture_output=True, text=True)
    assert ok.returncode == 0
    import json
    out = json.loads(ok.stdout)
    assert out["drafted"] is True and out["text"]
    fail = subprocess.run([sys.executable, MOCK, os.path.join(TASKS, "flaky.md")],
                          input="", capture_output=True, text=True)
    assert fail.returncode != 0 and "failed" in fail.stderr


def test_flow_routes_between_mdflow_tasks():
    """A PrismPath flow routes BETWEEN mdflow-task workers on the fields they emit."""
    graph = parse_file(os.path.join(EX, "pipeline.md"))
    res = run(graph, _agent(), max_steps=10)
    # draft (drafted=true) -> review (approved=true) -> done, all decided by task-emitted fields
    assert res.path == ["draft", "review", "done"]
    assert res.stopped == "terminal"


def test_mdflow_task_failure_rides_the_error_tier():
    """A task's nonzero exit becomes routable as an error edge, per the CLI-worker contract."""
    # force the path through `revise` (the flaky task) by making review withhold approval
    graph = parse_file(os.path.join(EX, "pipeline.md"))
    # a review task that does NOT approve, so routing reaches `revise` (the failing task)
    noapprove = os.path.join(TASKS, "review_noapprove.md")
    with open(noapprove, "w", encoding="utf-8") as f:
        f.write("---\nname: review\nmock_text: needs work\nmock_approved: false\n---\nreview\n")
    try:
        agent = cli_agent({
            "draft":  [sys.executable, MOCK, os.path.join(TASKS, "draft.md")],
            "review": [sys.executable, MOCK, noapprove],
            "revise": [sys.executable, MOCK, os.path.join(TASKS, "flaky.md")],
        })
        res = run(graph, agent, max_steps=12)
        # revise's task fails -> error tier: `-> draft: on error when error_count < 2` loops,
        # then `-> abandoned: on error` — the failure is handled as document-level edges
        assert "revise" in res.path
        assert res.path[-1] == "abandoned"
        assert res.stopped == "terminal"
    finally:
        os.remove(noapprove)
