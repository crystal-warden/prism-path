# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Tests for swarm_runner module."""

import os
import sys
import types
from prismpath.orchestration import swarm_runner


def test_extract_code():
    assert swarm_runner.extract_code("```python\nprint(42)\n```") == "print(42)"
    assert swarm_runner.extract_code("```\nhello\n```") == "hello"
    assert swarm_runner.extract_code("just plain text") == "just plain text"
    assert swarm_runner.extract_code("") == ""


def test_count_helper():
    log = "10 passed, 2 failed, 1 error"
    assert swarm_runner._count(log, r"(\d+) passed") == 10
    assert swarm_runner._count(log, r"(\d+) failed") == 2
    assert swarm_runner._count(log, r"(\d+) missing") == 0


def test_blame_file_idx():
    files = [
        {"name": "alpha", "path": "src/alpha.py"},
        {"name": "beta", "path": "src/beta.py"},
    ]
    err_log = "FAILED src/beta.py::test_something - AssertionError"
    idx = swarm_runner._blame_file_idx(err_log, files, default_idx=1)
    assert idx == 1

    err_log_mention = "Traceback in alpha.py line 42"
    idx2 = swarm_runner._blame_file_idx(err_log_mention, files, default_idx=2)
    assert idx2 == 0

    err_no_match = "Unknown error without filenames"
    idx3 = swarm_runner._blame_file_idx(err_no_match, files, default_idx=2)
    assert idx3 == 1


def test_swarm_endpoint_up(monkeypatch):
    class MockResponse:
        def __init__(self, status_code):
            self.status_code = status_code

    fake_agent_io = types.ModuleType("agent_io")
    fake_agent_io.DEFAULT_BASE = "http://127.0.0.1:8888"
    fake_pipeline = types.ModuleType("pipeline")
    fake_pipeline.agent_io = fake_agent_io

    monkeypatch.setitem(sys.modules, "pipeline", fake_pipeline)
    monkeypatch.setitem(sys.modules, "pipeline.agent_io", fake_agent_io)

    def mock_get_success(url, timeout):
        return MockResponse(200)

    def mock_get_failure(url, timeout):
        raise ConnectionError("connection refused")

    import requests
    monkeypatch.setattr(requests, "get", mock_get_success)
    assert swarm_runner._swarm_endpoint_up("http://127.0.0.1:8888") is True

    monkeypatch.setattr(requests, "get", mock_get_failure)
    assert swarm_runner._swarm_endpoint_up("http://127.0.0.1:8888") is False


def test_resolve_backend(monkeypatch):
    fake_agent_io = types.ModuleType("agent_io")
    fake_agent_io.DEFAULT_BASE = "http://127.0.0.1:8888"
    fake_agent_io.run_task = lambda *a, **k: ("code", {})
    fake_pipeline = types.ModuleType("pipeline")
    fake_pipeline.agent_io = fake_agent_io

    monkeypatch.setitem(sys.modules, "pipeline", fake_pipeline)
    monkeypatch.setitem(sys.modules, "pipeline.agent_io", fake_agent_io)

    monkeypatch.setattr(swarm_runner, "_swarm_endpoint_up", lambda base=None: True)
    fn, label = swarm_runner.resolve_backend("auto")
    assert label == "swarm"

    monkeypatch.setattr(swarm_runner, "_swarm_endpoint_up", lambda base=None: False)
    fn2, label2 = swarm_runner.resolve_backend("auto")
    assert label2 == "local"

    _, label_local = swarm_runner.resolve_backend("local")
    assert label_local == "local"


def test_make_swarm_agent_workflow(tmp_path, monkeypatch):
    spec = {
        "goal": "Build a widget",
        "files": [{"name": "widget.py", "path": "widget.py", "brief": "Widget implementation"}],
        "test_glob": "tests",
        "doc": {"path": "README.md", "brief": "Widget docs"},
    }

    def fake_generate(prompt, max_new_tokens=1024):
        return "```python\ndef widget(): return 42\n```"

    def fake_judge(prompt, max_new_tokens=64):
        return "the fix is clear, retry"

    monkeypatch.setattr(swarm_runner, "resolve_backend", lambda b, base, m: (fake_generate, "mock"))

    scratch_dir = str(tmp_path / "scratch")
    agent, label = swarm_runner.make_swarm_agent(
        spec, backend="mock", scratch_dir=scratch_dir, judge_fn=fake_judge
    )
    assert label == "mock"

    state = {}

    # 1. plan
    res_plan = agent("plan", "plan work", state)
    assert res_plan["planned"] is True
    assert res_plan["files_total"] == 1

    # 2. implement
    res_impl = agent("implement", "implement file", state)
    assert res_impl["wrote_file"] == "widget.py"
    assert res_impl["more_files"] is False
    assert os.path.exists(os.path.join(scratch_dir, "widget.py"))

    # 3. run_tests (monkeypatch run_pytest)
    monkeypatch.setattr(swarm_runner, "run_pytest", lambda d, t: (True, 3, 0, "3 passed"))
    res_tests = agent("run_tests", "run tests", state)
    assert res_tests["tests_pass"] is True
    assert res_tests["n_pass"] == 3

    # 4. debug
    state["last_error"] = "FAILED widget.py - AssertionError"
    res_debug = agent("debug", "debug failure", state)
    assert "retry" in res_debug["text"]
    assert "retry_idx" in state

    # 5. document
    res_doc = agent("document", "write README", state)
    assert res_doc["documented"] is True
    assert os.path.exists(os.path.join(scratch_dir, "README.md"))
