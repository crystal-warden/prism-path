# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Tests for swarm_exporter module."""

import io
import json
import os
from prismpath.orchestration import swarm_exporter


def test_esc_and_fold_helpers():
    assert swarm_exporter._esc('hello "world"\nnext') == 'hello \\"world\\" next'

    short_res = swarm_exporter._fold("short prompt")
    assert short_res["preview"] == "short prompt"
    assert short_res["folded"] == 0

    long_text = "A" * 2000
    long_res = swarm_exporter._fold(long_text, head=10, tail=10)
    assert long_res["folded"] == 1980
    assert "folded" in long_res["preview"]


def test_collect(tmp_path, monkeypatch):
    proj_dir = tmp_path / "demo_proj"
    proj_dir.mkdir()
    monkeypatch.setattr(swarm_exporter, "PROJ", str(proj_dir))
    monkeypatch.setattr(swarm_exporter, "ROLES_DIR", str(tmp_path / "roles"))

    status_file = proj_dir / "status.json"
    status_file.write_text(json.dumps({
        "iteration": 3,
        "elapsed_s": 25,
        "valid": True,
        "done": False,
        "files": ["main.py", "utils.py"],
        "biggest_tok": 500,
        "help_count": 1,
    }), encoding="utf-8")

    log_file = proj_dir / "sprint.log"
    log_file.write_text("[architect] plan\n[coder] code\n[review] main.py\n", encoding="utf-8")

    help_file = proj_dir / "HELP.md"
    help_file.write_text("- [ ] question 1\n- [x] resolved 1\n", encoding="utf-8")

    metrics = swarm_exporter.collect()
    assert isinstance(metrics, str)
    assert "swarm_iteration 3" in metrics
    assert "swarm_elapsed_seconds 25" in metrics
    assert "swarm_valid 1" in metrics
    assert "swarm_files 2" in metrics
    assert "swarm_help_open 1" in metrics
    assert "swarm_help_resolved 1" in metrics
    assert "swarm_up 1" in metrics


def test_read_interactions(tmp_path, monkeypatch):
    proj_dir = tmp_path / "demo_proj"
    proj_dir.mkdir()
    inter_file = proj_dir / "interactions.jsonl"
    inter_file.write_text(json.dumps({
        "ts": 1700000000.0,
        "kind": "swarm",
        "role": "coder",
        "phase": "build",
        "dur_ms": 150,
        "prompt": "write widget",
        "output": "widget code",
        "rc": 0,
    }) + "\n", encoding="utf-8")

    monkeypatch.setattr(swarm_exporter, "PROJ", str(proj_dir))
    monkeypatch.setattr(swarm_exporter, "INTER_PATH", str(inter_file))

    res = swarm_exporter.read_interactions(limit=10)
    assert "summary" in res
    assert "events" in res
    assert len(res["events"]) == 1
    event = res["events"][0]
    assert event["kind"] == "swarm"
    assert event["role"] == "coder"
    assert event["prompt"] == "write widget"


def test_handler_routes(tmp_path, monkeypatch):
    proj_dir = tmp_path / "demo_proj"
    proj_dir.mkdir()
    monkeypatch.setattr(swarm_exporter, "PROJ", str(proj_dir))
    monkeypatch.setattr(swarm_exporter, "INTER_PATH", str(proj_dir / "interactions.jsonl"))

    class MockHandler(swarm_exporter.Handler):
        def __init__(self, path):
            self.path = path
            self.wfile = io.BytesIO()
            self.headers_sent = {}
            self.response_code = None

        def send_response(self, code, message=None):
            self.response_code = code

        def send_header(self, keyword, value):
            self.headers_sent[keyword] = value

        def end_headers(self):
            pass

    # Test /metrics
    h1 = MockHandler("/metrics")
    h1.do_GET()
    assert h1.response_code == 200
    assert "swarm_up 1" in h1.wfile.getvalue().decode("utf-8")

    # Test /interactions
    h2 = MockHandler("/interactions")
    h2.do_GET()
    assert h2.response_code == 200
    data = json.loads(h2.wfile.getvalue().decode("utf-8"))
    assert "summary" in data

    # Test / (glass lens)
    h3 = MockHandler("/")
    h3.do_GET()
    assert h3.response_code == 200
    assert "Hermes Swarm" in h3.wfile.getvalue().decode("utf-8")
