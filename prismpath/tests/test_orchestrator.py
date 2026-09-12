# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Tests for orchestrator module."""

import io
import os
import zipfile
import pytest
import requests
from fastapi.testclient import TestClient
from prismpath.orchestration import orchestrator

client = TestClient(orchestrator.app)


def test_health():
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert "model" in data
    assert "target" in data
    assert "sessions" in data


def test_session_lifecycle(tmp_path, monkeypatch):
    monkeypatch.setattr(orchestrator, "WORK", str(tmp_path / "orch_work"))

    # 1. Start session in planning phase
    monkeypatch.setattr(orchestrator, "_llm", lambda msgs: "What features would you like in your app?")
    r1 = client.post("/api/session", json={"prompt": "I want a simple web app"})
    assert r1.status_code == 200
    d1 = r1.json()
    sid = d1["session_id"]
    assert d1["phase"] == "planning"
    assert "features" in d1["reply"]

    # 2. Send message transitioning to awaiting_approval
    plan_text = "Goal: Simple Web App\nFiles: index.html\nReply OK to build this, or tell me what to change."
    monkeypatch.setattr(orchestrator, "_llm", lambda msgs: plan_text)
    r2 = client.post(f"/api/session/{sid}/message", json={"text": "Looks good, propose the plan"})
    assert r2.status_code == 200
    d2 = r2.json()
    assert d2["phase"] == "awaiting_approval"

    # 3. Get snapshot
    r3 = client.get(f"/api/session/{sid}")
    assert r3.status_code == 200
    d3 = r3.json()
    assert d3["id"] == sid
    assert d3["phase"] == "awaiting_approval"
    assert d3["plan"] == plan_text

    # 4. Approve session (mock Popen)
    class FakeProc:
        def __init__(self):
            self.pid = 1234

    monkeypatch.setattr(orchestrator.subprocess, "Popen", lambda *a, **k: FakeProc())
    r4 = client.post(f"/api/session/{sid}/approve")
    assert r4.status_code == 200
    assert r4.json()["phase"] == "executing"

    # Approving again returns current phase
    r4_again = client.post(f"/api/session/{sid}/approve")
    assert r4_again.status_code == 200
    assert r4_again.json()["phase"] == "executing"

    # 5. Download artifact zip
    proj_dir = orchestrator.SESS[sid]["proj"]
    os.makedirs(proj_dir, exist_ok=True)
    with open(os.path.join(proj_dir, "app.js"), "w") as f:
        f.write("console.log('hello');")

    r5 = client.get(f"/api/session/{sid}/artifact")
    assert r5.status_code == 200
    assert r5.headers["content-type"] == "application/zip"

    z = zipfile.ZipFile(io.BytesIO(r5.content))
    assert "app.js" in z.namelist()
    assert z.read("app.js").decode("utf-8") == "console.log('hello');"


def test_session_404():
    resp = client.get("/api/session/nonexistent_sid_123")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "no such session"


def test_llm_failure_handling(monkeypatch):
    def mock_post(url, json=None, timeout=None):
        class MockResponse:
            def raise_for_status(self):
                raise requests.HTTPError("500 Internal Server Error")
        return MockResponse()

    monkeypatch.setattr(requests, "post", mock_post)
    with pytest.raises(requests.HTTPError, match="500 Internal Server Error"):
        orchestrator._llm([{"role": "user", "content": "hello"}])
