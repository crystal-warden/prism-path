"""Mission Control — the FastAPI proving + observability console.

Drives the app through fastapi.testclient (no network, no stdlib handler). The proving tests are the
un-gameable ones from the old frozen moat suite, re-pointed at the API: the answers depend on the
actual flow and the assumption, so a hardcoded response cannot pass. (The SSE endpoint is verified
against a real server, not here — TestClient's sync portal blocks on an endless stream.)
"""
import json

import pytest
from fastapi.testclient import TestClient

from prismpath import audit_log
from prismpath.mission_control import core
from prismpath.mission_control.app import app

V = "/api/v1"

# A fully Level-M flow (every deterministic edge is field-OP-constant) -> level_m True, 0 bad.
LM_OK = "---\nname: lm_ok\nstart: a\n---\n## a\n-> b: when score > 5\n-> c: else\n## b\nDone.\n## c\nDone.\n"
# A field-vs-field deterministic edge -> level_m False, >=1 bad.
LM_BAD = "---\nname: lm_bad\nstart: a\n---\n## a\n-> b: when x == y\n-> c: else\n## b\nDone.\n## c\nDone.\n"
# A branch whose reachability depends on an assumption.
BRANCH = "---\nname: branch\nstart: gate\n---\n## gate\n-> danger: when amount > 500\n-> safe: else\n## danger\nDone.\n## safe\nDone.\n"
# All four edge tiers, plus one non-Level-M deterministic edge.
DEMO = ("---\nname: triage\nstart: intake\n---\n"
        "## intake\nCollect.\n-> classify: when priority > threshold\n-> triage: else\n"
        "## classify\nAssess.\n-> escalate: needs a human\n-> resolve: on event resolved\n-> intake: on error\n"
        "## triage\nRoutine.\n-> resolve: else\n## escalate\nWait.\n## resolve\nDone.\n")


@pytest.fixture
def proj(tmp_path):
    p = tmp_path / "proj"
    (p / "flows").mkdir(parents=True)
    (p / "flows" / "triage.md").write_text(DEMO, encoding="utf-8")
    (p / "status.json").write_text(json.dumps(
        {"iteration": 3, "valid": True, "flow_path": str(p / "flows" / "triage.md")}), encoding="utf-8")
    (p / "interactions.jsonl").write_text(json.dumps(
        {"kind": "retriever", "phase": "retrieve", "prompt": "classify severity", "hits": 1,
         "hits_meta": [{"source": "runbook", "path": "sev.md", "score": 0.8}]}) + "\n", encoding="utf-8")
    (p / "checkpoint.json").write_text(json.dumps({"node": "classify", "state": {}}), encoding="utf-8")
    return p


@pytest.fixture
def client(proj, monkeypatch):
    monkeypatch.setattr(core, "MC_SCAN", str(proj / "status.json"))
    monkeypatch.setattr(core, "AUDIT", audit_log.AuditLog(str(proj / "audit.log")))  # don't touch the repo's log
    core.STATE.update({"proc": None, "proj": str(proj), "cfg": {}, "pinned": True})
    return TestClient(app)


# ── proving: the un-gameable invariants ───────────────────────────────────────
def test_level_m_distinguishes_flows(client):
    ok = client.post(V + "/prove/level-m", json={"flow": LM_OK}).json()
    assert ok["level_m"] is True and ok["non_member_edges"] == []
    bad = client.post(V + "/prove/level-m", json={"flow": LM_BAD}).json()
    assert bad["level_m"] is False and bad["non_member_edges"]      # a hardcoded True fails here


def test_reach_is_real_model_checking(client):
    # danger IS reachable with no assumption; a fake that always says "no" fails
    r1 = client.post(V + "/prove/reach", json={"flow": BRANCH, "forbid": ["danger"]}).json()
    assert r1["verdicts"]["danger"] != "no"
    # danger is NOT reachable once amount <= 500; a fake that always says "yes" fails
    r2 = client.post(V + "/prove/reach",
                     json={"flow": BRANCH, "reach": ["danger"], "assume": "amount <= 500"}).json()
    assert r2["verdicts"]["danger"] == "no"


def test_prove_audit_self_verify(client):
    d = client.get(V + "/prove/audit").json()
    assert d["valid"] is True and isinstance(d["n"], int)


def test_prove_rejects_empty_and_no_targets(client):
    assert client.post(V + "/prove/level-m", json={"flow": "   "}).status_code == 400
    assert client.post(V + "/prove/reach", json={"flow": BRANCH}).status_code == 400


# ── observe ───────────────────────────────────────────────────────────────────
def test_status_shape(client):
    s = client.get(V + "/status").json()
    assert "running" in s and "unbuffered" in s and s["iteration"] == 3


def test_flow_graph_tiers_and_text(client):
    g = client.get(V + "/flow/graph").json()
    assert set(g["nodes"]) == {"intake", "classify", "triage", "escalate", "resolve"}
    assert g["active_node"] == "classify" and g["flow_text"]        # text-in proving needs the source
    tiers = {e["tier"] for n in g["nodes"].values() for e in n["edges"]}
    assert {"deterministic", "semantic", "error", "event"} <= tiers


def test_retrievals_are_structured(client):
    r = client.get(V + "/retrievals").json()["retrievals"]
    assert r and r[0]["hits"][0]["source"] == "runbook" and r[0]["hits"][0]["path"] == "sev.md"


# ── edit containment (security) ───────────────────────────────────────────────
def test_write_rejects_traversal(client, proj):
    bad = client.post(V + "/file", json={"path": "../evil.txt", "content": "x"})
    assert bad.status_code == 400 and bad.json()["error"]["code"] == 400
    assert not (proj.parent / "evil.txt").exists()
    ok = client.post(V + "/file", json={"path": "flows/note.txt", "content": "hi"})
    assert ok.status_code == 200 and (proj / "flows" / "note.txt").read_text() == "hi"


def test_read_rejects_traversal(client):
    assert client.get(V + "/file", params={"path": "../../etc/passwd"}).status_code == 400


# ── contract ──────────────────────────────────────────────────────────────────
def test_openapi_contract(client):
    d = client.get("/openapi.json").json()
    assert d["info"]["title"] == "PrismPath Mission Control"
    assert "/api/v1/prove/level-m" in d["paths"] and "/api/v1/status" in d["paths"]


def test_error_envelope_shape(client):
    r = client.post(V + "/file", json={"path": "../x", "content": "y"})
    assert r.status_code == 400 and set(r.json()["error"]) == {"code", "message"}


def test_dropped_endpoints_are_gone(client):
    # chat, RAG-upload, and AGY were removed with the multi-user scope
    assert client.post(V + "/chat", json={"message": "hi"}).status_code >= 400
    assert client.get(V + "/agy/runs").status_code >= 400
    assert client.post(V + "/upload", json={}).status_code >= 400


def test_index_is_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "Mission Control" in r.text
