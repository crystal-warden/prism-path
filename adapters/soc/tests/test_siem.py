"""siem.py + the connector migration — stubbed HTTP, no live systems.

Covers: ElasticSource request shape + TLS default, WazuhSource lazy credentials,
NDJSONFileSource round-trip (poll/search/count over both raw-hit and flat rows),
SplunkSource export parsing, source_from_env selection, and dispatch parity between the
WazuhTriageConnector and the legacy HANDLERS (with _worker provenance added).
"""
import json
import os

import pytest

import siem


# ------------------------------------------------------------------ fake HTTP plumbing

class FakeResponse:
    def __init__(self, payload=None, text=""):
        self._payload = payload
        self.text = text

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self, payload=None, text=""):
        self.payload, self.text_body, self.calls = payload, text, []

    def get(self, url, **kw):
        self.calls.append(("GET", url, kw))
        return FakeResponse(self.payload, self.text_body)

    def post(self, url, **kw):
        self.calls.append(("POST", url, kw))
        return FakeResponse(self.payload, self.text_body)


RAW_HIT = {"_id": "A1", "_source": {
    "rule": {"level": 12, "id": "5710", "description": "sshd: brute force",
             "mitre": {"technique": ["T1110"]}},
    "agent": {"name": "web01"}, "data": {"srcip": "203.0.113.9"},
    "timestamp": "2026-08-05T10:00:00Z", "full_log": "Failed password " * 40}}


# ------------------------------------------------------------------ ElasticSource

def test_elastic_source_request_shape_and_tls_default(monkeypatch):
    for var in ("SIEM_URL", "SIEM_INDEX", "SIEM_USER", "SIEM_PASSWORD",
                "SIEM_VERIFY_TLS", "SIEM_CA_CERT"):
        monkeypatch.delenv(var, raising=False)
    fake = FakeSession(payload={"hits": {"hits": [RAW_HIT]}})
    src = siem.ElasticSource(url="https://siem.example:9200", index="alerts-*",
                             auth=("u", "p"), session=fake)
    assert src.verify is True, "TLS verification must default ON"
    alerts = src.poll(min_level=7, size=5)
    method, url, kw = fake.calls[0]
    assert method == "GET" and url.startswith("https://siem.example:9200/alerts-*/_search")
    assert "size=5" in url and kw["auth"] == ("u", "p") and kw["verify"] is True
    assert kw["json"] == {"query": {"range": {"rule.level": {"gte": 7}}}}
    a = alerts[0]
    assert a["id"] == "A1" and a["level"] == 12 and a["agent"] == "web01"
    assert a["srcip"] == "203.0.113.9" and a["mitre"] == ["T1110"]
    assert len(a["full_log"]) <= 400, "full_log capped like the legacy agent"


def test_elastic_env_configuration(monkeypatch):
    monkeypatch.setenv("SIEM_URL", "https://idx:9200/")
    monkeypatch.setenv("SIEM_INDEX", "custom-*")
    monkeypatch.setenv("SIEM_USER", "svc")
    monkeypatch.setenv("SIEM_PASSWORD", "s3cr3t")
    monkeypatch.setenv("SIEM_VERIFY_TLS", "0")
    src = siem.ElasticSource(session=FakeSession(payload={"count": 3}))
    assert src.url == "https://idx:9200" and src.index == "custom-*"
    assert src.auth == ("svc", "s3cr3t") and src.verify is False
    assert src.count({"query": {}}) == 3
    monkeypatch.setenv("SIEM_CA_CERT", "/etc/ssl/private-ca.pem")
    src2 = siem.ElasticSource(session=FakeSession())
    assert src2.verify == "/etc/ssl/private-ca.pem", "a CA path implies verification"


def test_wazuh_source_lazy_credentials(monkeypatch, tmp_path):
    """Constructing a WazuhSource never touches sudo/tar; only a query without configured
    credentials attempts extraction — and env credentials suppress it entirely."""
    monkeypatch.setenv("SIEM_USER", "admin")
    monkeypatch.setenv("SIEM_PASSWORD", "pw")
    monkeypatch.setenv("WAZUH_INSTALL_TAR", str(tmp_path / "absent.tar"))
    fake = FakeSession(payload={"hits": {"hits": []}})
    src = siem.WazuhSource(session=fake)
    src.search({"query": {}})
    assert src.auth == ("admin", "pw")

    monkeypatch.delenv("SIEM_USER")
    monkeypatch.delenv("SIEM_PASSWORD")
    src2 = siem.WazuhSource(session=fake)          # tar absent -> no extraction attempt
    src2.search({"query": {}})
    assert src2.auth is None


# ------------------------------------------------------------------ NDJSONFileSource

def test_ndjson_source_round_trip(tmp_path):
    flat = {"id": "B2", "level": 8, "rule_id": "31151", "description": "web scan",
            "agent": "dmz01", "srcip": "198.51.100.2", "timestamp": "2026-08-05T11:00:00Z"}
    low = {"id": "C3", "level": 3, "rule_id": "1002", "description": "noise",
           "agent": "dmz01", "timestamp": "2026-08-05T09:00:00Z"}
    f = tmp_path / "alerts.ndjson"
    f.write_text("\n".join(json.dumps(r) for r in (RAW_HIT, flat, low)) + "\nnot json\n")
    src = siem.NDJSONFileSource(f)

    alerts = src.poll(min_level=7)
    assert [a["id"] for a in alerts] == ["B2", "A1"], "level-filtered, newest first"

    hits = src.search({"query": {"range": {"rule.level": {"gte": 7}}}}, size=10)
    assert {h["_id"] for h in hits} == {"A1", "B2"}
    b2 = next(h for h in hits if h["_id"] == "B2")
    assert b2["_source"]["rule"]["level"] == 8, "flat rows reconstructed into hit shape"

    n = src.count({"query": {"bool": {"filter": [
        {"range": {"timestamp": {"gte": "now-24h"}}},
        {"term": {"agent.name": "dmz01"}}]}}})
    assert n == 2
    assert src.count({"query": {"bool": {"filter": [{"term": {"rule.id": "5710"}}]}}}) == 1
    assert siem.NDJSONFileSource(tmp_path / "missing.ndjson").poll() == []


# ------------------------------------------------------------------ SplunkSource (best-effort)

def test_splunk_source_export_parsing():
    lines = "\n".join([
        json.dumps({"preview": False, "result": {
            "_time": "2026-08-05T10:30:00", "level": "9", "rule_id": "sp1",
            "description": "beaconing", "agent": "edge01", "srcip": "192.0.2.4",
            "_raw": "raw event"}}),
        json.dumps({"preview": True}),          # non-result rows are skipped
    ])
    fake = FakeSession(text=lines)
    src = siem.SplunkSource(url="https://splunk:8089", token="tok", session=fake, verify=False)
    alerts = src.poll(min_level=7)
    method, url, kw = fake.calls[0]
    assert method == "POST" and url.endswith("/services/search/jobs/export")
    assert kw["headers"]["Authorization"] == "Bearer tok"
    assert alerts[0]["level"] == 9 and alerts[0]["agent"] == "edge01"


def test_source_from_env_selection(monkeypatch, tmp_path):
    monkeypatch.setenv("SIEM_KIND", "ndjson")
    monkeypatch.setenv("SIEM_FILE", str(tmp_path / "a.ndjson"))
    assert isinstance(siem.source_from_env(), siem.NDJSONFileSource)
    monkeypatch.setenv("SIEM_KIND", "elastic")
    assert type(siem.source_from_env()) is siem.ElasticSource
    monkeypatch.setenv("SIEM_KIND", "splunk")
    assert isinstance(siem.source_from_env(), siem.SplunkSource)
    monkeypatch.setenv("SIEM_KIND", "wazuh")
    assert isinstance(siem.source_from_env(), siem.WazuhSource)


# ------------------------------------------------------------------ connector migration

def test_connector_dispatch_parity_with_handlers(tmp_path, monkeypatch):
    """The WazuhTriageConnector dispatches the same handlers the HANDLERS dict did, adds
    _worker provenance, and drives a full offline triage step (observe over an NDJSON file)."""
    monkeypatch.setenv("SOC_STATE_DIR", str(tmp_path / "staging"))
    monkeypatch.setenv("SIEM_KIND", "ndjson")
    f = tmp_path / "alerts.ndjson"
    f.write_text(json.dumps(RAW_HIT) + "\n")
    monkeypatch.setenv("SIEM_FILE", str(f))

    import importlib
    import wazuh_triage_agent as wta
    importlib.reload(wta)

    out = wta.agent("idle", "", {})
    assert out["text"].startswith("no work")
    assert out["_worker"] == "soc.wazuh_triage.idle", "SDK provenance on every outcome"
    assert wta.agent("nonexistent", "", {})["text"].startswith("(no handler")

    state = {}
    obs = wta.CONNECTOR.agent("observe", "", state)
    assert obs["no_alert"] is False and obs["rule_level"] == 12
    assert state["alert"]["agent"] == "web01" and state["alert"]["id"] == "A1"
    assert set(wta.HANDLERS) == set(wta.CONNECTOR._handlers)

    wl = wta.CONNECTOR.agent("watchlist", "", state)
    assert "watchlist" in wl["text"]
    rows = [json.loads(l) for l in (tmp_path / "staging" / "watchlist.jsonl").open()]
    assert rows[0]["id"] == "A1"


def test_emit_labels_for_the_tuner(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_STATE_DIR", str(tmp_path / "staging"))
    monkeypatch.setenv("SIEM_KIND", "ndjson")
    monkeypatch.setenv("SIEM_FILE", str(tmp_path / "none.ndjson"))
    import importlib
    import wazuh_triage_agent as wta
    importlib.reload(wta)
    bdir = tmp_path / "staging"
    bdir.mkdir(parents=True, exist_ok=True)
    (bdir / "benign_patterns.jsonl").write_text(
        json.dumps({"id": "x", "desc": "expected cron noise", "agent": "web01",
                    "rule_id": "2902"}) + "\n")
    out = wta.emit_labels(str(tmp_path / "labels.jsonl"))
    assert out["labels"] == 1
    row = json.loads((tmp_path / "labels.jsonl").read_text())
    assert row["action"] == "ignore" and "expected cron noise" in row["doc"]
