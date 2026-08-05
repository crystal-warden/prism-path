"""siem.py — the SIEM ingestion port for the SOC adapter (production SIEM integrations).

One small port, several sources — the Ingestion side of the hexagonal contract, so triage
flows never know which SIEM is behind them:

  * ``ElasticSource``  — any Elasticsearch / OpenSearch-compatible indexer (query-DSL over
    REST). This single class covers Elastic, OpenSearch, and the Wazuh indexer (which *is*
    OpenSearch); everything is env-configurable and **TLS verification is ON by default**
    (self-signed homelabs opt out with ``SIEM_VERIFY_TLS=0`` or point ``SIEM_CA_CERT`` at
    their CA).
  * ``WazuhSource``    — ElasticSource with Wazuh's index pattern and alert-shape mapping,
    plus (opt-in, legacy) credential extraction from ``wazuh-install-files.tar``.
  * ``NDJSONFileSource`` — alerts from newline-delimited JSON files: the air-gap / replay /
    test path; deterministic and dependency-free.
  * ``SplunkSource``   — best-effort Splunk REST (``services/search/jobs/export``); the
    request/normalization shape is right, but this class has NOT been exercised against a
    live Splunk — treat it as a reviewed starting point, not a certified integration.

Env (ElasticSource defaults):
  SIEM_URL (https://127.0.0.1:9200) · SIEM_INDEX (wazuh-alerts-*) · SIEM_USER · SIEM_PASSWORD
  · SIEM_VERIFY_TLS (1; 0 disables) · SIEM_CA_CERT (CA bundle path; implies verification)

Every source normalizes hits into the FLAT alert dict the triage flows route on
(id/level/rule_id/description/mitre/agent/srcip/timestamp/full_log) — nested SIEM payloads
cross the port through the Connector SDK's ``PayloadFlattener`` discipline.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional


def _env_verify():
    """The `verify` value requests expects: a CA path, True, or False (opt-out only)."""
    ca = os.environ.get("SIEM_CA_CERT")
    if ca:
        return ca
    return os.environ.get("SIEM_VERIFY_TLS", "1") not in ("0", "false", "no", "")


def normalize_wazuh_hit(hit: Dict[str, Any]) -> Dict[str, Any]:
    """One indexer hit -> the flat alert dict the flows (and the prefilter's
    alert_document) consume."""
    src = hit.get("_source", hit)
    rule = src.get("rule", {})
    return {
        "id": hit.get("_id") or src.get("id") or "",
        "level": rule.get("level", src.get("level", 0)),
        "rule_id": rule.get("id", src.get("rule_id", "")),
        "description": rule.get("description", src.get("description", "")),
        "mitre": rule.get("mitre", {}).get("technique", src.get("mitre", []) or []),
        "agent": src.get("agent", {}).get("name") if isinstance(src.get("agent"), dict)
        else src.get("agent", "unknown"),
        "srcip": src.get("data", {}).get("srcip") if isinstance(src.get("data"), dict)
        else src.get("srcip"),
        "timestamp": src.get("timestamp", ""),
        "full_log": (src.get("full_log") or "")[:400],
    }


class SIEMSource:
    """The port. A source yields *normalized alert dicts*; the triage flow neither knows nor
    cares which SIEM produced them."""

    def poll(self, min_level: int = 7, size: int = 25) -> List[Dict[str, Any]]:
        """Newest-first alerts at/above `min_level`, normalized."""
        raise NotImplementedError

    def count(self, query: Dict[str, Any]) -> int:
        """Count documents matching a source-native query (enrichment context)."""
        raise NotImplementedError


class ElasticSource(SIEMSource):
    """Elasticsearch / OpenSearch / Wazuh-indexer over the query DSL. `session` is injectable
    for tests (anything with .get/.post returning requests-shaped responses)."""

    def __init__(self, url: Optional[str] = None, index: Optional[str] = None,
                 auth: Optional[tuple] = None, verify=None, session=None,
                 timeout: int = 15):
        self.url = (url or os.environ.get("SIEM_URL", "https://127.0.0.1:9200")).rstrip("/")
        self.index = index or os.environ.get("SIEM_INDEX", "wazuh-alerts-*")
        if auth is None:
            user = os.environ.get("SIEM_USER")
            pw = os.environ.get("SIEM_PASSWORD")
            auth = (user, pw) if user and pw is not None else None
        self.auth = auth
        self.verify = _env_verify() if verify is None else verify
        self.timeout = timeout
        if session is None:
            import requests
            session = requests
        self.session = session

    # -- raw DSL surface (the wazuh agent's enrichment queries use these directly)
    def search(self, body: Dict[str, Any], size: int = 10) -> List[Dict[str, Any]]:
        r = self.session.get(
            f"{self.url}/{self.index}/_search?size={size}&sort=timestamp:desc",
            auth=self.auth, verify=self.verify, json=body, timeout=self.timeout)
        r.raise_for_status()
        return r.json()["hits"]["hits"]

    def count(self, query: Dict[str, Any]) -> int:
        r = self.session.get(f"{self.url}/{self.index}/_count", auth=self.auth,
                             verify=self.verify, json=query, timeout=self.timeout)
        r.raise_for_status()
        return r.json()["count"]

    # -- the port
    def poll(self, min_level: int = 7, size: int = 25) -> List[Dict[str, Any]]:
        hits = self.search({"query": {"range": {"rule.level": {"gte": min_level}}}}, size=size)
        return [normalize_wazuh_hit(h) for h in hits]


class WazuhSource(ElasticSource):
    """The Wazuh indexer — ElasticSource with wazuh defaults plus the legacy credential path:
    when no SIEM_USER/SIEM_PASSWORD is configured, optionally extract the admin password from
    the root-owned ``wazuh-install-files.tar`` (the stock single-box install). Extraction is
    LAZY and opt-in via ``WAZUH_INSTALL_TAR`` (or the default path existing) — constructing
    the source never triggers a sudo prompt."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self._tar = os.environ.get("WAZUH_INSTALL_TAR",
                                   str(Path.home() / "wazuh-install-files.tar"))

    def _tar_auth(self) -> tuple:
        out = subprocess.run(
            ["sudo", "tar", "-O", "-xf", self._tar, "wazuh-install-files/wazuh-passwords.txt"],
            capture_output=True, text=True, check=True).stdout
        pw, take = None, False
        for line in out.splitlines():
            if "indexer_username: 'admin'" in line:
                take = True
            elif take and "indexer_password:" in line:
                pw = line.split("'")[1]
                break
        if not pw:
            raise RuntimeError("could not locate admin indexer password in install bundle")
        return "admin", pw

    def _ensure_auth(self):
        if self.auth is None and os.path.exists(self._tar):
            self.auth = self._tar_auth()

    def search(self, body, size: int = 10):
        self._ensure_auth()
        return super().search(body, size=size)

    def count(self, query):
        self._ensure_auth()
        return super().count(query)


class NDJSONFileSource(SIEMSource):
    """Alerts from an NDJSON file (one JSON object per line — raw indexer hits or already-flat
    alerts). The air-gap ingestion path, the replay path, and the test path. `count(query)`
    supports the enrichment shapes the triage flow uses (term / range filters) well enough for
    offline runs."""

    def __init__(self, path):
        self.path = Path(path)

    def _rows(self) -> List[Dict[str, Any]]:
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        return out

    @staticmethod
    def _to_hit(row: Dict[str, Any]) -> Dict[str, Any]:
        """Raw-hit passthrough, or reconstruct the indexer hit shape from a flat alert row —
        so the triage agent's observe path reads files exactly like a live indexer."""
        if "_source" in row:
            return row
        a = normalize_wazuh_hit(row)
        return {"_id": a["id"] or f"row-{hash(json.dumps(row, sort_keys=True)) & 0xffffffff:x}",
                "_source": {"rule": {"level": a["level"], "id": a["rule_id"],
                                     "description": a["description"],
                                     "mitre": {"technique": a["mitre"]}},
                            "agent": {"name": a["agent"]},
                            "data": {"srcip": a["srcip"]},
                            "timestamp": a["timestamp"], "full_log": a["full_log"]}}

    def search(self, body: Dict[str, Any], size: int = 10) -> List[Dict[str, Any]]:
        """DSL-lite over the file: honors a top-level rule.level range, newest first."""
        gte = 0
        q = body.get("query", {})
        if "range" in q and "rule.level" in q["range"]:
            gte = q["range"]["rule.level"].get("gte", 0)
        hits = [self._to_hit(r) for r in self._rows()]
        hits = [h for h in hits if (h["_source"].get("rule", {}).get("level") or 0) >= gte]
        hits.sort(key=lambda h: h["_source"].get("timestamp", ""), reverse=True)
        return hits[:size]

    def poll(self, min_level: int = 7, size: int = 25) -> List[Dict[str, Any]]:
        alerts = [normalize_wazuh_hit(r) for r in self._rows()]
        alerts = [a for a in alerts if (a.get("level") or 0) >= min_level]
        alerts.sort(key=lambda a: a.get("timestamp", ""), reverse=True)
        return alerts[:size]

    def count(self, query: Dict[str, Any]) -> int:
        filters = (query.get("query", {}).get("bool", {}) or {}).get("filter", [])
        n = 0
        for row in self._rows():
            a = normalize_wazuh_hit(row)
            ok = True
            for f in filters:
                if "term" in f:
                    (field, want), = f["term"].items()
                    have = {"agent.name": a.get("agent"), "rule.id": a.get("rule_id"),
                            "data.srcip": a.get("srcip")}.get(field)
                    ok = ok and (have == want)
                elif "range" in f:
                    (field, cond), = f["range"].items()
                    if field == "rule.level":
                        ok = ok and (a.get("level") or 0) >= cond.get("gte", 0)
                    # timestamp ranges pass — offline files are assumed in-window
            if ok:
                n += 1
        return n


class SplunkSource(SIEMSource):
    """Splunk via the REST export API — **best-effort, not exercised against a live Splunk**.
    The search/auth/normalization shape follows the documented API
    (``POST /services/search/jobs/export`` with an SPL query, token auth via
    ``Authorization: Bearer``), but until it runs against a real instance treat it as a
    reviewed starting point. Env: SPLUNK_URL, SPLUNK_TOKEN, SPLUNK_INDEX (default `main`)."""

    def __init__(self, url: Optional[str] = None, token: Optional[str] = None,
                 index: Optional[str] = None, verify=None, session=None, timeout: int = 30):
        self.url = (url or os.environ.get("SPLUNK_URL", "https://127.0.0.1:8089")).rstrip("/")
        self.token = token or os.environ.get("SPLUNK_TOKEN", "")
        self.index = index or os.environ.get("SPLUNK_INDEX", "main")
        self.verify = _env_verify() if verify is None else verify
        self.timeout = timeout
        if session is None:
            import requests
            session = requests
        self.session = session

    def _export(self, spl: str) -> List[Dict[str, Any]]:
        r = self.session.post(
            f"{self.url}/services/search/jobs/export",
            headers={"Authorization": f"Bearer {self.token}"},
            data={"search": spl, "output_mode": "json"},
            verify=self.verify, timeout=self.timeout)
        r.raise_for_status()
        rows = []
        for line in r.text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
            except ValueError:
                continue
            if isinstance(doc, dict) and "result" in doc:
                rows.append(doc["result"])
        return rows

    def poll(self, min_level: int = 7, size: int = 25) -> List[Dict[str, Any]]:
        spl = (f"search index={self.index} level>={min_level} "
               f"| sort -_time | head {size} "
               f"| table _raw, _time, level, rule_id, description, agent, srcip")
        out = []
        for row in self._export(spl):
            out.append({
                "id": row.get("_cd") or row.get("id") or f"splunk-{row.get('_time', '')}",
                "level": int(float(row.get("level", 0) or 0)),
                "rule_id": row.get("rule_id", ""),
                "description": row.get("description", row.get("_raw", ""))[:400],
                "mitre": [],
                "agent": row.get("agent", row.get("host", "unknown")),
                "srcip": row.get("srcip"),
                "timestamp": row.get("_time", ""),
                "full_log": (row.get("_raw") or "")[:400],
            })
        return out

    def count(self, query: Dict[str, Any]) -> int:
        rows = self._export(f"search index={self.index} | stats count")
        try:
            return int(rows[0]["count"]) if rows else 0
        except (KeyError, ValueError, TypeError):
            return 0


def source_from_env() -> SIEMSource:
    """The deployment seam: SIEM_KIND ∈ {wazuh (default), elastic, ndjson, splunk} selects the
    source; each source reads its own env. `SIEM_FILE` names the NDJSON path."""
    kind = os.environ.get("SIEM_KIND", "wazuh").lower()
    if kind == "ndjson":
        return NDJSONFileSource(os.environ.get("SIEM_FILE", "alerts.ndjson"))
    if kind == "splunk":
        return SplunkSource()
    if kind == "elastic":
        return ElasticSource()
    return WazuhSource()
