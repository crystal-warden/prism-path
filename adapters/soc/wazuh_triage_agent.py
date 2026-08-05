"""wazuh_triage_agent.py — agent adapter for flows/wazuh_triage.md (blue-team playbook, Mode 1).

Bridges the prismpath kernel to a SIEM through the **Connector SDK** and the **SIEM ingestion
port** (siem.py):
  observe  -> SOURCE.poll / query-DSL against the configured indexer (Wazuh/OpenSearch/
              Elastic by env; NDJSON files for air-gap/replay; Splunk best-effort)
  reason   -> the served model at PRISMPATH_LLM_ENDPOINT (default: local gemma4 — NOT
              llm_local, which would load a second model onto the GPU next to the swarm)
  contain  -> writes a rule DRAFT to the staging dir for human approval; the
              verify_staged node is the gate: the file on disk is the definition
              of done, not the model's claim. Nothing ever touches the firewall.

Runtime artifacts live outside the repo in SOC_STATE_DIR (default ~/cw-staging/). TLS
verification to the indexer is ON by default (SIEM_VERIFY_TLS=0 opts out for self-signed
homelabs); credentials come from SIEM_USER/SIEM_PASSWORD, with the legacy root-owned
wazuh-install-files.tar extraction as the Wazuh fallback — never stored in this file.

Run one triage cycle:  python wazuh_triage_agent.py
Seed / inspect the prefilter corpus:  python wazuh_triage_agent.py seed | info
Emit labeled decisions for `prefilter tune`:  python wazuh_triage_agent.py labels out.jsonl
Env: WAZUH_MIN_LEVEL (7) · TRIAGE_FLOW · SIEM_KIND/SIEM_URL/SIEM_INDEX/SIEM_VERIFY_TLS
     · SOC_STATE_DIR · PRISMPATH_LLM_ENDPOINT/PRISMPATH_LLM_MODEL
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

from prismpath.parser import parse_file
from prismpath.engine import run
from prismpath.router import HybridRouter, LLMRouter
from prismpath.connector import BaseConnector
from prismpath.prefilter import PrefilterCache  # verdict memoization (auto-resolve near-identical alerts)
from prismpath.ledger_runner import upsert_jsonl  # idempotent side-effect appends (replay-safe)
from prismpath.checkpoint import flow_hash  # content hash of the flow file -> the prefilter policy_hash

import siem

LLM_ENDPOINT = os.environ.get("PRISMPATH_LLM_ENDPOINT", "http://127.0.0.1:8888/v1/chat/completions")
LLM_MODEL = os.environ.get("PRISMPATH_LLM_MODEL", "gemma4")
MIN_LEVEL = int(os.environ.get("WAZUH_MIN_LEVEL", "7"))
FLOW = os.environ.get("TRIAGE_FLOW", str(Path(__file__).parent / "flows" / "wazuh_triage.md"))

# The SIEM behind the port — selected by SIEM_KIND (wazuh | elastic | ndjson | splunk).
SOURCE = siem.source_from_env()

# --- measurement instrumentation ----------------------------------------------------
GEMMA_CALLS: list = []   # {latency_s, prompt_tokens, completion_tokens, max_tokens}
NODE_TIMES: list = []    # {node, seconds}

# Structured verdict schema — vLLM enforces this via response_format=json_schema,
# so classify returns a reliable object and the flow routes deterministically on it.
VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "threat_class": {"type": "string",
                         "enum": ["malware", "intrusion", "recon", "exfil", "benign", "other"]},
        "is_active_threat": {"type": "boolean"},
        "confidence": {"type": "number"},
        "recommended_action": {"type": "string", "enum": ["contain", "watch", "ignore"]},
        "rationale": {"type": "string"},
    },
    "required": ["threat_class", "is_active_threat", "confidence", "recommended_action", "rationale"],
}

BASE = Path(os.environ.get("SOC_STATE_DIR", str(Path.home() / "cw-staging"))).expanduser()
DRAFTS = BASE / "opnsense-rule-drafts"
REPORTS = BASE / "triage-reports"
STATE_FILE = BASE / "triage_state.json"
WATCHLIST = BASE / "watchlist.jsonl"
BENIGN = BASE / "benign_patterns.jsonl"

# The verdict cache (prismpath.prefilter). Construction is lazy — no model load here.
CACHE = PrefilterCache(BASE / "prefilter_corpus")

# --- self-policing (prefilter shadow sampling, roadmap item #3) ----------------------
# POLICY_HASH stamps every learned verdict with the triage flow it was adjudicated under (the SAME
# content hash the checkpoint/lockfile layer uses). Editing flows/wazuh_triage.md rotates the hash, so
# lookups auto-skip verdicts learned under the old policy — a flow edit invalidates stale cache hits
# without a manual purge. SHADOW_RATE routes that fraction of cache HITS through the LLM anyway and
# compares: sustained disagreement quarantines the drifting entry. Set to 0 to disable the audit.
POLICY_HASH = flow_hash(FLOW)
SHADOW_RATE = float(os.environ.get("PREFILTER_SHADOW_RATE", "0.05"))


# --- alert -> document mapping (the wazuh-specific half of the prefilter) -----------
def alert_document(alert: dict) -> str:
    """Build the 'alert document' string that gets embedded, from the stable alert
    fields: description + agent + srcip + mitre + rule_id. Same shape for live
    triage and for seeding, so vectors are comparable."""
    mitre = alert.get("mitre") or []
    if isinstance(mitre, list):
        mitre = ", ".join(str(x) for x in mitre)
    return (
        f"description: {alert.get('description', '')} | "
        f"agent: {alert.get('agent', '')} | "
        f"srcip: {alert.get('srcip') or 'none'} | "
        f"mitre: {mitre or 'n/a'} | "
        f"rule_id: {alert.get('rule_id', '')}"
    )


def alert_key(alert: dict) -> str:
    return f"{alert.get('rule_id','')}|{alert.get('agent','')}|{alert.get('srcip') or 'none'}"


# --- small helpers (the SIEM port, kept under the old names so handlers read the same) --
def _search(body: dict, size: int = 10) -> list[dict]:
    return SOURCE.search(body, size=size)


def _count(body: dict) -> int:
    return SOURCE.count(body)


def gemma(prompt: str, max_tokens: int = 8) -> str:
    t = time.time()
    r = requests.post(LLM_ENDPOINT, json={
        "model": LLM_MODEL, "temperature": 0, "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}]}, timeout=120)
    dt = time.time() - t
    r.raise_for_status()
    j = r.json()
    u = j.get("usage", {})
    GEMMA_CALLS.append({"latency_s": round(dt, 2), "prompt_tokens": u.get("prompt_tokens"),
                        "completion_tokens": u.get("completion_tokens"), "max_tokens": max_tokens})
    return j["choices"][0]["message"]["content"].strip()


def gemma_json(prompt: str, schema: dict, max_tokens: int = 768) -> dict:
    """Schema-constrained call — vLLM guarantees valid JSON matching `schema`."""
    t = time.time()
    body = {"model": LLM_MODEL, "temperature": 0, "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
            "response_format": {"type": "json_schema",
                                "json_schema": {"name": "verdict", "schema": schema}}}
    r = requests.post(LLM_ENDPOINT, json=body, timeout=120)
    dt = time.time() - t
    r.raise_for_status()
    j = r.json()
    u = j.get("usage", {})
    GEMMA_CALLS.append({"latency_s": round(dt, 2), "prompt_tokens": u.get("prompt_tokens"),
                        "completion_tokens": u.get("completion_tokens"), "max_tokens": max_tokens,
                        "structured": True})
    try:
        return json.loads(j["choices"][0]["message"]["content"])
    except Exception:
        return {}


def _load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"processed": []}


def _save_state(s: dict) -> None:
    BASE.mkdir(exist_ok=True)
    STATE_FILE.write_text(json.dumps(s, indent=2))


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


# --- node handlers -------------------------------------------------------------------
def observe(state: dict) -> dict:
    # Skip alerts already processed. Under the git ledger (run_ledgered_loop), `_done_units` carries
    # the ids already proven in git — so resume-from-ledger works without the STATE_FILE list.
    seen = set(_load_state()["processed"]) | set(state.get("_done_units", set()))
    hits = _search({"query": {"range": {"rule.level": {"gte": MIN_LEVEL}}}}, size=25)
    alert = next((h for h in hits if h["_id"] not in seen), None)
    if alert is None:
        return {"text": "no unprocessed alerts at or above the minimum level", "no_alert": True}
    src = alert["_source"]
    ctx = {
        "id": alert["_id"],
        "level": src["rule"]["level"],
        "rule_id": src["rule"]["id"],
        "description": src["rule"]["description"],
        "mitre": src["rule"].get("mitre", {}).get("technique", []),
        "agent": src.get("agent", {}).get("name", "unknown"),
        "srcip": src.get("data", {}).get("srcip"),
        "timestamp": src["timestamp"],
        "full_log": (src.get("full_log") or "")[:400],
    }
    state["alert"] = ctx
    text = (f"Alert on agent '{ctx['agent']}': {ctx['description']} "
            f"(rule {ctx['rule_id']}, level {ctx['level']}"
            + (f", srcip {ctx['srcip']}" if ctx['srcip'] else "") + ")")
    return {"text": text, "no_alert": False, "rule_level": ctx["level"]}


def enrich(state: dict) -> dict:
    a = state["alert"]
    day = {"range": {"timestamp": {"gte": "now-24h"}}}
    same_agent = _count({"query": {"bool": {"filter": [
        day, {"term": {"agent.name": a["agent"]}},
        {"range": {"rule.level": {"gte": MIN_LEVEL}}}]}}})
    same_rule = _count({"query": {"bool": {"filter": [
        day, {"term": {"rule.id": a["rule_id"]}}]}}})
    parts = [f"Last 24h: {same_agent} alerts (level>={MIN_LEVEL}) from agent "
             f"'{a['agent']}'; rule {a['rule_id']} fired {same_rule} times."]
    if a["srcip"]:
        same_src = _count({"query": {"bool": {"filter": [
            day, {"term": {"data.srcip": a["srcip"]}}]}}})
        parts.append(f"Source {a['srcip']} appears in {same_src} alerts.")
    state["context_brief"] = " ".join(parts)
    return {"text": state["context_brief"], "rule_level": a["level"]}


def vector_prefilter(state: dict) -> dict:
    """Vector pre-filter gate (prismpath.prefilter.PrefilterCache). Embed the alert,
    cosine-match against the corpus of already-adjudicated alerts. A near-identical,
    high-confidence match auto-resolves the alert (reuse the prior action) and SKIPS
    the LLM classify entirely — the dominant escalation-reduction lever. On a miss,
    fall through to classify.

    The embedding is stashed in state so the learning loop (in classify) can reuse it
    instead of re-embedding.

    Reuse is scoped to the current POLICY_HASH (a triage-flow edit auto-invalidates stale verdicts) and
    a SHADOW_RATE fraction of hits is audited against the live LLM (see _shadow_audit)."""
    a = state["alert"]
    res = CACHE.lookup(alert_document(a), policy_hash=POLICY_HASH, sample_rate=SHADOW_RATE)
    state["prefilter_vector"] = res.vector
    if res.hit:
        cached = res.record["action"]
        # Populate the fields downstream nodes (stage_containment / report) expect,
        # since classify never ran. This verdict is inherited from the prior match.
        state["assessment"] = (f"AUTO-RESOLVED by vector pre-filter: near-identical "
                               f"(cosine {res.similarity:.3f} >= {CACHE.threshold}) to a "
                               f"prior '{cached}' adjudication (conf "
                               f"{res.record['confidence']:.2f}): "
                               f"{res.record['description']}. LLM classify skipped.")
        state["verdict"] = {"threat_class": "prefilter_cached", "is_active_threat": cached == "contain",
                            "confidence": res.record["confidence"], "recommended_action": cached,
                            "rationale": state["assessment"], "prefilter": True,
                            "matched_key": res.record["key"], "similarity": round(res.similarity, 4)}
        # Self-policing: on a shadow-sampled hit, run the real adjudicator anyway and compare — the
        # verdict is STILL reused this cycle; the comparison only feeds the cache's drift monitor.
        shadow_note = _shadow_audit(a, state, res, cached) if res.shadow else ""
        return {"text": f"HIT: cosine {res.similarity:.3f} -> reuse '{cached}' verdict "
                        f"(matched {res.record['key']}); SKIP LLM{shadow_note}",
                "prefilter_hit": True, "cached_action": cached,
                "rule_level": a["level"], "recommended_action": cached}
    return {"text": f"MISS: top cosine {res.similarity:.3f} < {CACHE.threshold} "
                    f"(corpus={len(CACHE)}); escalating to LLM classify",
            "prefilter_hit": False, "cached_action": None, "rule_level": a["level"]}


def _shadow_audit(a: dict, state: dict, res, cached_action: str) -> str:
    """Roadmap item #3 self-policing. On a shadow-sampled cache hit, run the SAME classify oracle the
    reuse-accuracy experiment uses (classify_verdict) and feed the (reused vs oracle) comparison back to
    the cache via record_shadow. Sustained disagreement quarantines the entry so it stops auto-resolving
    — the continuous reuse-error signal, measured live rather than only in an offline sweep. Never lets
    the audit break a live triage cycle. Returns a short note appended to the node log."""
    try:
        oracle = classify_verdict(a, state["context_brief"])
        oracle_action = oracle.get("recommended_action", "watch")
        rep = CACHE.record_shadow(res.record["key"], cached_action, oracle_action)
        tag = "QUARANTINED" if rep["quarantined"] else ("agree" if rep["agree"] else "DISAGREE")
        return (f" | shadow[{tag}] reused={cached_action} oracle={oracle_action} n={rep['shadow_n']}")
    except Exception as e:  # noqa: BLE001 - a self-audit must never break live triage
        print(f"  [prefilter] shadow audit failed: {e!r}")
        return " | shadow[error]"


def classify_prompt(a: dict, context_brief: str) -> str:
    """The classification prompt, factored out so the live pipeline AND the reuse-accuracy shadow
    experiment (measure_reuse.py) build the SAME prompt — the oracle can't drift from production."""
    return (
        "You are a SOC analyst triaging ONE alert on a small homelab network "
        "(Proxmox hypervisor, OPNsense firewall, an Ubuntu VM, this GB10 host).\n"
        f"ALERT: {a['description']} | rule {a['rule_id']} level {a['level']} | "
        f"agent {a['agent']} | mitre {a['mitre'] or 'n/a'} | srcip {a['srcip'] or 'n/a'}\n"
        f"LOG EXCERPT: {a.get('full_log') or 'n/a'}\n"
        f"CONTEXT: {context_brief}\n"
        "Decide the threat class, whether it is an active threat, your confidence (0..1), and the "
        "recommended action: contain (stage a firewall block), watch (monitor), or ignore (expected "
        "noise). Weigh evidence — internal vs external source, key vs password auth, legitimacy — "
        "over the raw severity number.")


def classify_verdict(a: dict, context_brief: str, max_tokens: int = 768) -> dict:
    """The SOC classification call — same prompt+model+schema as production. Returns the structured
    verdict (recommended_action ∈ {contain, watch, ignore})."""
    return gemma_json(classify_prompt(a, context_brief), VERDICT_SCHEMA, max_tokens=max_tokens)


def classify(state: dict) -> dict:
    a = state["alert"]
    verdict = classify_verdict(a, state["context_brief"])
    state["verdict"] = verdict
    state["assessment"] = verdict.get("rationale", "")

    # --- learning loop: append this fresh adjudication to the corpus so future
    # near-identical alerts auto-resolve. Reuse the embedding from vector_prefilter.
    try:
        vec = state.get("prefilter_vector")
        if vec is None:
            vec = alert_document(a)  # learn() embeds a raw document itself
        CACHE.learn(vec, verdict.get("recommended_action", "watch"),
                    verdict.get("confidence", 0.0) or 0.0,
                    key=alert_key(a), description=a.get("description", ""),
                    policy_hash=POLICY_HASH)
    except Exception as e:  # never let corpus write break a live triage cycle
        print(f"  [prefilter] learning-loop append failed: {e!r}")

    return {"text": f"{verdict.get('threat_class', '?')} / {verdict.get('recommended_action', '?')} "
                    f"(conf {verdict.get('confidence', '?')}): {verdict.get('rationale', '')}",
            "rule_level": a["level"],
            "threat_class": verdict.get("threat_class"),
            "is_active_threat": verdict.get("is_active_threat"),
            "confidence": verdict.get("confidence"),
            "recommended_action": verdict.get("recommended_action")}


def stage_containment(state: dict) -> dict:
    a = state["alert"]
    rationale = gemma(
        "Draft a containment proposal for a human firewall operator. "
        f"ALERT: {a['description']} (rule {a['rule_id']}, level {a['level']}, "
        f"agent {a['agent']}, srcip {a['srcip'] or 'none'}).\n"
        f"ASSESSMENT: {state['assessment']}\n"
        "Give: (1) the single OPNsense rule you propose (plain description, e.g. "
        "'block inbound from <ip> on WAN, log'), (2) blast-radius: what could break, "
        "(3) rollback: how to undo. Keep it under 10 lines.",
        max_tokens=300)
    DRAFTS.mkdir(parents=True, exist_ok=True)
    path = DRAFTS / f"{_now()}-rule{a['rule_id']}-{a['id'][:8]}.md"
    path.write_text(
        f"# OPNsense rule draft — APPROVAL: PENDING\n\n"
        f"Generated by wazuh_triage (prismpath) at {_now()}. DO NOT APPLY without human review.\n\n"
        f"## Alert\n{json.dumps(a, indent=2)}\n\n"
        f"## Analyst assessment (gemma4)\n{state['assessment']}\n\n"
        f"## Structured verdict\n{json.dumps(state.get('verdict', {}), indent=2)}\n\n"
        f"## Proposed containment\n{rationale}\n\n"
        f"## Reasoning chain\n{state['context_brief']}\n")
    state["draft_path"] = str(path)
    return {"text": f"containment draft staged at {path.name}", "rule_level": a["level"]}


def verify_staged(state: dict) -> dict:
    p = Path(state.get("draft_path", ""))
    ok = (p.is_file() and p.stat().st_size > 200
          and "APPROVAL: PENDING" in p.read_text()
          and "## Reasoning chain" in p.read_text())
    return {"text": f"staged draft verified on disk: {ok} ({p.name if p.name else 'missing'})",
            "staged_ok": ok}


def watchlist(state: dict) -> dict:
    a = state["alert"]
    BASE.mkdir(exist_ok=True)
    # Idempotent: keyed on the alert id, so a replayed alert never double-appends (Slice-2 DoD).
    upsert_jsonl(WATCHLIST, {"id": a["id"], "ts": _now(), "agent": a["agent"],
                            "rule_id": a["rule_id"], "srcip": a["srcip"], "desc": a["description"]},
                 key="id")
    return {"text": f"added to watchlist: rule {a['rule_id']} on {a['agent']}"
                    + (f" / src {a['srcip']}" if a["srcip"] else "")}


def benign(state: dict) -> dict:
    a = state["alert"]
    BASE.mkdir(exist_ok=True)
    upsert_jsonl(BENIGN, {"id": a["id"], "ts": _now(), "agent": a["agent"], "rule_id": a["rule_id"],
                         "desc": a["description"], "why": state.get("assessment", "")[:300]},
                 key="id")
    return {"text": f"stored benign pattern for rule {a['rule_id']} on {a['agent']}"}


def escalate_human(state: dict) -> dict:
    BASE.mkdir(exist_ok=True)
    p = BASE / f"ESCALATION-{_now()}.md"
    p.write_text(f"# Escalation — staging failed\n\nalert: "
                 f"{json.dumps(state.get('alert', {}), indent=2)}\n\n"
                 f"assessment: {state.get('assessment', 'n/a')}\n"
                 f"draft_path: {state.get('draft_path', 'n/a')}\n")
    return {"text": f"escalation written: {p.name}"}


def report(state: dict) -> dict:
    a = state.get("alert")
    REPORTS.mkdir(parents=True, exist_ok=True)
    path = REPORTS / f"{_now()}-triage-{(a or {}).get('id', 'none')[:8]}.md"
    lines = [f"# Triage report — {_now()}", ""]
    if a:
        lines += [f"**Alert:** {a['description']} (rule {a['rule_id']}, level {a['level']}, "
                  f"agent {a['agent']})", ""]
    for step in state.get("transcript", []):
        node = step.get("node", "?") if isinstance(step, dict) else str(step)
        out = step.get("outcome", step.get("text", "")) if isinstance(step, dict) else ""
        lines.append(f"- **{node}**: {str(out)[:300]}")
    path.write_text("\n".join(lines) + "\n")
    if a:
        s = _load_state()
        s["processed"].append(a["id"])
        _save_state(s)
    return {"text": f"triage report written: {path.name}; alert marked processed"}


def idle(state: dict) -> dict:
    return {"text": "no work — all current alerts processed"}


# --- prefilter corpus seeding from past adjudications --------------------------------
def _seed_from_drafts() -> list:
    """OPNsense rule drafts carry the full alert JSON + the structured verdict
    (recommended_action + confidence) — the richest seed source."""
    out = []
    ddir = BASE / "opnsense-rule-drafts"
    if not ddir.exists():
        return out
    for p in sorted(ddir.glob("*.md")):
        txt = p.read_text()
        am = re.search(r"## Alert\n(\{.*?\})\n\n## ", txt, re.DOTALL)
        vm = re.search(r"## Structured verdict\n(\{.*?\})\n\n## ", txt, re.DOTALL)
        if not am:
            continue
        try:
            alert = json.loads(am.group(1))
        except Exception:
            continue
        action, conf = "contain", 0.8  # drafts land on the contain path by default
        if vm:
            try:
                v = json.loads(vm.group(1))
                action = v.get("recommended_action", action)
                conf = float(v.get("confidence", conf))
            except Exception:
                pass
        else:
            # Older drafts (pre structured-verdict) have no verdict block. A draft
            # can be staged purely because rule_level>=12, even when the analyst
            # judged it benign — so infer the true action from the proposal text:
            # "No containment / None / N/A" => the analyst said ignore, not contain.
            pm = re.search(r"## Proposed containment\n(.*?)\n\n## ", txt, re.DOTALL)
            proposal = (pm.group(1) if pm else "").lower()
            if re.search(r"no containment|not required|proposal:\s*none|rule:\*\*?\s*none|\bn/a\b",
                         proposal):
                action = "ignore"
        out.append((alert, action, conf))
    return out


def _seed_from_benign() -> list:
    """benign_patterns.jsonl == deliberately-stored 'ignore' adjudications."""
    out = []
    bp = BASE / "benign_patterns.jsonl"
    if not bp.exists():
        return out
    for line in bp.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        alert = {"description": r.get("desc", ""), "agent": r.get("agent", ""),
                 "srcip": None, "mitre": [], "rule_id": r.get("rule_id", "")}
        out.append((alert, "ignore", 0.9))
    return out


def _seed_from_reports() -> list:
    """Triage reports record the decision PATH -> recommended_action, plus the
    alert description/rule/agent/srcip in the observe line. Confidence is not in
    the report, so a conservative 0.8 is assumed (meets the gate's min_conf)."""
    out = []
    rdir = BASE / "triage-reports"
    if not rdir.exists():
        return out
    for p in sorted(rdir.glob("*.md")):
        txt = p.read_text()
        if "stage_containment" in txt or "verify_staged" in txt:
            action = "contain"
        elif "watchlist" in txt:
            action = "watch"
        elif "benign" in txt:
            action = "ignore"
        else:
            continue
        hm = re.search(r"\*\*Alert:\*\* (.+?) \(rule (\d+), level (\d+), agent ([^)]+)\)", txt)
        om = re.search(r"srcip ([0-9a-fA-F\.:]+)", txt)
        if not hm:
            continue
        alert = {"description": hm.group(1).strip(), "rule_id": hm.group(2),
                 "agent": hm.group(4).strip(), "srcip": om.group(1) if om else None,
                 "mitre": []}
        out.append((alert, action, 0.8))
    return out


def seed_corpus(rebuild: bool = True) -> dict:
    """(Re)build the prefilter corpus from all past adjudications (drafts + benign +
    reports), de-duplicated by alert_key (highest-confidence adjudication wins).
    Returns a small stats dict."""
    sources = _seed_from_drafts() + _seed_from_benign() + _seed_from_reports()
    by_key = {}
    for alert, action, conf in sources:
        k = alert_key(alert)
        if k not in by_key or conf > by_key[k][2]:
            by_key[k] = (alert, action, conf)

    if not by_key:
        return {"seeded": 0, "note": "no adjudications found to seed from"}

    if rebuild:
        CACHE.clear()
    items = list(by_key.items())
    vecs = CACHE.embed([alert_document(alert) for _, (alert, _, _) in items])
    for (k, (alert, action, conf)), vec in zip(items, vecs):
        CACHE.learn(vec, action, conf, key=k, description=alert.get("description", ""),
                    policy_hash=POLICY_HASH)
    return {"seeded": len(items), **CACHE.stats()}


HANDLERS = {
    "observe": observe, "enrich": enrich, "vector_prefilter": vector_prefilter,
    "classify": classify,
    "stage_containment": stage_containment, "verify_staged": verify_staged,
    "watchlist": watchlist, "benign": benign, "escalate_human": escalate_human,
    "report": report, "idle": idle,
}


class WazuhTriageConnector(BaseConnector):
    """The SOC triage adapter on the Connector SDK — the HANDLERS dict promoted onto the
    six-port base. Dispatch (with `_worker` provenance stamped into every outcome) comes from
    BaseConnector; the SIEM ingestion rides the siem.py port; attestation/deferral/sink come
    with the base. A node without a handler degrades to a soft note (the flow keeps routing)
    rather than the SDK's hard NotImplementedError — triage prefers a readable transcript over
    a crash."""

    def __init__(self):
        super().__init__("soc.wazuh_triage", "1.0.0")
        for name, fn in HANDLERS.items():
            self.register_handler(name, fn)

    def fallback(self, node: str, instruction: str, state: dict):
        return {"text": f"(no handler for node '{node}')"}


CONNECTOR = WazuhTriageConnector()


def agent(node: str, instruction: str, state: dict):
    """Back-compat agent callable: the connector dispatch plus the per-node timing/logging the
    metrics summary reads. Existing callers (main, run_ledgered_loop, tests) are unchanged."""
    t = time.time()
    out = CONNECTOR.agent(node, instruction, state)
    NODE_TIMES.append({"node": node, "seconds": round(time.time() - t, 2)})
    print(f"  [{node}] ({NODE_TIMES[-1]['seconds']}s) {out['text'][:130]}")
    return out


def emit_labels(out_path: str) -> dict:
    """Write the adapter's past adjudications (drafts + benign + reports — the same parsers
    seed_corpus uses) as labeled decisions for `python -m prismpath.prefilter tune --labels`:
    one {"doc", "action"} row per de-duplicated adjudication. The tuner then derives the
    risk-certified operating point from THIS deployment's own history."""
    sources = _seed_from_drafts() + _seed_from_benign() + _seed_from_reports()
    by_key = {}
    for alert, action, conf in sources:
        k = alert_key(alert)
        if k not in by_key or conf > by_key[k][2]:
            by_key[k] = (alert, action, conf)
    with open(out_path, "w") as f:
        for alert, action, _conf in by_key.values():
            f.write(json.dumps({"doc": alert_document(alert), "action": action}) + "\n")
    return {"labels": len(by_key), "path": out_path}


def main_ledgered() -> int:
    """Drive the triage flow as a per-alert loop, writing a git proof-commit per handled alert and
    resuming from the ledger (SPRINT_LEDGER=1). Each alert's `report` node is the @checkpoint; the
    proof is the structured verdict. Best-effort — a git failure falls back to STATE_FILE."""
    from prismpath.ledger import Ledger, new_run_id
    from prismpath.ledger_runner import run_ledgered_loop
    router = HybridRouter(LLMRouter(gemma))
    led = Ledger(flow="wazuh_triage", run_id=os.environ.get("SPRINT_LEDGER_RUN") or new_run_id())
    committed = run_ledgered_loop(FLOW, agent, led, router=router)
    print(f"\nledger run {led.run_id} on {led.ref}")
    print(f"handled this pass: {committed or '(none — queue drained)'}")
    print(f"total proven alerts: {len(led.done_set())}")
    return 0


def main() -> int:
    if os.environ.get("SPRINT_LEDGER") == "1":
        return main_ledgered()
    graph = parse_file(FLOW)
    router = HybridRouter(LLMRouter(gemma))  # δ default (0.05) from prismpath.router
    t0 = time.time()
    result = run(graph, agent, router=router)
    total = time.time() - t0
    print(f"\npath: {' -> '.join(result.path)}")
    print(f"stopped: {result.stopped}  ({total:.1f}s total)")

    # --- metrics summary ---
    n = len(GEMMA_CALLS)
    gsum = sum(c["latency_s"] for c in GEMMA_CALLS)
    ptok = sum(c["prompt_tokens"] or 0 for c in GEMMA_CALLS)
    ctok = sum(c["completion_tokens"] or 0 for c in GEMMA_CALLS)
    slow = max(NODE_TIMES, key=lambda x: x["seconds"]) if NODE_TIMES else {"node": "-", "seconds": 0}
    print("--- metrics ---")
    print(f"  gemma calls: {n} | gemma time: {gsum:.1f}s ({100*gsum/total:.0f}% of run) "
          f"| tokens in/out: {ptok}/{ctok}")
    print(f"  slowest node: {slow['node']} ({slow['seconds']}s)")
    print(f"  per-node: " + ", ".join(f"{t['node']}={t['seconds']}s" for t in NODE_TIMES))

    metrics = {"ts": _now(), "path": result.path, "total_s": round(total, 2),
               "gemma_calls": n, "gemma_time_s": round(gsum, 2),
               "tokens_in": ptok, "tokens_out": ctok, "nodes": NODE_TIMES,
               "gemma_detail": GEMMA_CALLS,
               "alert": {k: state_alert.get(k) for k in ("level", "rule_id", "description", "srcip")}
               if (state_alert := result.state.get("alert")) else None}
    BASE.mkdir(exist_ok=True)
    with (BASE / "metrics.jsonl").open("a") as f:
        f.write(json.dumps(metrics) + "\n")
    return 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    if cmd == "seed":
        print(json.dumps(seed_corpus(rebuild=True), indent=2))
    elif cmd == "info":
        print(json.dumps(CACHE.stats(), indent=2))
    elif cmd == "labels":
        out = sys.argv[2] if len(sys.argv) > 2 else str(BASE / "triage_labels.jsonl")
        print(json.dumps(emit_labels(out), indent=2))
    elif cmd == "run":
        raise SystemExit(main())
    else:
        print(f"unknown command: {cmd} (use: run | seed | info | labels)")
