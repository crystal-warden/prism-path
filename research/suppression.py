#!/usr/bin/env python3
"""Per-environment suppression/context layer for triage (task #44).

Deterministic, versioned PER TENANT — the pilot's tuning-window deliverable, made a first-class
artifact instead of tribal knowledge. Two rule kinds:
  - hard:    (rule_id[, agent, srcip, contains]) -> auto-disposition (ignore|watch), SKIP the LLM
             (cost saving + FP elimination on KNOWN-benign patterns for this environment).
  - context: same match -> inject a benign-context note into the classify prompt so the LLM
             adjudicates INFORMED (doesn't blindly suppress — the reviewer's "don't over-tune").
Config is JSON per environment, HASH-VERSIONED (an edit rotates the hash, like the flow-hash, so a
downstream cache/ledger can invalidate rules learned under an old config). This is legitimate SOC
triage-layer tuning/allowlisting (NOT the detector-layer CDN allowlist we rejected — different layer,
different threat model). FLYWHEEL HOOK (#38): repeated AUTHORITATIVE benign dispositions get promoted
to context/hard rules via `propose_rule()`.
"""
import json, hashlib

def load_config(path):
    raw=open(path,"rb").read(); cfg=json.loads(raw)
    cfg["_hash"]="sha256:"+hashlib.sha256(raw).hexdigest()[:16]
    return cfg

def _matches(alert, r):
    if str(r.get("rule_id","*")) not in ("*", str(alert.get("rule_id"))): return False
    if "agent"  in r and r["agent"]  != alert.get("agent"):  return False
    if "srcip"  in r and r["srcip"]  != alert.get("srcip"):  return False
    if "contains" in r and r["contains"].lower() not in str(alert.get("description","")).lower(): return False
    return True

def apply(alert, cfg):
    """First matching rule wins. -> {kind, action, note, rule, env, env_hash} or None (pass through)."""
    for r in cfg.get("rules", []):
        if _matches(alert, r):
            return dict(kind=r.get("kind","hard"), action=r.get("action"), note=r.get("note",""),
                        rule=str(r.get("rule_id")), env=cfg.get("environment"), env_hash=cfg["_hash"])
    return None

def triage_gate(alert, cfg):
    """The flow's integration point (slots AFTER observe/enrich, BEFORE vector_prefilter/classify):
      hard    -> auto-resolved, skip LLM: {'resolved':True, 'action':..., 'via':'suppression', ...}
      context -> pass to classify but carry a context note: {'resolved':False, 'context':note}
      None    -> {'resolved':False, 'context':None} (normal prefilter/LLM path)."""
    m=apply(alert, cfg)
    if m is None: return {"resolved":False, "context":None}
    if m["kind"]=="hard":
        return {"resolved":True, "action":m["action"], "via":"suppression",
                "note":m["note"], "rule":m["rule"], "env_hash":m["env_hash"]}
    return {"resolved":False, "context":m["note"], "context_rule":m["rule"], "env_hash":m["env_hash"]}

def propose_rule(rule_id, action, note, agent=None, kind="context", min_confidence=0.9):
    """Flywheel hook: turn a repeated AUTHORITATIVE benign disposition into a proposed suppression rule
    (context by default — conservative; a human promotes to hard). Never auto-promotes to hard."""
    r={"rule_id":str(rule_id), "kind":kind, "action":action, "note":note, "_proposed":True}
    if agent: r["agent"]=agent
    return r
