# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""trail: the operator's read side of the receipts. Summarise an append only audit log (the JSONL
`prismpath.audit_log` writes: decisions, swaps, attestations) over a window, in cause code terms, and
say whether the log's Merkle root still verifies. What decisions have been shifting, and why, is the
input to "should the policy change today"; the evaluator uses the same verb after the fact.

    prismpath trail run.audit.jsonl                 # everything, by action, outcome, and cause
    prismpath trail run.audit.jsonl --last 200      # the most recent 200 events
    prismpath trail run.audit.jsonl --since 2026-09-09T00:00:00Z --json
"""
from __future__ import annotations

import collections
import datetime as _dt
import json
import sys
from typing import Any, Dict, List, Optional

from prismpath import audit_log, causes


def _parse_since(text: Optional[str]) -> Optional[float]:
    if not text:
        return None
    t = text.replace("Z", "+00:00")
    d = _dt.datetime.fromisoformat(t)
    if d.tzinfo is None:
        d = d.replace(tzinfo=_dt.timezone.utc)
    return d.timestamp()


def summarise(events: List[dict]) -> Dict[str, Any]:
    by_action: collections.Counter = collections.Counter(ev.get("action", "?") for ev in events)
    decisions = [ev for ev in events if ev.get("action") == "decision"]
    outcomes: collections.Counter = collections.Counter(str((ev.get("data") or {}).get("outcome")) for ev in decisions)
    by_cause: collections.Counter = collections.Counter()
    for ev in decisions:
        code = (ev.get("data") or {}).get("cause")
        if code is None:
            label = "unrecorded"
        elif int(code) == 0:
            label = "0 clean"                      # 0 is the clean decision, outside the registry's refusal bands
        else:
            label = f"{code} {causes.name(int(code)) or 'unregistered'}"
        by_cause[label] += 1
    rules: collections.Counter = collections.Counter(str((ev.get("data") or {}).get("rule")) for ev in decisions)
    swaps = [ev for ev in events if ev.get("action") in ("swap", "swap_rejected", "rollback", "attestation")]
    swap_lines = []
    for ev in swaps:
        d = ev.get("data") or {}
        when = _dt.datetime.fromtimestamp(float(ev.get("ts", 0)), _dt.timezone.utc).isoformat(timespec="seconds")
        if ev["action"] == "swap":
            swap_lines.append(f"{when} swap accepted -> version {d.get('version')} {str(d.get('to_hash'))[:12]}"
                              + (f" overlay of {d['overlay_of']}" if d.get("overlay_of") else ""))
        elif ev["action"] == "swap_rejected":
            swap_lines.append(f"{when} swap refused: {','.join(d.get('reasons', []))}")
        elif ev["action"] == "rollback":
            swap_lines.append(f"{when} rollback -> {str(d.get('to_hash'))[:12]}")
        else:
            swap_lines.append(f"{when} attestation: version {d.get('version')}"
                              + (f" overlay of {d['overlay_of']}" if d.get("overlay_of") else ""))
    first = min((float(ev.get("ts", 0)) for ev in events), default=None)
    last = max((float(ev.get("ts", 0)) for ev in events), default=None)
    return {"events": len(events), "decisions": len(decisions),
            "window": {"first": first, "last": last},
            "by_action": dict(by_action), "outcomes": dict(outcomes), "causes": dict(by_cause),
            "rules": dict(rules), "swaps": swap_lines}


def run(path: str, since: Optional[str] = None, last: Optional[int] = None) -> Dict[str, Any]:
    log = audit_log.AuditLog(path)
    events = list(log.events)
    t0 = _parse_since(since)
    if t0 is not None:
        events = [ev for ev in events if float(ev.get("ts", 0)) >= t0]
    if last:
        events = events[-last:]
    out = summarise(events)
    out["log"] = {"path": path, "total_events": len(log.events), "merkle_root": log.current_root(),
                  "verifies": log.verify_log()}
    return out


def render(rep: Dict[str, Any]) -> str:
    lines = [f"trail: {rep['log']['path']}  events {rep['events']} of {rep['log']['total_events']}  "
             f"root {rep['log']['merkle_root'][:16] or '(empty)'}  verifies {rep['log']['verifies']}"]
    if rep["window"]["first"] is not None:
        f = _dt.datetime.fromtimestamp(rep["window"]["first"], _dt.timezone.utc).isoformat(timespec="seconds")
        l = _dt.datetime.fromtimestamp(rep["window"]["last"], _dt.timezone.utc).isoformat(timespec="seconds")
        lines.append(f"window: {f} to {l}")
    lines.append("by action: " + ", ".join(f"{k} {v}" for k, v in sorted(rep["by_action"].items())))
    if rep["decisions"]:
        lines.append(f"decisions {rep['decisions']}:")
        lines.append("  outcomes: " + ", ".join(f"{k} {v}" for k, v in sorted(rep["outcomes"].items(), key=lambda kv: -kv[1])))
        lines.append("  causes:   " + ", ".join(f"{k} x{v}" for k, v in sorted(rep["causes"].items(), key=lambda kv: -kv[1])))
        lines.append("  rules:    " + ", ".join(f"{k} {v}" for k, v in sorted(rep["rules"].items(), key=lambda kv: -kv[1])))
    for sl in rep["swaps"]:
        lines.append("  " + sl)
    return "\n".join(lines)


def trail_cmd(args) -> int:
    rep = run(args.audit_log, since=args.since, last=args.last)
    print(json.dumps(rep, indent=1) if args.json else render(rep))
    return 0 if rep["log"]["verifies"] else 1


def add_parser(subparsers) -> None:
    p = subparsers.add_parser("trail", help="Summarise an audit log over a window: decisions by outcome, rule, and cause code, "
                                            "swaps and attestations, and whether the Merkle root verifies")
    p.add_argument("audit_log", help="an append only JSONL written by prismpath.audit_log (decisions, swaps, attestations)")
    p.add_argument("--since", default=None, help="ISO 8601 lower bound on event time (UTC if no zone)")
    p.add_argument("--last", type=int, default=None, help="only the most recent N events")
    p.add_argument("--json", action="store_true", help="machine readable output")
    p.set_defaults(func=trail_cmd)
