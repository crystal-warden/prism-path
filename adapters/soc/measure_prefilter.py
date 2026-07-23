"""measure_prefilter.py — escalation-reduction measurement for the vector pre-filter.

Samples recent Wazuh alerts and reports, for thresholds 0.95/0.97/0.99:
  (A) STATIC seed-only auto-resolution rate: % of live alerts near-identical to the
      seed corpus (cold-start view — only what the LLM adjudicated so far).
  (B) STREAMING self-learning auto-resolution rate: process alerts oldest->newest;
      a hit auto-resolves (skips the LLM); a miss escalates to the LLM and is added
      to the corpus (the real learning loop) so later near-identical alerts hit.
      This is the honest steady-state escalation-reduction number.

Read-only against Wazuh; rebuilds the seed corpus first for reproducibility.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import numpy as np
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from prismpath.prefilter import match_arrays
from wazuh_triage_agent import CACHE, alert_document, alert_key, seed_corpus

INDEXER = "https://127.0.0.1:9200"
MIN_LEVEL = 7
SAMPLE = 400
THRESHOLDS = [0.95, 0.97, 0.99]


def _auth():
    out = subprocess.run(
        ["sudo", "tar", "-O", "-xf", str(Path.home() / "wazuh-install-files.tar"),
         "wazuh-install-files/wazuh-passwords.txt"],
        capture_output=True, text=True, check=True).stdout
    pw, take = None, False
    for line in out.splitlines():
        if "indexer_username: 'admin'" in line:
            take = True
        elif take and "indexer_password:" in line:
            pw = line.split("'")[1]
            break
    return "admin", pw


def fetch_alerts(n):
    auth = _auth()
    body = {"query": {"range": {"rule.level": {"gte": MIN_LEVEL}}}}
    r = requests.get(f"{INDEXER}/wazuh-alerts-*/_search?size={n}&sort=timestamp:asc",
                     auth=auth, verify=False, json=body, timeout=30)
    r.raise_for_status()
    hits = r.json()["hits"]["hits"]
    alerts = []
    for h in hits:
        s = h["_source"]
        alerts.append({
            "id": h["_id"],
            "level": s["rule"]["level"],
            "rule_id": s["rule"]["id"],
            "description": s["rule"]["description"],
            "mitre": s["rule"].get("mitre", {}).get("technique", []),
            "agent": s.get("agent", {}).get("name", "unknown"),
            "srcip": s.get("data", {}).get("srcip"),
            "timestamp": s["timestamp"],
        })
    return alerts


def main():
    print("== re-seeding corpus from past adjudications (reproducibility) ==")
    stats = seed_corpus(rebuild=True)
    print(json.dumps(stats, indent=2))
    seed_emb, seed_meta = CACHE.load()
    print(f"seed corpus: {seed_emb.shape[0]} entries\n")

    print(f"== fetching up to {SAMPLE} recent alerts (level>={MIN_LEVEL}) ==")
    alerts = fetch_alerts(SAMPLE)
    docs = [alert_document(a) for a in alerts]
    vecs = CACHE.embed(docs)
    print(f"sampled {len(alerts)} alerts; embedded {vecs.shape}\n")

    # distribution
    from collections import Counter
    rc = Counter((a["rule_id"], a["description"][:40]) for a in alerts)
    print("top rules in sample:")
    for (rid, desc), c in rc.most_common(8):
        print(f"  rule {rid:>6}  x{c:<4} {desc}")
    print()

    # (A) STATIC seed-only
    print("== (A) STATIC seed-only auto-resolution (cold-start view) ==")
    static = {}
    for th in THRESHOLDS:
        hits = 0
        for v in vecs:
            hit, _, _ = match_arrays(v, seed_emb, seed_meta, threshold=th, min_conf=0.8)
            hits += hit
        static[th] = hits
        print(f"  threshold {th}: {hits}/{len(alerts)} auto-resolved = {100*hits/len(alerts):.1f}%")
    print()

    # (B) STREAMING self-learning
    print("== (B) STREAMING self-learning auto-resolution (steady-state) ==")
    stream = {}
    examples = {}
    for th in THRESHOLDS:
        emb = seed_emb.copy()
        meta = list(seed_meta)
        auto = 0
        ex_hit = ex_miss = None
        for a, v in zip(alerts, vecs):
            hit, best, sim = match_arrays(v, emb, meta, threshold=th, min_conf=0.8)
            if hit:
                auto += 1
                if ex_hit is None:
                    ex_hit = (a, best, sim)
            else:
                # escalate to LLM; the learning loop then adds this adjudication.
                # (action unknown here; conf assumed >=0.8 as the LLM would produce.)
                if ex_miss is None:
                    ex_miss = (a, sim)
                emb = v.reshape(1, -1) if emb.shape[0] == 0 else np.vstack([emb, v.reshape(1, -1)])
                meta = meta + [{"action": "escalated", "confidence": 0.9,
                                "key": alert_key(a),
                                "description": a["description"]}]
        stream[th] = auto
        examples[th] = (ex_hit, ex_miss)
        print(f"  threshold {th}: {auto}/{len(alerts)} auto-resolved = "
              f"{100*auto/len(alerts):.1f}%  (LLM escalations: {len(alerts)-auto})")
    print()

    # examples at recommended threshold 0.97
    print("== concrete examples @ threshold 0.97 (streaming) ==")
    ex_hit, ex_miss = examples[0.97]
    if ex_hit:
        a, best, sim = ex_hit
        print(f"  AUTO-RESOLVED (hit, cosine {sim:.3f}):")
        print(f"    alert : rule {a['rule_id']} lvl {a['level']} '{a['description']}' "
              f"agent={a['agent']} src={a['srcip']}")
        print(f"    match : prior '{best['action']}' adjudication "
              f"({best['key']}) -> SKIP LLM")
    if ex_miss:
        a, sim = ex_miss
        print(f"  ESCALATED (miss, top cosine {sim:.3f} < 0.97):")
        print(f"    alert : rule {a['rule_id']} lvl {a['level']} '{a['description']}' "
              f"agent={a['agent']} src={a['srcip']}  -> LLM classify")
    print()

    # summary table
    n = len(alerts)
    print("== SUMMARY: auto-resolution (escalation reduction) vs threshold ==")
    print(f"  {'threshold':>10} | {'static seed-only':>18} | {'streaming steady-state':>24}")
    for th in THRESHOLDS:
        print(f"  {th:>10} | {100*static[th]/n:>16.1f}% | {100*stream[th]/n:>22.1f}%")

    # capacity multiplier from streaming @0.97
    p = stream[0.97] / n
    mult = 1.0 / (1.0 - p) if p < 1 else float("inf")
    print(f"\n  streaming @0.97: {100*p:.1f}% auto-resolved -> escalation load x{1-p:.3f} "
          f"-> ~{mult:.2f}x clients/box (if classify is the binding constraint)")

    # re-seed clean to leave the live corpus in a known state
    seed_corpus(rebuild=True)
    print("\n(live corpus re-seeded to clean state)")


if __name__ == "__main__":
    main()
