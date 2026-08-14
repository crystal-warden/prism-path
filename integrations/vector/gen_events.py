#!/usr/bin/env python3
"""Emit Vector-shaped cyber-physical fusion events as NDJSON (a stand-in for any real Vector source)."""
import json, random, sys

n = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
random.seed()
stab = ["still", "moving", "shaken"]
act = ["none", "watch", "contain"]
for i in range(n):
    print(json.dumps({
        "timestamp": "2026-01-01T00:00:%02dZ" % (i % 60),
        "host": "tac-node-%02d" % (i % 8),
        "source_type": "cyber_physical_fusion",
        "service": "fusion-correlate",
        "dev_mg": random.randint(0, 3000),
        "rule_level": random.randint(0, 15),
        "stability": random.choice(stab),
        "soc_action": random.choice(act),
        "message": "fused IMU posture + SIEM verdict",
    }))
