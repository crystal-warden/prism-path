# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Freeze the fleet-migration corpus (`spec-crypto-agility.md` §10.5, §12).

A family of suite-selection policies `policy_k` each permit the classical suite only *below* migration
phase `k` (so past phase `k`, only quantum-resistant suites are reachable). Proving the monotone-
migration property (P4) for every (policy-gate `k`, envelope-floor `f`) pair characterizes it exactly:

    P4 holds  <=>  f >= k

i.e. a policy that gates classical at phase `k` satisfies every floor at or above `k`, and provably
fails every floor below it. The corpus freezes the whole matrix; the replay test asserts both that it
reproduces byte-for-byte and that the `f >= k` invariant holds in every cell (so it can never silently
degrade into a vacuous all-pass).

    python -m prismpath.portable.gen_crypto_migration_fixtures      # regenerate
"""
from __future__ import annotations

import json
from pathlib import Path

from prismpath import crypto_agility as ca
from prismpath import crypto_registry as cr
from prismpath.parser import parse

HERE = Path(__file__).resolve().parent
OUT = HERE / "conformance" / "crypto_migration.json"

SUITES = {
    "cnsa2-hybrid-1":           {"kem": "x25519+ml-kem-1024", "sig": "ml-dsa-87", "aead": "aes-256-gcm",     "provider": "cryptography>=44", "strength_rank": 3},
    "tls13-hybrid-x25519mlkem": {"kem": "x25519+ml-kem-768",  "sig": "ed25519",   "aead": "chacha20poly1305", "provider": "cryptography",     "strength_rank": 2},
    "tls13-aesgcm":             {"kem": "x25519",             "sig": "ed25519",   "aead": "aes-256-gcm",      "provider": "cryptography",     "strength_rank": 1},
}
KEY_ID = "0" * 64
GATES = [1, 2, 3]
FLOORS = [0, 1, 2, 3]


def phase_policy(k: int) -> str:
    return f"""---
name: ca_phase_{k}
start: classify
---
## classify
-> cui-path: when data_class == "cui"
-> legacy-path: when migration_phase < {k}
-> hybrid-path: else
## cui-path
-> suite-cnsa2-hybrid-1: when always
## legacy-path
-> suite-tls13-aesgcm: when always
## hybrid-path
-> suite-tls13-hybrid-x25519mlkem: when always
## suite-cnsa2-hybrid-1
-> end: when always
## suite-tls13-aesgcm
-> end: when always
## suite-tls13-hybrid-x25519mlkem
-> end: when always
## end
done
"""


def _envelope(registry_hash: str, floor: int) -> dict:
    return {"envelope_id": f"floor-{floor}", "approved_suites": sorted(SUITES),
            "class_field": "data_class", "migration_phase_field": "migration_phase",
            "migration_phase_floor": floor, "registry_hash": registry_hash, "key_id": KEY_ID}


def build() -> dict:
    registry = cr.build_registry(SUITES, key_id=KEY_ID)
    rh = cr.registry_hash(registry)
    cells = []
    for k in GATES:
        graph = parse(phase_policy(k))
        for f in FLOORS:
            p4 = ca.prove_monotone_migration(graph, _envelope(rh, f), registry)
            cells.append({"policy_gate": k, "envelope_floor": f, "p4": p4,
                          "invariant_holds": (p4["ok"] == (f >= k))})
    return {"format": "crypto-migration-conformance/1", "registry_hash": rh,
            "gates": GATES, "floors": FLOORS, "cells": cells}


def main() -> int:
    data = build()
    OUT.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")
    passes = sum(1 for c in data["cells"] if c["p4"]["ok"])
    inv = all(c["invariant_holds"] for c in data["cells"])
    print(f"wrote {OUT.relative_to(HERE.parent.parent)}: {len(data['cells'])} cells "
          f"({passes} P4-pass), f>=k invariant holds in every cell: {inv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
