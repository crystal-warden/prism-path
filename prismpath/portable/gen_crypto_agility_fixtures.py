"""Freeze the crypto-agility conformance fixture (`spec-crypto-agility.md` §10.3).

Emits `conformance/crypto_agility.json`: the signed-registry contents + its hash, the CNSA-2 envelope,
and a set of cases (the baseline policy plus deliberate downgrade/lax/unapproved/non-total variants),
each with its full P1-P5 proof output as computed by the Python reference. Any runtime that ports the
proofs replays these and must match byte-for-byte — and the negative cases pin that the proofs stay
falsifiable, not just green.

    python -m prismpath.portable.gen_crypto_agility_fixtures      # regenerate
"""
from __future__ import annotations

import json
from pathlib import Path

from prismpath import crypto_agility as ca
from prismpath import crypto_registry as cr
from prismpath.parser import parse

HERE = Path(__file__).resolve().parent
FLOW = HERE.parent / "flows" / "crypto_agility_cnsa2.md"
OUT = HERE / "conformance" / "crypto_agility.json"

# The registry is keyed to a fixed authority id so the frozen registry_hash is stable across machines
# (the fixture verifies hashing/proof determinism, not a live signature — signing is exercised in
# test_crypto_registry).
SUITES = {
    "cnsa2-hybrid-1":           {"kem": "x25519+ml-kem-1024", "sig": "ml-dsa-87", "aead": "aes-256-gcm",     "provider": "cryptography>=44", "strength_rank": 3},
    "tls13-hybrid-x25519mlkem": {"kem": "x25519+ml-kem-768",  "sig": "ed25519",   "aead": "chacha20poly1305", "provider": "cryptography",     "strength_rank": 2},
    "tls13-aesgcm":             {"kem": "x25519",             "sig": "ed25519",   "aead": "aes-256-gcm",      "provider": "cryptography",     "strength_rank": 1},
}
KEY_ID = "0" * 64                                        # placeholder authority id, fixture-stable


def envelope(registry_hash: str) -> dict:
    return {
        "envelope_id": "cnsa2-2026",
        "fields": {"peer_class": "str", "data_class": "str",
                   "migration_phase": "int", "hw_floor": "int"},
        "approved_suites": sorted(SUITES),
        "min_suite_by_class": {"cui": "cnsa2-hybrid-1"},
        "class_field": "data_class",
        "migration_phase_field": "migration_phase",
        "migration_phase_floor": 2,
        "registry_hash": registry_hash,
        "require_level_m": True,
        "key_id": KEY_ID,
    }


def _mini(*edges_by_node: str) -> str:
    return "\n".join(edges_by_node) + "\n"


# Negative variants — each must trip exactly one proof (documented alongside the expected output).
DOWNGRADE = """---
name: ca_downgrade
start: classify
---
## classify
-> suite-tls13-aesgcm: when data_class == "cui"
-> suite-cnsa2-hybrid-1: else
## suite-tls13-aesgcm
-> end: when always
## suite-cnsa2-hybrid-1
-> end: when always
## end
done
"""

LAX_PHASE = """---
name: ca_lax_phase
start: classify
---
## classify
-> suite-cnsa2-hybrid-1: when data_class == "cui"
-> suite-tls13-aesgcm: else
## suite-cnsa2-hybrid-1
-> end: when always
## suite-tls13-aesgcm
-> end: when always
## end
done
"""

UNAPPROVED = """---
name: ca_unapproved
start: classify
---
## classify
-> suite-rot13-lol: when data_class == "cui"
-> suite-cnsa2-hybrid-1: else
## suite-rot13-lol
-> end: when always
## suite-cnsa2-hybrid-1
-> end: when always
## end
done
"""

NON_TOTAL = """---
name: ca_non_total
start: classify
---
## classify
-> suite-cnsa2-hybrid-1: when data_class == "cui"
## suite-cnsa2-hybrid-1
-> end: when always
## end
done
"""


def build() -> dict:
    registry = cr.build_registry(SUITES, key_id=KEY_ID)
    rh = cr.registry_hash(registry)
    env = envelope(rh)
    baseline = FLOW.read_text()
    cases = [
        ("baseline_cnsa2", baseline, "all proofs hold"),
        ("downgrade_cui_to_classical", DOWNGRADE, "P3 fails: CUI reaches a below-floor suite"),
        ("classical_past_phase_floor", LAX_PHASE, "P4 fails: classical suite reachable past phase 2"),
        ("unapproved_suite", UNAPPROVED, "P1 fails: a suite outside the approved set is reachable"),
        ("non_total_router", NON_TOTAL, "P2 fails: a decision node has no catch-all"),
    ]
    out_cases = []
    for name, text, note in cases:
        out_cases.append({
            "name": name, "note": note, "flow_text": text,
            "expected": ca.prove_all(parse(text), env, registry),
        })
    return {"format": "crypto-agility-conformance/1", "registry": registry,
            "registry_hash": rh, "envelope": env, "cases": out_cases}


def main() -> int:
    data = build()
    OUT.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")
    n_ok = sum(1 for c in data["cases"] if c["expected"]["ok"])
    print(f"wrote {OUT.relative_to(HERE.parent.parent)}: {len(data['cases'])} cases "
          f"({n_ok} all-pass, {len(data['cases']) - n_ok} deliberate-fail), registry_hash={data['registry_hash'][:12]}…")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
