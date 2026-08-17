# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""crypto_agility — the P1-P5 proofs + the frozen conformance fixture (spec-crypto-agility.md §5, §12).

Replays `portable/conformance/crypto_agility.json`: every case's full proof output must reproduce
byte-for-byte (the cross-runtime parity target), and the deliberate-fail cases must trip exactly the
proof they were built to trip (the proofs stay falsifiable, not just green)."""
import json
from pathlib import Path

from prismpath import crypto_agility as ca
from prismpath.parser import parse

FIXTURE = Path(__file__).resolve().parent.parent / "portable" / "conformance" / "crypto_agility.json"
DATA = json.loads(FIXTURE.read_text())
REGISTRY = DATA["registry"]
ENVELOPE = DATA["envelope"]
CASES = {c["name"]: c for c in DATA["cases"]}


def _prove(case_name: str) -> dict:
    return ca.prove_all(parse(CASES[case_name]["flow_text"]), ENVELOPE, REGISTRY)


def test_fixture_replays_byte_for_byte():
    for name, case in CASES.items():
        got = ca.prove_all(parse(case["flow_text"]), ENVELOPE, REGISTRY)
        assert got == case["expected"], f"proof output drift in case {name!r}"


def test_registry_hash_is_bound_into_the_envelope():
    from prismpath import crypto_registry as cr
    assert cr.registry_hash(REGISTRY) == DATA["registry_hash"] == ENVELOPE["registry_hash"]


def test_baseline_passes_every_proof():
    res = _prove("baseline_cnsa2")
    assert res["ok"] is True
    assert all(p["ok"] for p in res["proofs"].values())
    # the CNSA-2 hybrid is reachable; the classical suite is reachable only below the phase floor
    assert res["proofs"]["P1_envelope_closure"]["reachable_suites"]["cnsa2-hybrid-1"] == "yes"


def test_downgrade_trips_class_floor_only():
    p = _prove("downgrade_cui_to_classical")["proofs"]
    assert p["P3_class_floor"]["ok"] is False
    assert p["P1_envelope_closure"]["ok"] is True and p["P5_decidable"]["ok"] is True


def test_classical_past_phase_floor_trips_monotone_migration():
    p = _prove("classical_past_phase_floor")["proofs"]
    assert p["P4_monotone_migration"]["ok"] is False
    assert any(v["suite"] == "tls13-aesgcm" for v in p["P4_monotone_migration"]["violations"])


def test_unapproved_suite_trips_envelope_closure():
    p = _prove("unapproved_suite")["proofs"]
    assert p["P1_envelope_closure"]["ok"] is False
    assert any(o["suite"] == "rot13-lol" for o in p["P1_envelope_closure"]["offenders"])


def test_non_total_router_trips_totality():
    p = _prove("non_total_router")["proofs"]
    assert p["P2_totality"]["ok"] is False
    assert "classify" in p["P2_totality"]["nodes_without_catchall"]


def test_forbidden_unreachability_is_proven_not_just_absent():
    # P3/P4 "no" verdicts on the baseline come back proven (state space exhausted), so they are real
    # unreachability, not search-bound artefacts.
    reach = ca.reachable_suites(parse(CASES["baseline_cnsa2"]["flow_text"]),
                                assume='when data_class == "cui"')
    assert reach["tls13-aesgcm"] == {"reachable": "no", "proven": True}
