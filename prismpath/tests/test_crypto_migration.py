"""Fleet-migration replay (spec-crypto-agility.md §10.5): the monotone-migration property,
characterized as a (policy-gate k x envelope-floor f) matrix and replayed from the frozen corpus.

The property: a policy that gates the classical suite at phase k satisfies P4 for every floor f >= k
and provably violates it for every f < k. The corpus must reproduce byte-for-byte, and the f>=k
invariant must hold in every cell — so the suite can never silently degrade into a vacuous all-pass."""
import json
from pathlib import Path

from prismpath import crypto_agility as ca
from prismpath import crypto_registry as cr
from prismpath.parser import parse
from prismpath.portable.gen_crypto_migration_fixtures import SUITES, KEY_ID, phase_policy, _envelope

FIXTURE = Path(__file__).resolve().parent.parent / "portable" / "conformance" / "crypto_migration.json"
DATA = json.loads(FIXTURE.read_text())
REGISTRY = cr.build_registry(SUITES, key_id=KEY_ID)


def test_matrix_replays_byte_for_byte():
    for cell in DATA["cells"]:
        k, f = cell["policy_gate"], cell["envelope_floor"]
        got = ca.prove_monotone_migration(parse(phase_policy(k)), _envelope(DATA["registry_hash"], f), REGISTRY)
        assert got == cell["p4"], f"P4 drift at gate={k} floor={f}"


def test_monotone_invariant_holds_every_cell():
    # P4 holds  <=>  envelope_floor >= policy_gate — the whole point of the corpus
    for cell in DATA["cells"]:
        assert cell["p4"]["ok"] == (cell["envelope_floor"] >= cell["policy_gate"])
        assert cell["invariant_holds"] is True


def test_boundary_is_falsifiable():
    # a policy gating classical at phase 2, held to a stricter floor of 1, must FAIL (classical still
    # reachable at phase 1) — the proof is not vacuously green
    below = next(c for c in DATA["cells"] if c["policy_gate"] == 2 and c["envelope_floor"] == 1)
    assert below["p4"]["ok"] is False
    assert any(v["suite"] == "tls13-aesgcm" for v in below["p4"]["violations"])
    at_floor = next(c for c in DATA["cells"] if c["policy_gate"] == 2 and c["envelope_floor"] == 2)
    assert at_floor["p4"]["ok"] is True


def test_registry_hash_is_stable():
    assert cr.registry_hash(REGISTRY) == DATA["registry_hash"]
