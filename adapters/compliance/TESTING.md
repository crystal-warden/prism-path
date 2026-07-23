# Compliance adapter — testing methodology

Run from `adapters/compliance/`:

```bash
~/cwprojects/prismpath/.venv/bin/python -m pytest        # fast, deterministic, no gemma (default)
~/cwprojects/prismpath/.venv/bin/python -m pytest -m gemma   # opt-in live-gemma integration (slow)
```

The venv (`prismpath/.venv`) has `pytest`, `hypothesis`, `jsonschema`; the core package is installed editable so `from prismpath import ...` resolves. `pytest.ini` deselects `gemma`-marked tests by default so the everyday run is fast and deterministic.

## Layers (depth, not just happy path)

1. **Schema validity across the matrix** (`test_emit.py`) — every status combination (all-met, all-not-met, mixed, single, empty) serialized to OSCAL POA&M + AR and CycloneDX 1.6, each validated against the cached published schema.
2. **Negative-schema tests** — the gate must *bite*: corrupt a doc (drop required `metadata`, bad enum `state`, non-integer `version`, bad `bomFormat`) and assert `validate()` **rejects** it. A validator that never rejects proves nothing.
3. **Invariants** — provenance embedding (every manifest hash present in AR/CDX; POA&M carries only open controls), deterministic RFC-4122 v5 uuids, token-safe finding ids, conformance-score mapping.
4. **Adversarial attestation** (`test_deferral_attestation.py`) — the value proposition. `verify_manifest` recomputes the content-address; tampering *any* bound field (root, policy, gate, kb, ingestion, label) is detected; the override chain supersedes the prior and **cannot be silently re-pointed or its rationale rewritten**; override-of-override chains; deferral resume/double-resume/persistence.
5. **Rollup math + tamper** (`test_rollup.py`) — SPRS deductions (partial counts as not-met), honesty caveats present, ceiling/subset arithmetic, and: swapping one control's manifest changes the rollup root (the rollup is bound to the *exact* control attestations).
6. **Property-based** (`test_properties.py`, hypothesis) — for ANY combination of controls/statuses: emit always schema-valid + provenance always embedded, SPRS math invariant, emit deterministic, rollup binds exactly the record manifests.
7. **Live integration** (`test_integration_gemma.py`, opt-in) — real adjudication end-to-end emits valid standards; the two unambiguous curated bundles land on their expected status.

## What it caught
The empty-`observations` bug: when every control is met, the POA&M emitted an empty `observations` array, which OSCAL rejects (minItems 1 if present). The happy-path demos always included a not-met control, so this only surfaced under the all-met / property tests. Fixed by omitting empty optional arrays.

## Counts (2026-07-22)
- Core suite: **379** tests (373 passed, 6 skipped — git/env gated).
- Adapter: **86** (83 deterministic + 3 opt-in gemma), all green.
