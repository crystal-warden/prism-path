# Compliance adapter · NIST SP 800-171

A PrismPath **domain adapter** (the second reference adapter after SOC triage). It plugs into the
engine's six ports with **no compliance vocabulary in the core**: see `ADAPTER_CONTRACT.md` for the
port boundary and `TESTING.md` for how it's tested. Assessment claims are logged in the engine's
`docs/research/supporting-evidence.md`.

Runs against the published `prismpath` core (`import prismpath`; `pip install -e ../..`). Live
adjudication calls the served model at `PRISMPATH_LLM_ENDPOINT` (default `http://127.0.0.1:8888`).

## File map

**Core adapter (the ports)**
| file | role |
|---|---|
| `compliance_adapter.py` | the adapter: a **Connector SDK** consumer (`ComplianceConnector`): Retrieval (selectable catalog), Ingestion, Adjudicator (escalation default, method-profile-aware), Sink, Attestation (reuses core `ledger_airgap` through the SDK), Deferral (HITL + discovery) |
| `emit.py` | Sink: dual OSCAL (AR + POA&M) + CycloneDX 1.6 emitter, schema-validated against `schemas/` |
| `rollup.py` | Sink: system rollup: partial SPRS score + scope + rollup attestation |

**Catalog pipeline**
| file | role |
|---|---|
| `build_catalogs.py` | build `catalog/nist_800171_r2.json` + `_r3.json` from source (mirror + official NIST OSCAL) |
| `enrich_catalog.py` | legacy: add evidence_types + discovery_query to the AC-only catalog (superseded by build_catalogs) |

**Assessment content**
- `catalog/`; the dual catalogs + `sprs_weights.json`. `flows/`; the maps (`nist_800171_generic.md`
  is canonical; `nist_800171_access_control.md` legacy AC; `agy_800171_assessment.md` is an
  independently agy-authored map kept as a generalization artifact). `schemas/`; cached OSCAL +
  CycloneDX JSON schemas (the hermetic validation gate). `requests/`; sample evidence bundles.

**Efficacy harness (#72; testing decision quality with a held-out, independent-model corpus)**

(*agy* = the independent frontier-model coding agent used as corpus author, reference assessor,
and second annotator; a different model family from the local adjudicator, so agreement numbers
measure cross family consistency, not self-agreement.)
| file | role |
|---|---|
| `build_efficacy_spec.py` | extract a stratified control set (spec) to ground corpus generation |
| `generate_agy_prompts.py` | per control agy authoring prompts |
| `ingest_company.py` | ingest blind company docs → per control evidence (lexical, or `--map` semantic) → adjudicate → disposition report |
| `semantic_retrieve.py` | EmbeddingGemma (CPU) retrieval map; **needs its own env** (sentence-transformers: heavier than the adapter's deps) |
| `efficacy_harness.py` | run gemma vs agy labels on a labeled corpus; agreement by difficulty |
| `dump_reference_bundles.py` | dump the exact bundles gemma saw, for an independent agy reference pass |
| `compare_reference.py` | gemma-vs-agy differential → routes disagreements to the HITL queue |
| `efficacy/` | task prompts + spec (committed); generated corpora/reports are gitignored |

**Illustrative demos**: human-readable walkthroughs, **superseded by `tests/` for verification** (kept
for docs): `discovery_demo.py`, `dual_standard_demo.py`, `emit_demo.py`, `hitl_demo.py`, `rollup_demo.py`.

**Early harnesses** (pre-`tests/`): `assess.py`, `validate_compliance_adjudication.py`.

## Quick start
```bash
# from this directory, with the repo's package installed (pip install -e ../..)
python -m pytest -q                    # deterministic adapter suite (131)
python -m pytest -m gemma -q           # opt-in live-model integration
python -m prismpath.cli validate flows/nist_800171_generic.md
python build_catalogs.py               # rebuild the dual catalogs
```
