# PrismPath Adapter Contract — the hexagonal boundary

PrismPath is a domain-agnostic **attestable decision-automation engine**. SOC triage was adapter #1;
compliance/audit is adapter #2 and the forcing function that *proves* the onion/hexagonal boundary.

## The core (onion center) — owns the engine, knows no domain
Flow parser · decision graph · deterministic + semantic router · lockfile (reproducible routing) ·
Flow-Ledger + attestation (OTS / RFC-3161) · the adjudication protocol · checkpoint/resume.
It knows only: **route → adjudicate a node → emit a structured result → attest.**

## The rule (enforced by `arch_guard.py` Signal 1 — HARD)
**No domain vocabulary in core.** A `control_id`, `NIST`, `CMMC`, `POA&M`, `threat_class`, or
`learner_state` appearing in an engine module is a leak. Domain vocab, verdict/determination schemas,
and catalogs live in the **adapter only**. Adding an adapter must touch **zero** core files.

## The six ports (core-owned interfaces) and what each adapter supplies
The adapter is a **Connector SDK** consumer: `ComplianceConnector(BaseConnector)` carries the
six ports; the module functions remain the stable API (see adapters/ADAPTER_GUIDE.md §2b).

| Port | Core interface | SOC adapter (#1) | **Compliance adapter (#2)** |
|---|---|---|---|
| **Ingestion** | yields a unit-of-work | Wazuh alert | control-assessment request (control id + evidence bundle) |
| **Adjudicator** | node → structured result | threat verdict (contain/watch/ignore) | control determination (met / partially-met / not-met) |
| **Embedder** *(auxiliary — shared infrastructure, not one of the six ports)* | text → vector | bge / EmbeddingGemma | *same (shared)* |
| **Retrieval** | query → few relevant snippets | LOLBAS cards | control objectives + assessment procedures (800-171A) |
| **Action/Sink** | consume a determination | OPNsense containment staging | finding + POA&M entry |
| **Attestation** | bind + prove | Flow-Ledger + OTS (+ knowledge-base hash) | *same* + control-catalog hash + evidence-bundle hash |
| **Deferral** | suspend / resume with the actor | human-gated containment queue | HITL review (`defer_for_review`/`resolve_review`) + evidence discovery (`defer_for_evidence`/`resolve_evidence`) |

Note the **Adjudicator** port must NOT assume an LLM — the FPGA adapter (#4) will drive it with
comparators. Here it drives an LLM; the port stays neutral.

**Adjudicator determination schema — keep it FLAT (learned 2026-07-22).** gemma's guided decoding
destabilizes on nested object arrays: a per-objective array of `{id, satisfied, finding}` objects made
the model loop and truncate → invalid JSON. The determination schema is therefore flat —
`{status, unmet_objective_ids: [strings], gap_summary}` — and the Sink derives per-objective weaknesses
by intersecting `unmet_objective_ids` with the catalog. Any LLM-adjudicator adapter
should avoid nested object arrays in its structured-output schema.

## This adapter (`adapters/compliance/`)
- `flows/` — decomposed decision flows, one per control family (plain-English — the PrismPath thesis).
- `catalog/` — control catalogs (NIST 800-171 / 800-171A, CMMC L2) = the Retrieval-port content.
- *(next)* evidence connectors (Ingestion), POA&M writer (Sink), determination schema (Adjudicator).

## The escalation-default, transferred (the anti-rationalization prior)
- SOC: *"a detection is a true positive unless there is positive evidence of a benign business process."*
- **Compliance: *"a control is NOT MET unless the evidence positively demonstrates each assessment
  objective; absence of evidence, intent-only policy, or evidence outside the assessed boundary = not met."***

Same burden-of-proof framing — the auditor's default. Retrieved objectives are injected as **decision
criteria, one-directional**, never a context dump (the #1/#2/#3 dilution lesson; the #58 rule).

## Anti-leak checklist (verify per change)
1. `arch_guard` Signal 1 = **PASS** (no compliance noun in any core module).
2. The interesting logic lives in the `.md` flow, **not** adapter code (the thesis; watch %-logic-in-md).
3. `git diff` for this adapter touches the adapter dir and **nothing in core**.
4. Adjudicator/Retrieval/Sink types are domain-neutral; the *determination schema* lives in the adapter.
5. Marginal cost < adapter #1 (SOC) — the core is amortized, not rebuilt.

## Why compliance is the right #2
Same DIB/regulated buyers as the local-SOC pitch; CMMC is mandatory-market; and a determination that
is **plain-English-authored + reproducible + cryptographically timestamped** is exactly what an
assessor/regulator/insurer wants — the purest expression of the attestation moat.

---

## Sink port — standards-native report emitter (#65)

`emit.py` serializes a batch of adjudicated + attested records into buyer-native formats. The Sink is a **dual emitter** (`emit(results, fmt="oscal"|"cyclonedx"|"both")`):

- **OSCAL 1.1.3** (NIST-native) — Assessment Results (AR) + Plan of Action & Milestones (POA&M). What a CMMC C3PAO / FedRAMP assessor ingests. POA&M carries only open (non-met) controls; AR carries every finding with a satisfied / not-satisfied objective target.
- **CycloneDX 1.6 Attestations** (OWASP) — the signed / DevSecOps supply-chain audience. Each control becomes a `definitions.standards.requirements[]` entry, and `declarations.attestations[].map[]` binds a conformance score per requirement.

**Provenance binding (the differentiator):** every emitted record carries the Flow-Ledger manifest into the report — in OSCAL as `props` under the `ns=https://crystalwarden.io/ns/prismpath` namespace (flow-ledger manifest hash, determination root, policy hash, gate id, knowledge-base hash, ingestion hashes, attested-at); in CycloneDX as `requirements[].properties` (`prismpath:*`). The report is bound to the exact attested decision that produced it — not a re-typed summary.

**CI gate:** `emit.validate(doc, kind)` validates against the cached published schemas in `schemas/` (NIST OSCAL v1.1.3 POA&M + AR; CycloneDX bom-1.6 + jsf + spdx). No per-run network. NOTE: OSCAL / CycloneDX datatype patterns use `\p{...}` Unicode-property escapes that Python `re` rejects; `emit._sanitize()` rewrites them to Python-compatible classes before validating (structural / required / enum checks stay intact).

Verified: `emit.py --selftest` (3 synthetic records) and `emit_demo.py` (3 LIVE gemma determinations: 3.1.11 met, 3.1.12 partially-met, 3.1.5 not-met) both emit all three documents **schema-valid, 0 errors**, with every provenance hash embedded where it belongs. arch_guard Signal-1 PASS, 0 violations — pure adapter serialization, zero core touch.

---

## Sink port — system-level rollup (#66)

`rollup.py` aggregates the per-control determinations into a system artifact, three parts, all bound to the control attestations that fed them:

- **Partial SPRS score** — DoD Assessment Methodology weights (5 / 3 / 1, base 110) in `catalog/sprs_weights.json`. Scored binary MET / NOT MET; a `partially-met` determination is counted as NOT MET (full deduction) for the AC family. **Honesty rails:** the weights file carries an explicit `_verification` caveat (provisional, verify vs the official methodology), and the score is reported as `deducted_points` + an `assessed_subset` breakdown + a clearly-labeled `ceiling_if_unassessed_all_met` upper bound — never a submittable 110-based score, because only a subset of controls is assessed.
- **Assessment scope** — system name, boundary, sampled assets, sampling method, assessor, date; hashed into the rollup knowledge-base binding.
- **System rollup attestation** — a `provenance_manifest` whose `ingestion_hashes` ARE the per-control manifest hashes. The system report is provably derived from exactly those attested control determinations (a superstructure over the individual Flow-Ledger commits).

`compliance_adapter.rollup_report(records, scope_meta, out_dir, fmt)` runs it and emits the standard(s) with the rollup embedded in the OSCAL AR (`results[].props` for the SPRS numbers + boundary + rollup-manifest; a `back-matter` resource binding the control manifests).

Verified (`rollup_demo.py`, 3 LIVE determinations): 3.1.11 met / 3.1.12 partially-met / 3.1.5 not-met → deducted 8 points (5 for 3.1.12-as-not-met + 3 for 3.1.5), ceiling 102, assessed-subset earned 1 of 9; rollup manifest binds all 3 control manifests (`rollup_binds_all_control_manifests: true`); OSCAL AR + POA&M + CycloneDX all schema-valid. arch_guard Signal-1 PASS, 0 violations.

---

## Retrieval port — catalog Translation layer (#67, Gap 1)

The catalog (`catalog/nist_800171_ac.json`) is enriched so each control carries `evidence_types` (the artifact categories that satisfy it) and each objective carries a `discovery_query` (the specific ask routed to the client when that objective is not demonstrated). `enrich_catalog.py` applies this idempotently (overwrites only the enrichment fields, never the control/objective text).

`compliance_adapter.translate_missing(control, unmet_ids=None)` is the Translation layer: it turns a control + its unmet objectives into a catalog-driven, objective-specific evidence request — `{control_id, evidence_types, requests:[{objective_id, objective, ask}]}`. `unmet_ids=None` means the whole control (empty bundle); passing the determination's `unmet_objective_ids` targets only the gaps.

`defer_for_evidence(control, req, missing=None, unmet_ids=None)` now generates the request from the Translation layer when `missing` is not supplied; a hand-written string still works (backward-compatible with the earlier discovery demo).

Verified (`discovery_demo.py`, deterministic — no gemma): empty bundle for 3.1.7 → 4 objective-specific asks + evidence_types; partial 3.1.12 with `unmet_ids=[b,d]` → only those 2 asks. Smoke over all 8 controls: evidence_types present, one non-empty ask per objective (29 objectives). arch_guard Signal-1 PASS, 0 violations.

---

## Testing

See [TESTING.md](TESTING.md). Deterministic suite: `pytest` (fast, no gemma). Live integration: `pytest -m gemma`. 86 adapter tests (83 deterministic + 3 opt-in gemma); adversarial attestation-tamper + hypothesis property coverage. Core suite: 379 tests via prismpath/.venv.

---

## Retrieval port — runtime-selectable standard (#69, full breadth)

The engine is **catalog-agnostic**: the assessor picks the standard *before* running the audit, and the same adjudication / attestation / emit machinery runs against whichever catalog is active.

```python
ca.use_standard("nist_800171_r2")   # or "nist_800171_r3"
ca.list_standards()                 # {std: {revision, controls, families}}
```

| Standard | Revision | Controls | Families | Objectives | SPRS | Source |
|---|---|---|---|---|---|---|
| `nist_800171_r2` | Rev 2 | 110 | 14 | 308 | scored (DoD weights) | tbusillo OSCAL mirror — **UNOFFICIAL** community transcription |
| `nist_800171_r3` | Rev 3 | 130 | 17 | 422 | not scored | usnistgov/oscal-content — **OFFICIAL** NIST OSCAL |
| `nist_800171_ac` | Rev 2 | 8 | 1 | 29 | scored | legacy AC-only subset |

**Rev 2** carries the full DoD Assessment Methodology weight table (5/3/1) per control, the 800-171A objectives, and assessment methods (Examine/Interview/Test). It is what **CMMC 2.0 assesses today**. Provenance is flagged in `_meta`: NIST retired Rev 2 machine-readable data, so this is a community transcription — verify against the source NIST/DoD PDFs before assessment use.

**Rev 3** is NIST's current official OSCAL, self-contained with inline 800-171A r3 objectives, methods, and ODPs. It is **not SPRS-scored** — the DoD point system is a Rev-2 construct — so `catalog_weights()` is empty and `rollup_report` marks SPRS `applicable: false` with the reason recorded in the OSCAL AR (`sprs-status` prop).

Ports touched: Retrieval (`STANDARDS`, `use_standard`, `active_standard`, `list_standards`, `catalog_weights`); rollup (`sprs_partial(records, weights)` takes weights from the active catalog); emit (AR embeds SPRS only when applicable). `catalog_hash` binds the active standard, so attestations differ by standard. Rebuild catalogs with `build_catalogs.py`.

Verified (`dual_standard_demo.py` + `test_standards.py`, 8 deterministic tests): both catalogs load, controls resolve per standard, R2 = 110/14 all-weighted, R3 = 130/17 zero-weighted with ODPs, catalog hashes differ, R3 rollup marks SPRS not-applicable, R2 rollup scores. Live gemma: adjudication runs end-to-end on both R2 and R3 controls.

---

## Assessment flow — family-agnostic (#70)

`flows/nist_800171_generic.md` is the family-agnostic playbook, superseding the AC-only slice. It routes by **assessment-method profile** — `adjudicate_technical` (Examine+Test config: AC, AU, CM, IA, SC, SI, MP), `adjudicate_procedural` (Examine policy + Interview: AT, PS, PL, SA, RA, SR), `adjudicate_operational` (process in practice: IR, MA, PE, CA), `general_control` (fallback) — rather than AC sub-families, so ONE flow covers all 14 Rev 2 / 17 Rev 3 families under whichever standard is active. Every adjudicator is escalation-default (the `when always` fallback sinks to POA&M — a control is never asserted met without evidence).

`active_flow_hash()` hashes the flow content and `attest()` binds it as `policy_hash` (gate `nist_800171_generic@v1`), so the Flow-Ledger records the exact decision graph used, not a placeholder. Compiles clean (12 nodes / 26 edges, `prismpath validate`); covered by `tests/test_flow.py`. The AC flow is retained as a legacy reference.

---

## Adjudicator — assessment-method depth (#71)

`adjudicate()` no longer applies one document-Examine-centric prompt to every family. `_method_profile(control)` classifies each control by family NAME (robust across the Rev2/Rev3 `SA`-digraph ambiguity — Rev2 "Security Assessment" vs Rev3 "Services Acquisition") into the same four profiles the generic flow routes by, and the profile's evidence guidance + the control's catalog `methods` (Examine/Interview/Test) are injected into the prompt:

- **technical** (AC, AU, CM, IA, SC, SI, MP) — satisfied only by CONFIGURED-AND-ENFORCED evidence; intent-only policy does not count.
- **procedural** (AT, PS, PL, SA-acq, SR, RA) — requires a current policy AND corroboration it is operative (interview/records).
- **operational** (IR, MA, PE, CA/Security Assessment) — requires the process EVIDENCED OPERATING (exercise records, logs, observations).
- **general** — fallback to the objective's own methods.

Classification covers every family with zero `general` leakage (R2: 83/8/19 tech/proc/op over 110; R3: 88/18/24 over 130). Verified by `tests/test_method_profile.py` (family-name classification incl. risk-vs-security-assessment disambiguation, no-general-leak sweep over both full catalogs, and a monkeypatched check that the profile guidance + methods reach the prompt without calling gemma). Gemma regression: the unambiguous determinations do not flip.
