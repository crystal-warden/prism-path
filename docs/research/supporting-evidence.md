# Supporting Evidence — Validated Results Ledger

*Every claim in the PrismPath papers, backed by a measured result, its provenance, and an honest
verdict — negative results included. Written to survive a hostile read and to be merge-ready into the
research paper (`docs/research/paper-routing-spectrum.md`) and engineering white paper
(`docs/research/whitepaper-engineering.md`). All numbers first-party on the GB10 (Grace-Blackwell, unified
memory). Consolidated 2026-07-21.*

> **Rule of use.** No claim ships without its row here (result + provenance + gap).
>
> **On provenance paths.** Rows whose provenance is a bare `benchmark/*.json` or a `prismpath/`
> script are reproducible from THIS repo (`prismpath/benchmark/`, `research/`). Rows citing
> `etbert-lab/`, `triage-corpus/`, `triage-7b-lab/`, or `knowledge-lib/` are measurements from
> **separate first-party lab repositories** that are not part of this open release — the security-track
> detector (ET-BERT), the ATT&CK triage corpora, and the knowledge index. Their numbers are reported
> here because the papers cite them; they are **not independently reproducible from this repo alone**,
> and that limitation is stated rather than implied by a path that looks local.
>
> Rows citing [`prismpath-hw/`](../../prismpath-hw/README.md) (the hardware target, rows
> #72–#76) are reproducible from **THIS repo** — the strongest class above — and their evidence
> set is additionally OTS-anchored (`prismpath-hw/evidence/SHA256SUMS` + `.ots`, Bitcoin block
> 961390): rerun the gates, or verify the hashes.

---

## A. Routing spectrum — the core contribution (paper §4)
| Claim | Result | Provenance |
|---|---|---|
| Embedding beats lexical, splits by stratum | ALL 0.69 vs 0.53 lexical; intent 0.81, abstraction 0.74, **polarity 0.52** (near-chance) | paper §4.2; `benchmark/reproduce.py` |
| Centroid (learned prototypes) lifts routing | **0.827** overall (+0.14 vs embed), +0.23 polarity, 5-fold CV, leakage-audited | `benchmark/gaussian_route_eval.json` (centroid row) |
| Hybrid frontier (LLM-on-doubt) | 0.837 @ 38% escalation → ~0.99 at higher budgets; margin has a **confident-error blind spot** | paper §4.3 |
| Head-to-head vs LangGraph/CrewAI/LLM-router | 83.7% at **2.6× fewer LLM calls, ~2× lower median latency**; loses p95 tail (stated) | paper §4.4 |

## B. The density/geometry NEGATIVE result (NEW — publishable; strengthens "mean+margin wins at scale")
Four pre-registered experiments tested whether learned geometry beats the shrunk mean + cosine margin.
**All four failed their bars.** This is the honest-research asset — it forecloses a whole family of
"pet-idea" geometry with evidence.
| Experiment | Result | Verdict | Provenance |
|---|---|---|---|
| Gaussian-per-edge (raw 768-d), #39 | g_shared 0.797 / g_diag 0.803 **< centroid 0.827**; don't-know AUC 0.582; *one nugget:* g_diag 0.788 > centroid 0.748 on polarity | PARK | `gaussian_route_eval.json` |
| PCA-32-d density + don't-know, #41 | gpca 0.797; don't-know AUC **0.608 (<0.75 screen)**; likelihood **loses to margin** at every escalation rate | PARK (pre-registered) | `gaussian_route_pca.json` |
| Stratified router (g_diag on lint edges), #47 | polarity lint fires on **0/99** cases → g_diag has no delivery mechanism | DEAD ON ARRIVAL | ad-hoc falsification script (not retained) |
| Native-128 Matryoshka density (EmbeddingGemma), #52 | don't-know AUC **0.706** — improving (0.582→0.608→0.706) but still <0.75 | PARK (representation-limited, not dead) | `embeddinggemma_scout.json` |
**Net:** at ~15 labeled outcomes/edge, covariance/density adds noise; the shrunk mean is the winner.
The don't-know signal improves with representation quality but does not cross the bar today.

## C. Learning curves — data-starved, not method-starved (#42)
| Axis | Curve | Read |
|---|---|---|
| Routing acc vs samples/edge | centroid 0.77→0.803→0.807→**0.827** at 3/5/8/15 (max=15) — **still rising** | more labeled dispositions (pilot/flywheel) will lift routing |
| Cross-family recall vs flows/family | 0.144→0.151→0.154→0.176→**0.224** — **rising steeply, unsaturated** | more per-family flows (#30/#40) will lift the 22% |
Provenance: `benchmark/learning_curve.json`. This *justifies* the corpus-collection tasks: the gains are real and unsaturated.

## D. Embedder scouting + succession — the "upgrade engine" (#48, #52)
| Claim | Result | Provenance |
|---|---|---|
| Scouting harness scores any candidate per-stratum | bge-small 0.803 (viable −0.024 cheaper); **EmbeddingGemma 0.853 (BEATS bge-base 0.827)**, intent 0.961 | `embedder_succession.json`, `embeddinggemma_scout.json` |
| Succession map migrates locked artifacts | unit rotation **100%**; same-family bge↔bge **101%**; **cross-family bge→EmbeddingGemma 100.4% — PASSES ≥98%** | same |
| Lockfile narrative upgrade | "pinned, with a **certified succession path** (validated cross-vendor)" | §3.3 lockfile + this row |

## E. Encrypted-traffic detection — margin + calibration (#34; separate lab repo)
| Claim | Result | Provenance |
|---|---|---|
| Discriminative benign margin kills confident FPs | **margin-AUC 1.0** separating 62 confident-FP-benign from raw-flagged malicious | `benign_corpus/eval/step2_margin.json` |
| Per-benign-flow FP, Wilson-certified | raw 2.09% → margin τ=0 **certified ≤0.053% @95%**, cross-family recall **0.2235 unchanged** | `step3_calibration.json` |
| Honest framing | ~22% cross-family recall = a **complement**, not a wall; the 22% is armed (hardest generalization test, one layer, system-level = pilot agreement) | `etbert-lab/CLAIMS_detection_metrics.md` |

## F. Capacity levers (paper §5; CAPACITY.md; SERVICE_CLAIMS D3/D7)
| Lever | Result | Provenance |
|---|---|---|
| Demand — prefilter | **58.3% auto-resolve** (233/400 real alerts), **97% oracle agreement, 0 unsafe downgrades** | paper §5 |
| Supply — two-model 7B/31B | 4.6× end-to-end; A/B containment agreement 80%, 0 dangerous under-calls; routing rule → 0 escaped under-calls | `triage-7b-lab/ab_results.md` |
| GPU ingestion (measured) | log embed CPU 179 → GPU **2,473 ev/s = 13.8×**; flow encoder ~13×; client-year in ~8 GPU-hours | ad-hoc benchmark (not retained); SERVICE_CLAIMS D7 (internal) |
| Indexer not the binding tier | heap 1→8.6 GB, 90-day ISM; LLM stays the ceiling (~17–171 nets/box) | `etbert-lab/INDEXER_CAPACITY.md` |

## G. Operational hardening (engineering paper)
| Item | Result | Provenance |
|---|---|---|
| ET-BERT capture redesign (#33) | silent-failure war-story; no-sudo rotating capture; hourly GPU batch (4.23 ms/flow); cwcheck function-check | ET-BERT lab repo (`batch_score.py`) |
| Per-tenant suppression (#44) | **17.3% hard-suppressed** (skip LLM) on 5k live alerts + context-tagged over-calls; hash-versioned | `research/suppression.py`, `homelab.json` |
| Learning flywheel (#38) | authoritative labels teach cache (recurrence auto-resolves cos 0.994) + propose context rules; **self-labels REFUSED, threats never suppressed** | `research/flywheel.py` |
| OTS anchoring connected v1 (#36) | ledger enumerate → Merkle → real Bitcoin `ots stamp` → verify → **tamper-evident** | `prismpath/ledger_ots.py`; `docs/design/spec-ledger-opentimestamps.md` |
| OTS air-gap tier (#53) — disconnected attestation | T1 batch-and-forward (tiny hash-only bundle across the diode; real stamp round-trip proven) + **T2 RFC-3161 internal-TSA validated fully OFFLINE** (query->sign->`Verification: OK`->tamper rejected) + C1 provenance binding (POLICY_HASH+gate+ingestion) + C4 salt + `prismpath ledger` CLI + staged timers. Extends attestation to DIB/OT/healthcare air-gapped sites. | `prismpath/ledger_airgap.py`, `deploy/systemd/`, `docs/design/spec-ledger-opentimestamps.md` §4/§6 |
| Shadow-pilot harness (P6) | dry-run: containment agreement 0.867, **0 dangerous under-calls**, 0 parse errors | `research/shadow_agreement.py` |
| Triage vs DIVERSE labeled data (#40, honest breadth) | on 249-technique ATT&CK corpus (single-event): escalation **0.672**, **33% dangerous under-calls** (vs 0 on monotone homelab — the distribution-shift blind spot MEASURED), benign-correct 0.923; weakest = Lateral Movement 2/8. *Caveat: isolated single events understate a correlated stream; attack signal is in the sequence.* | `triage-corpus/validation_v0.json` |
| LM deep-dive (#3): is LM a model gap or ambiguity? | On 14 LM cases escalation is **10/14 (71%)** — the 2/8 draw was pessimistic (LM escalation is high-variance by technique). The 4 under-calls are **all admin-mimicry** (DCOM 10016, impacket-via-mmc, PowerShell-Remoting, System file-create); LLM rationales explicitly read them as "common administrative behavior"/"false positive." One (DCOM 10016) is a **correct** benign call the by-construction label penalizes. **Conclusion: LM under-calls are single-event ambiguity, not a reasoning gap.** | `triage-corpus/lm_deepdive.json` |
| Enrich-lift (#2): does correlated context help? **NEGATIVE.** | Injecting up to 8 same-file correlated events (naive, unordered, unweighted) **lowered** escalation 0.902→0.77 and **raised** under-calls 6→14 (net +8). Only 2 flipped ignore→contain (real multi-event chains); ~10 flipped contain→ignore as benign noise **diluted** the malicious signal. LM barely moved (7/8→6/8) — the #3 "context helps LM most" prediction **refuted**. **Lesson: raw context hurts; context must be ranked/ordered with the anchor event marked, not dumped.** *Caveat: tiny n (5-8/tactic); bounds the naive approach only.* | `triage-corpus/enrich_lift_v0.json` |
| Sequence 3-arm (#1): does ENGINEERED context recover the loss? **STRONG NEGATIVE.** | On 52 paired multi-event cases: escalation A single-event **0.904** > B naive-bag **0.788** > C engineered kill-chain-timeline **0.538**; under-calls 5 / 11 / **24**. `C_recovers_over_B=-0.25` — engineered framing was the WORST arm, monotonically across nearly every tactic. C talked itself out of escalating mimikatz, DCSync, LSASS hashdump, security-log-clearing (1102), and a live CVE-2018-15982 exploit — the ‘look for a progression / a lone event may be benign’ framing handed the model an off-ramp it took. **Conclusion (converges with #2/#3): in-prompt context DEGRADES single-shot triage; the more reasoning room, the more the LLM rationalizes benign. Correlation belongs UPSTREAM as a deterministic layer, NOT as free-text the triage LLM weighs. Validates the 3-layer architecture.** *Caveat: noisy real-capture timelines (bounds the production regime), single model, temp 0, by-construction all-malicious labels.* | `triage-corpus/sequence_lift_v0.json`, `triage_sequence_corpus.jsonl` (249 seqs) |
| Decomposed graph (#54): does a DECISION-GRAPH beat single-shot? **POSITIVE — double win.** | Same 64 malicious + 48 benign, arm A single-shot vs arm D decomposed (signature-gate -> tactic-router -> escalation-defaulted narrow node). D raised malicious-recall **0.844 -> 0.969** (+12.5pts, under-calls 10->2) AND benign-correct **0.792 -> 0.938** (+14.6pts, over-calls 10->3) — improved BOTH ends, not a recall/precision trade. Signature gate resolved **8/64 (12.5%) deterministically, 0 benign FP** (mimikatz/NTDS/DCSync/LSASS/log-clear/encoded-PS). **Completes the arc: monolithic prompt + more context = WORSE (#1/#2/#3); same prompt split into narrow nodes = BETTER on both axes. The lever is DECISION STRUCTURE, not context volume — PrismPath's thesis, validated.** *Caveat: D routed on the corpus's built-in _tactic label (a production router must EARN that classification -> #56); the label-independent, robust gains are the signature gate + escalation-default framing. Small n, by-construction labels.* | `triage-corpus/decomposed_v0.json`, `research/validate_triage_decomposed.py` |
| Compliance adapter #2 (#60-62): PrismPath generalizes to a 2nd domain | Decomposed NIST 800-171 control-assessment flow (validates clean, 27-edge graph) reuses the SOC patterns (per-control nodes, escalation-default = the auditor's burden of proof, retrieval-as-criteria). On 8 labeled Access-Control evidence bundles gemma scored **8/8, 0 over-pass, 0 rubber-stamps** including the intent-only / absent-evidence / out-of-boundary failure modes. HEXAGONAL BOUNDARY PROVEN: adding the adapter touched ZERO core files; after extracting the pre-existing SOC leak (measure_prefilter + wazuh_triage_agent) the arch_guard **Signal-1 PASSES (0 violations, core domain-clean, 6019 LOC)**. Caveat: escalation-default vs neutral not separated on this explicit set (needs ambiguous bundles). | `adapters/compliance/`, `tools/arch_guard.py` |
| Embedder-routed graph (#56): does the #54 win survive WITHOUT the free tactic label? **YES — unconfounded.** | EmbeddingGemma routes each alert to a decision node by similarity to TRAIN-split centroids (leading 'Tactic |' prefix STRIPPED so it routes on event content, not the label). Routing: binary attack-vs-benign gate **64/64 + 48/48 = 100%** (0 malicious->benign, 0 benign->attack); fine exact-tactic only 45% but HARMLESS (every attack node shares the escalation-default framing, so a mis-tactic'd alert still escalates). End-to-end **D_embed recall 0.984 / benign 0.938** — matches D_oracle (0.969/0.938), both crush single-shot A (0.844/0.792). **The decomposition win rides on a binary attack/benign separation a learned embedder does perfectly from event content — NOT on the ground-truth label. Production-realizable.** | `triage-corpus/embed_routed_v0.json`, `research/validate_triage_embed_routed.py` |
| Agentic PULL node (#55): mechanism validated, efficacy gated on telemetry | Bounded ReAct loop (manual, via structured output — gemma4 tool-calling reliable after concise-retry) lets the triage LLM PULL specific facts via tools instead of us PUSHing a noise-bag. On 3 residual hard cases: **PULL 3/3 correct vs single-shot 2/3** — fixed the wuauclt LotL masquerade under-call by pulling process-lineage (launched by cmd.exe from C:\Users\Public) + host-baseline (never seen); correctly DE-escalated benign DCOM 10016 by pulling related-alerts (no supporting activity). **HONEST: PUSH-all also 3/3 here** — the demo's small/clean evidence stores do NOT exercise PULL's anti-dilution advantage, which only appears with LARGE/noisy real telemetry (the #2/#1 regime). So PULL>PUSH stays GATED on real telemetry (pilot / Tier-1 / probe signals). Deliverable = the working mechanism + production-shaped tool interface (binds to Wazuh/Zeek/baseline/probes), NOT a corpus-wide lift. | `triage-corpus/agentic_pull_demo.json`, `research/agentic_investigate.py` |
| ET-BERT live-heavy re-cert (#35) — hardened FP claim | Prior τ=0 FP ≤0.053% rested on only 76 live samples (small-sample artifact). Re-certified on **93,956 live-captured benign flows**: τ=0 observed FP **0.102%**, Wilson-95% **≤0.121%**, certifies at α=0.01 (LB 0.99879). 18× more data, live-distribution — slightly higher but far more defensible; operating point holds at scale. | `etbert-lab/benign_corpus/eval/step4_recert_livepool.json` |
| ET-BERT weak-family recall (#30): calibration can't fix cross-family recall | 66 families, cross-family macro recall 0.224 (3 strong / 29 weak / 34 near-blind). Per-family-floor fix REFUTED: recovers recall 0.224->0.521 but benign FP explodes 1.7%->22.7% (malicious/benign overlap in the 0.85-0.95 band). The cosine layer is a high-precision known-threat matcher; ~22% unseen-family recall is architectural, not tunable. Real levers = corpus growth or a better encoder (#59). Claim as 'known-bad flow detection, ~0.1% FP', NOT 'encrypted-threat detection'. | `etbert-lab/benign_corpus/eval/step6_perfamily_recall.json` |
| Knowledge-library nodes (#58): retrieval-augmented adjudication — mechanism+principle win, efficacy data-gated | Real 239-card LOLBAS index (EmbeddingGemma 768d), retrieval precise (14/64 malicious, **0/48 benign** false-retrieval), air-gap Docker image, KB-hash bound into Flow-Ledger provenance (#53). VALIDATION: v0 injected the full card incl. its 'legitimate binary, mere presence not malicious' framing → HURT the escalation node (recall 0.969->0.875, the #1/#2/#3 dilution effect at a 3rd layer). v1 ONE-DIRECTIONAL abuse-only injection → RECOVERED (ER 0.969/0.938 = E no-knowledge, no harm) + lifted a NEUTRAL node 0.844->0.906 + fixed the wuauclt under-call WITH a cited justification (audit value). **Efficacy WIN not established on this corpus** — knowledge is redundant with the escalation-default prior for recall, and its unique PRECISION benefit (correctly ignoring genuinely-benign LOLBin use) is UNTESTABLE here (0 benign LOLBin cases). Design rule: inject one-directional abuse-evidence, never balanced prose. | `triage-corpus/rag_nodes_v1.json`, `research/{build_knowledge_index,validate_triage_rag}.py`, `knowledge-lib/` |

## H. Document map (the whole set, navigable)
In this repo:
- **Papers:** `docs/research/paper-routing-spectrum.md` (research),
  `docs/research/whitepaper-engineering.md` (engineering).
- **Specs:** `docs/design/spec-ledger-opentimestamps.md` (OTS — connected v1 + air-gap tier delivered),
  `docs/design/spec-guard-onion.md` (the safety floor), `SPEC.md` (the format).
- **Negative results:** §B of this ledger (the density/geometry thread — four pre-registered
  experiments, all failed their bars; the publishable negative result).
- **On-ramp:** `docs/research/primer-students-guide.md`.
- **Use case:** `docs/research/soc-triage-case-study.md`.
- **Bypass protocol:** `docs/research/bypass-measurement.md` (pre-registered, per-stratum rates).

Not in this repo (first-party, separate — see the provenance note at the top):
- **Merge-ready paper outlines:** the ET-BERT research + engineering contribution outlines
  (editorial working documents, held with the strategy set).
- **Detection specs + claim discipline:** `etbert-lab/HARDENING_SPEC_benign_margin.md`,
  `etbert-lab/CLAIMS_detection_metrics.md`.
- **Claims + strategy:** `SERVICE_CLAIMS.md`, `BRAND_ARCHITECTURE.md`, `CONSULTING_STRATEGY.md`,
  `RETROSPECTIVE.md`, `CAPACITY.md`.

## I. Reproducibility
Scripts (this repo's `research/` + `prismpath/benchmark/`; plus the separate
`etbert-lab/` lab repo — see the provenance note above): `gaussian_route_eval.py`, `gaussian_route_pca.py`,
`learning_curve.py`, `embedder_succession.py`, `embeddinggemma_scout.py`, `suppression.py`, `flywheel.py`,
`ledger_ots.py`, `etbert-lab/{build_benign_corpus,step2_margin_eval,step3_grow_calibrate}.py`. Each emits JSON
under `benchmark/` or `benign_corpus/eval/`. Embedders: bge-base/small, EmbeddingGemma (all local); LLM: gemma4
served locally. No number here depends on a cloud API.

### #65 — Sink dual-emitter (OSCAL + CycloneDX), schema-gated (2026-07-22)

**Claim:** the compliance adapter emits assessment results in both NIST-native OSCAL and OWASP CycloneDX, each schema-valid and each cryptographically bound to the attested decision that produced it.

**Method:** `emit.py` (pure serialization, adapter-local) with `validate()` against cached published schemas (NIST OSCAL v1.1.3 POA&M + AR; CycloneDX bom-1.6). `emit_demo.py` runs the three live request bundles through gemma, attests each via `ledger_airgap.provenance_manifest`, then emits both standards.

**Result:** 3 live determinations — 3.1.11 met, 3.1.12 partially-met, 3.1.5 not-met.
- OSCAL POA&M: valid, 0 errors; carries the 2 open controls (met control correctly excluded).
- OSCAL AR: valid, 0 errors; 3 findings with satisfied / not-satisfied targets.
- CycloneDX 1.6: valid, 0 errors; conformance 1.0 / 0.0 / 0.0.
- Every Flow-Ledger manifest hash embedded in the reports it belongs in (verified by string-containment).
- arch_guard Signal-1 PASS, 0 violations.

**Caveat:** `partially-met` maps to CycloneDX conformance 0.0 (not fractional) — CycloneDX conformance is a claim of full conformance; partial is treated as non-conformant with the gap detailed in the OSCAL POA&M.

### #66 — System rollup Sink: partial SPRS + scope + rollup attestation (2026-07-22)

**Claim:** the compliance adapter rolls per-control determinations up into a system-level artifact — a partial SPRS score, an assessment scope, and a rollup attestation cryptographically bound to the per-control attestations — without overstating the score.

**Method:** `rollup.py` (pure aggregation + `ledger_airgap.provenance_manifest` reuse). Weights in `catalog/sprs_weights.json` (DoD methodology 5/3/1, base 110, flagged provisional). `rollup_demo.py` runs the three live bundles → adjudicate → attest → rollup → emit.

**Result:** 3 live determinations (3.1.11 met, 3.1.12 partially-met, 3.1.5 not-met):
- Deductions: 3.1.12 (partial → NOT MET, 5 pts) + 3.1.5 (not-met, 3 pts) = 8 points.
- `ceiling_if_unassessed_all_met` = 102 (labeled optimistic upper bound, NOT submittable).
- Assessed-subset: earned 1 of 9 possible points.
- Rollup attestation `e7c0ab7c…` binds all 3 per-control manifest hashes (verified).
- OSCAL AR (with SPRS props + back-matter rollup resource), POA&M, CycloneDX all schema-valid, 0 errors.
- arch_guard Signal-1 PASS, 0 violations.

**Honesty rails:** partially-met scored as NOT MET (no AC partial-credit exception); weights provisional with explicit verify-before-submission caveat; no 110-based score claimed on a 3-control subset.

### #67 — Catalog Translation layer: evidence-types + discovery queries (2026-07-22)

**Claim:** the discovery loop generates catalog-driven, objective-specific evidence requests (the Gap-1 Translation layer) rather than a hand-passed string.

**Method:** enrich the 800-171 AC catalog with control-level `evidence_types` + per-objective `discovery_query` (`enrich_catalog.py`, idempotent). Add `translate_missing(control, unmet_ids)` and rewire `defer_for_evidence` to use it.

**Result:** 8 controls / 29 objectives enriched. `discovery_demo.py`: empty bundle for 3.1.7 → 4 objective-specific asks + the control evidence_types; partial 3.1.12 with unmet=[b,d] → only those 2 asks targeted. All 8 controls translate cleanly (one non-empty ask per objective). Backward-compat: a hand-written `missing` string still works. arch_guard Signal-1 PASS, 0 violations — Retrieval-port enrichment, zero core touch.

### #68 — Testing methodology: pytest env + adversarial-depth adapter suite (2026-07-22)

**Claim:** the compliance adapter is covered by a real assertion-based suite with adversarial and property-based depth, not eyeball demos — and the attestation tamper-evidence is verified, not asserted.

**Method:** stood up a `prismpath/.venv` (pytest 9.1.1 + hypothesis 6.16 + jsonschema, editable core). Added `verify_manifest()` to core `ledger_airgap` (canonical content-address verifier). Wrote 5 deterministic test files + 1 opt-in gemma file under `adapters/compliance/tests/`, plus `TESTING.md`.

**Result:**
- Core suite now runnable + green: 379 collected, **373 passed / 6 skipped** (git/env-gated).
- Adapter: **86 tests** (83 deterministic + 3 opt-in live-gemma), all green. Live-gemma suite: 3 passed in 31.9s (end-to-end valid standards; two unambiguous bundles land on met / not-met).
- Coverage layers: schema-validity matrix; negative-schema (validate() must REJECT — dropped metadata, bad enum, bad type); invariants (provenance embedding, v5 uuid determinism, token-safe ids); ADVERSARIAL attestation (tamper any bound field detected; override can't be silently re-pointed / rationale rewritten; chain-of-overrides; deferral resume/double-resume/persistence); rollup math + swapped-manifest tamper; hypothesis property tests (any status combo → valid + provenance embedded; SPRS invariant; deterministic; rollup binds exactly the record manifests).
- arch_guard Signal-1 PASS, 0 violations (verify_manifest is core, domain-neutral).

**Value delivered:** the suite immediately caught a real production bug — POA&M emitted an empty `observations` array when all controls were met (OSCAL rejects it); never exposed by the not-met demos. Fixed by omitting empty optional arrays.

### #69 — Dual runtime-selectable catalog: full 800-171 breadth, Rev 2 + Rev 3 (2026-07-22)

**Claim:** the compliance adapter covers the full breadth of 800-171 across all families, and the engine is catalog-agnostic — the assessor selects the standard (Rev 2 or Rev 3) before the audit.

**Method:** `build_catalogs.py` transforms two sources into the adapter schema. Rev 2 from the tbusillo OSCAL mirror (unofficial community transcription — flagged, verify vs NIST PDFs); Rev 3 from usnistgov/oscal-content (official NIST OSCAL). Retrieval port made standard-selectable (`use_standard`/`list_standards`/`catalog_weights`); rollup takes weights from the active catalog; SPRS only for Rev 2.

**Result:**
- Rev 2: 110 controls / 14 families / 308 objectives, DoD weights (5/3/1) on all 110, methods Examine/Interview/Test; curated AC discovery_query preserved.
- Rev 3: 130 controls / 17 families / 422 objectives + ODPs + methods + evidence objects; not SPRS-scored (rollup marks `applicable:false`, recorded as `sprs-status` in the OSCAL AR).
- `catalog_hash` binds the active standard (attestations differ per standard).
- Tests: adapter now 95 (91 deterministic + 4 opt-in gemma), all green. Live gemma adjudicates R2 and R3 controls end-to-end. arch_guard Signal-1 PASS, 0 violations.

**Honesty rails:** Rev 2 provenance flagged unofficial in `_meta`; Rev 3 marked not-SPRS-scored; methods are control-level for R2 (union across objects). Follow-ups: generic per-family flow (current flow is AC-specific), assessment-method depth (adjudicator does document-Examine only), and CPRT verification of the Rev 2 transcription.

### #70 — Family-agnostic assessment flow (2026-07-22)

**Claim:** the decomposed flow playbook matches the catalog's full breadth — one flow assesses every family under either revision.

**Method:** `flows/nist_800171_generic.md` routes by assessment-method profile (technical/procedural/operational/general) instead of AC sub-families; escalation-default at each adjudicator. `active_flow_hash()` wired into `attest()` so the manifest's policy_hash binds the real flow content.

**Result:** compiles clean (12 nodes / 26 edges); attest binds policy_hash == active_flow_hash (gate nist_800171_generic@v1). Adapter suite now 100 (96 deterministic + 4 gemma), all green; `test_flow.py` asserts compile, method-profile routing, escalation-default-to-POA&M, and the flow-hash binding. arch_guard Signal-1 PASS. AC flow retained as legacy. Follow-up: the adjudicator prompt still emphasizes document-Examine; wiring per-family method emphasis into the runtime prompt is the next depth step.

### #71 — Adjudicator method-depth (2026-07-23)

**Claim:** the adjudicator varies its evidence demand by the family's assessment-method profile, not one document-Examine prompt for all.

**Method:** `_method_profile(control)` classifies by family_name into technical/procedural/operational/general (matching the generic flow); profile guidance + the control's catalog methods (Examine/Interview/Test) injected into the adjudication prompt.

**Result:** zero general-leak across both catalogs (R2 83/8/19, R3 88/18/24). Adapter suite now 129 (125 deterministic + 4 gemma), all green; test_method_profile.py covers classification, risk-vs-security-assessment disambiguation, full-catalog no-leak, and prompt-injection (monkeypatched, no gemma). Gemma regression: unambiguous determinations unchanged. arch_guard PASS. Follow-up: the profile still shapes the PROMPT only; a future step could route to distinct decision nodes per profile (true graph decomposition) and score interview/test evidence sufficiency explicitly.

### agy-authored map — engine generalization proof (2026-07-23)

**Claim:** the PrismPath maps-and-directions format is authorable by an INDEPENDENT frontier model (agy) from the spec (docs/guides/authoring.md/SPEC.md) + a task description alone — not just by us.

**Method:** agy (Antigravity CLI, user-driven) given the format rules + a NIST 800-171 assessment task spec, explicitly told NOT to read our flows; instructed to self-validate with `prismpath validate`. Output: flows/agy_800171_assessment.md.

**Result:** compiles clean on the engine validator. 9 nodes / 17 edges (11 deterministic / 6 semantic), terminal=attest. agy independently: split deterministic `when` (no_evidence, determination==X, visits>=3) from semantic judgment edges (intent-only-policy/out-of-scope/missing-objective) per the routing spectrum; encoded escalation-default; built a BOUNDED discovery loop (check_evidence <-> request_evidence with a `when visits >= 3` guard) — more complete at the flow level than our hand-written nist_800171_generic.md (which handles discovery in Python). Nuance: its adjudicate-node semantic fallbacks are shadowed by the deterministic determination edges (precedence). Ours differs by routing on method-profile (#71); agy used a single adjudicate node.

**Value:** independent-authorability is a real generalization/usability signal for the ENGINE. Follow-up: fold agy's in-graph bounded discovery loop into nist_800171_generic.md. Maps-execution (engine walks the .md with gemma as node agent) still deferred.

### Labeled-corpus efficacy test — INVALID (agy authored circular evidence) (2026-07-23)

**What ran:** agy authored a 9-control x 3-difficulty labeled corpus (efficacy/corpus/, 27 bundles), then gemma adjudicated each; efficacy_harness.py compared gemma vs agy's `_label.status`.

**Raw numbers (DO NOT TRUST):** overall agreement 52%; by difficulty easy .44 / medium .11 / hard 1.0; gemma distribution 0 met / 3 partial / 24 not-met; confusion agy-met->gemma-not-met x5, agy-partial->gemma-not-met x8.

**Why invalid:** spot-check showed agy did NOT author real evidence — every bundle's "evidence" is a single `policy` doc that RESTATES the control objectives as declarative claims with a verdict preamble ("All objectives are fully met." / "Most objectives are met."), and the label just tracks that preamble. No configs/logs/screenshots/records. Asking an LLM to "generate evidence labeled X" yields the conclusion, not substantive evidence.

**Correct conclusion:** gemma behaved CORRECTLY — it rejected circular intent-only assertions as not-met every time (escalation-default working; not fooled by "we are compliant" text). This raises confidence in the adjudicator, not lowers it. The "hard=100%" is a class-imbalance artifact (all not-met on both sides). #62 already showed gemma awards met/partial on genuine implementation evidence.

**Methodology lesson (vindicates the BLIND approach):** the blind "be a company, write your docs" framing produced realistic artifacts (SSP/IR plan/roster/draft RA) and a better test; the "author evidence labeled X" framing produced degenerate circular text. Prefer blind generation. A valid positive test still needs a corpus with genuine met-worthy implementation evidence (concrete config/logs/screenshots), or a human/third-model reference. See [[testing-depth-standard]] [[agy-antigravity-cli]].

### Semantic retrieval (EmbeddingGemma) — retrieval was NOT the bottleneck (2026-07-23)

**Method:** replaced lexical TF-IDF ingestion with EmbeddingGemma-300m (CPU, GPU/gemma untouched) semantic retrieval over the 15 blind company docs → 14 breadth controls (semantic_retrieve.py under jupyterlab venv; ingest_company.py --map adjudicates under prismpath venv).

**Result:** routing quality improved for TOPICAL prose (MP->Media_Protection_Standard 0.64, IR->IR_Plan 0.52, RA->Risk_Assessment, PE->Physical_Policy) — real improvement over lexical. BUT disposition distribution UNCHANGED: 14/14 not-met, identical to lexical, control-for-control (zero flips).

**Conclusion:** retrieval was NOT the cause of uniform not-met (earlier hypothesis FALSIFIED). Dispositions are driven by evidence quality; agy's blind company is genuinely paper-only (policies/SSP/draft RA/template IR plan) and correctly fails escalation-default regardless of routing. Triangulated across lexical + semantic + gap-summary inspection -> adjudicator is evidence-driven and correctly strict.

**Residuals (logged):** semantic retrieval is a genuine keep (routes prose well) but can't route RAW ARTIFACTS (logs/configs/CSVs — content is data not prose) -> needs doc-type/metadata-aware HYBRID ingestion. SSP legitimately dominates (discusses all families). Still no clean POSITIVE test (company with genuinely-met controls).

**Env note:** installed sentence-transformers into ~/jupyterlab/.venv (torch already present); bumped its transformers 4.56.1->4.57.6 (4.56.1 warned EmbeddingGemma bidirectional may fall back to causal; briefly hit 5.14.1 which broke peft HybridCache, pinned back to <5). EmbeddingGemma-300m cached at ~/.cache/huggingface (1.2G). See [[gb10-wazuh-hub]].

### #72 — PPT v1 table compiler + C target: declared-subset certification (2026-08-06)

**Claim:** a Level M flow compiles to a binary table image (PPT v1) and a fixed C interpreter reproduces the frozen conformance vectors on a **declared subset** — the portability-tier pattern taken one level down. The subset is stated, never exceeded: this is NOT SPEC §8 conformance, and no hardware-target claim uses "conformant" unqualified.

**Method:** `ppt_compile.py` uses the repo's own classifier (`prismpath.model_check`) as the fragment authority — the compiler cannot disagree with `verify --level-m`; chained comparisons desugared per SPEC §4.3 SHOULD (exact: operands pure, comparisons total); compilation over reachable nodes only (SPEC §7); error/event edges skipped as host-side tiers. `run_vectors.py` filters the corpus to the declared v0 domain (ints/bools/interned strings; no floats), compiles each case, runs `interp.c`, diffs; every image compiled twice and byte-compared.

**Result:** **114/1,067 predicate + 6/27 engine vectors pass with zero divergence**; every excluded vector carries a **machine-readable exclusion reason**; recompiles **byte-identical** (gated). Repo sweep: **8/23** flow files fully table-compile; `wazuh_triage` (production SOC flow, unmodified) = **302 bytes** (5 fields, 9 atoms, 12 nodes, 19 edges); `incident_severity` = **136 bytes**. Provenance: `prismpath-hw/` (`make cert`, `TABLE_FORMAT.md`).

### #73 — RTL interpreter: vector-equivalent in simulation; AXI wrapper bus-proven (2026-08-06)

**Claim:** a fixed Verilog interpreter circuit reproduces the C target exactly — one synthesized-shape design, every flow loaded as runtime data through a load port, never re-synthesized per flow.

**Method:** `rtl/ppt_interp.sv` under cocotb 1.9.2 + Verilator 5.020; the testbench mirrors the C harness (same subset filter, same expectations) and drives the DUT's load port per image. Second test replays the full Day-2 live sensor log; third suite drives `rtl/ppt_axi.sv` through real AXI4-Lite transactions.

**Result:** **same 114 + 6 vectors, zero divergence, one DUT build**; **7,436 live sensor samples** replayed through simulated fabric reproduce the C target's live decisions with **zero mismatches** (spec → C → RTL: three implementations, one behavior, physical data); evaluate = **5–21 cycles**; AXI wrapper: **532-sample** replay via bus transactions, zero mismatches. Provenance: `prismpath-hw/` (`make -C tb`, `make -C tb/axi`).

### #74 — Vivado overlay: timing-clean at 50 MHz, two percent of the part (2026-08-06)

**Claim:** the interpreter synthesizes, implements, and closes timing on a Zynq-7020 (Arty Z7-20, PYNQ-Z1 v3.1.1 image) as an AXI-Lite peripheral, at negligible area.

**Method:** Vivado 2023.2 batch (`vivado/build_overlay.tcl`), part `xc7z020clg400-1` targeted directly; PS7 configured from a previously board-proven preset; interpreter attached as a module reference.

**Result:** fabric clock **50 MHz**: WNS **+1.623 ns**, **0/4,455 failing endpoints**, hold clean (+0.044 ns). 100 MHz missed by **5.23 ns** (single-cycle atom path; a one-stage fetch/evaluate overlap is backlogged, PR-sized, expected ~2× latency win). Resources: **1,064 LUTs (2.0% of XC7Z020)**, 995 FFs (0.9%), 300 LUTRAM, 0.5 BRAM tile. WCET: **100–420 ns per evaluate** (5–21 cycles at 50 MHz). Provenance: `prismpath-hw/evidence/timing.rpt`, `utilization.rpt` (hashes in `SHA256SUMS`).

### #75 — First light on silicon: live sensor fields routed in fabric (2026-08-07)

**Claim:** the bitstream on the physical board answers memory-mapped evaluate correctly, and an unmodified repo flow routes live sensor fields in fabric.

**Method:** PYNQ overlay load; magic-register check (`"PPT1"`) asserted before use; the 136-byte `incident_severity` image written into fabric over AXI-Lite MMIO; live BNO086 accelerometer fields streamed from a host bridge; every sample and decision logged with per-sample timing.

**Result:** **2,985 live samples routed in fabric**; round-trip **89/96/202 µs min/median/max — including Linux, Python, and an SSH-tunnel hop** (the fabric evaluate itself is the measured 5–21 cycles of #73/#74); hand-run choreography executed by the circuit: `watch` → `sev3_ticket` → `sev2_oncall` → `sev1_page` in 0.3 s, peak deviation 5.0 m/s², decay to `watch`. Artifact hashes: `ppt_overlay.bit` = `2b69d54dc2194f40d0d06e555e18e1b9550ab3929f7b781c155fa38acbbc88d2`, `incident_severity.ppt` = `314b033cd1251b6da7671cbd8a209be0b46d3babd77e254bed1b669ea4d83065` — both in the OTS-anchored `SHA256SUMS`. Provenance: `prismpath-hw/evidence/fabric_session1.ndjson`.

### #76 — Classifier/evaluator disagreement found by the compiler, fixed (2026-08-06)

**Claim:** the hardware work functioned as a spec stress test: the first external consumer of the Level M classifier surfaced a real soundness defect.

**Method:** the table compiler consumed `model_check._atom_reason` as its fragment authority and hit conditions the evaluator rejects.

**Result:** `is_level_m("when x is None")` returned in-fragment while `eval_condition` raises `PredicateError` on `is`/`is not` (the corpus records such cases as ERROR) — so `verify --level-m` could call table-compilable what the engine won't run. Fixed (operator gate in `_atom_reason`) + two regression rows; full suite 525 green; shipped on `main` as `6638670`.

### #77 — eBPF target: in-kernel conformance + real-flow triage on a live alert stream (2026-08-09)

**Claim:** the same decidability that compiles Level M to FPGA BRAM makes it a verifier-accepted eBPF/XDP program, and that program is conformant *in-kernel* against the same frozen corpus as every other substrate — and executes real flows.

**Method:** the loader drives the actual XDP program in-kernel via `BPF_PROG_TEST_RUN` (no NIC). `cert_corpus.py` frames every in-fragment vector of `portable/conformance/predicates.json` (table-per-vector) and cross-checks each against `interp.c`; `run`/`runbatch` drive whole flows hop-by-hop and compare paths to the host reference. The 12-node Level M SOC flow `adapters/soc/flows/wazuh_triage.md` was run against a live Wazuh alert stream, each alert given a real verdict by the live LLM (`classify_verdict`).

**Result:** **66/66 of the Level M fragment** certified in-kernel, byte-matching the reference; the 1001 excluded vectors are itemized as not-match-action (field-vs-field, arithmetic, floats, string-ordering, `is`, …), none an eBPF limit (max operand-stack depth used = 2 of `STACK_MAX=4`). **27/27 real alerts** routed identically in-kernel and by the reference, branching correctly (`benign` vs `stage_containment`) on real LLM verdicts — including the LLM correctly downgrading a loopback-sourced brute-force to benign. Kernel 6.17 (aarch64), libbpf 1.3, in `prismpath/prismpath-ebpf/`. **Not yet earned:** live line-rate deployment on real traffic, a real-packet parser front-end, and measured per-packet latency (the "line-rate" claim is designed-for, not measured).
