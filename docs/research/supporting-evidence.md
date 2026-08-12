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
| Per-tenant suppression (#44) | **17.3% hard-suppressed** (skip LLM) on 5k live alerts + context-tagged over-calls; hash-versioned | `etbert-lab/suppression.py`, `homelab.json` |
| Learning flywheel (#38) | authoritative labels teach cache (recurrence auto-resolves cos 0.994) + propose context rules; **self-labels REFUSED, threats never suppressed** | `etbert-lab/flywheel.py` |
| OTS anchoring connected v1 (#36) | ledger enumerate → Merkle → real Bitcoin `ots stamp` → verify → **tamper-evident** | `prismpath/ledger_ots.py`; `docs/design/spec-ledger-opentimestamps.md` |
| OTS air-gap tier (#53) — disconnected attestation | T1 batch-and-forward (tiny hash-only bundle across the diode; real stamp round-trip proven) + **T2 RFC-3161 internal-TSA validated fully OFFLINE** (query->sign->`Verification: OK`->tamper rejected) + C1 provenance binding (POLICY_HASH+gate+ingestion) + C4 salt + `prismpath ledger` CLI + staged timers. Extends attestation to DIB/OT/healthcare air-gapped sites. | `prismpath/ledger_airgap.py`, `deploy/systemd/`, `docs/design/spec-ledger-opentimestamps.md` §4/§6 |
| Shadow-pilot harness (P6) | dry-run: containment agreement 0.867, **0 dangerous under-calls**, 0 parse errors | `etbert-lab/shadow_agreement.py` |
| Triage vs DIVERSE labeled data (#40, honest breadth) | on 249-technique ATT&CK corpus (single-event): escalation **0.672**, **33% dangerous under-calls** (vs 0 on monotone homelab — the distribution-shift blind spot MEASURED), benign-correct 0.923; weakest = Lateral Movement 2/8. *Caveat: isolated single events understate a correlated stream; attack signal is in the sequence.* | `triage-corpus/validation_v0.json` |
| LM deep-dive (#3): is LM a model gap or ambiguity? | On 14 LM cases escalation is **10/14 (71%)** — the 2/8 draw was pessimistic (LM escalation is high-variance by technique). The 4 under-calls are **all admin-mimicry** (DCOM 10016, impacket-via-mmc, PowerShell-Remoting, System file-create); LLM rationales explicitly read them as "common administrative behavior"/"false positive." One (DCOM 10016) is a **correct** benign call the by-construction label penalizes. **Conclusion: LM under-calls are single-event ambiguity, not a reasoning gap.** | `triage-corpus/lm_deepdive.json` |
| Enrich-lift (#2): does correlated context help? **NEGATIVE.** | Injecting up to 8 same-file correlated events (naive, unordered, unweighted) **lowered** escalation 0.902→0.77 and **raised** under-calls 6→14 (net +8). Only 2 flipped ignore→contain (real multi-event chains); ~10 flipped contain→ignore as benign noise **diluted** the malicious signal. LM barely moved (7/8→6/8) — the #3 "context helps LM most" prediction **refuted**. **Lesson: raw context hurts; context must be ranked/ordered with the anchor event marked, not dumped.** *Caveat: tiny n (5-8/tactic); bounds the naive approach only.* | `triage-corpus/enrich_lift_v0.json` |
| Sequence 3-arm (#1): does ENGINEERED context recover the loss? **STRONG NEGATIVE.** | On 52 paired multi-event cases: escalation A single-event **0.904** > B naive-bag **0.788** > C engineered kill-chain-timeline **0.538**; under-calls 5 / 11 / **24**. `C_recovers_over_B=-0.25` — engineered framing was the WORST arm, monotonically across nearly every tactic. C talked itself out of escalating mimikatz, DCSync, LSASS hashdump, security-log-clearing (1102), and a live CVE-2018-15982 exploit — the ‘look for a progression / a lone event may be benign’ framing handed the model an off-ramp it took. **Conclusion (converges with #2/#3): in-prompt context DEGRADES single-shot triage; the more reasoning room, the more the LLM rationalizes benign. Correlation belongs UPSTREAM as a deterministic layer, NOT as free-text the triage LLM weighs. Validates the 3-layer architecture.** *Caveat: noisy real-capture timelines (bounds the production regime), single model, temp 0, by-construction all-malicious labels.* | `triage-corpus/sequence_lift_v0.json`, `triage_sequence_corpus.jsonl` (249 seqs) |
| Decomposed graph (#54): does a DECISION-GRAPH beat single-shot? **POSITIVE — double win.** | Same 64 malicious + 48 benign, arm A single-shot vs arm D decomposed (signature-gate -> tactic-router -> escalation-defaulted narrow node). D raised malicious-recall **0.844 -> 0.969** (+12.5pts, under-calls 10->2) AND benign-correct **0.792 -> 0.938** (+14.6pts, over-calls 10->3) — improved BOTH ends, not a recall/precision trade. Signature gate resolved **8/64 (12.5%) deterministically, 0 benign FP** (mimikatz/NTDS/DCSync/LSASS/log-clear/encoded-PS). **Completes the arc: monolithic prompt + more context = WORSE (#1/#2/#3); same prompt split into narrow nodes = BETTER on both axes. The lever is DECISION STRUCTURE, not context volume — PrismPath's thesis, validated.** *Caveat: D routed on the corpus's built-in _tactic label (a production router must EARN that classification -> #56); the label-independent, robust gains are the signature gate + escalation-default framing. Small n, by-construction labels.* | `triage-corpus/decomposed_v0.json`, `etbert-lab/validate_triage_decomposed.py` |
| Compliance adapter #2 (#60-62): PrismPath generalizes to a 2nd domain | Decomposed NIST 800-171 control-assessment flow (validates clean, 27-edge graph) reuses the SOC patterns (per-control nodes, escalation-default = the auditor's burden of proof, retrieval-as-criteria). On 8 labeled Access-Control evidence bundles gemma scored **8/8, 0 over-pass, 0 rubber-stamps** including the intent-only / absent-evidence / out-of-boundary failure modes. HEXAGONAL BOUNDARY PROVEN: adding the adapter touched ZERO core files; after extracting the pre-existing SOC leak (measure_prefilter + wazuh_triage_agent) the arch_guard **Signal-1 PASSES (0 violations, core domain-clean, 6019 LOC)**. Caveat: escalation-default vs neutral not separated on this explicit set (needs ambiguous bundles). | `adapters/compliance/`, `tools/arch_guard.py` |
| Embedder-routed graph (#56): does the #54 win survive WITHOUT the free tactic label? **YES — unconfounded.** | EmbeddingGemma routes each alert to a decision node by similarity to TRAIN-split centroids (leading 'Tactic |' prefix STRIPPED so it routes on event content, not the label). Routing: binary attack-vs-benign gate **64/64 + 48/48 = 100%** (0 malicious->benign, 0 benign->attack); fine exact-tactic only 45% but HARMLESS (every attack node shares the escalation-default framing, so a mis-tactic'd alert still escalates). End-to-end **D_embed recall 0.984 / benign 0.938** — matches D_oracle (0.969/0.938), both crush single-shot A (0.844/0.792). **The decomposition win rides on a binary attack/benign separation a learned embedder does perfectly from event content — NOT on the ground-truth label. Production-realizable.** | `triage-corpus/embed_routed_v0.json`, `etbert-lab/validate_triage_embed_routed.py` |
| Agentic PULL node (#55): mechanism validated, efficacy gated on telemetry | Bounded ReAct loop (manual, via structured output — gemma4 tool-calling reliable after concise-retry) lets the triage LLM PULL specific facts via tools instead of us PUSHing a noise-bag. On 3 residual hard cases: **PULL 3/3 correct vs single-shot 2/3** — fixed the wuauclt LotL masquerade under-call by pulling process-lineage (launched by cmd.exe from C:\Users\Public) + host-baseline (never seen); correctly DE-escalated benign DCOM 10016 by pulling related-alerts (no supporting activity). **HONEST: PUSH-all also 3/3 here** — the demo's small/clean evidence stores do NOT exercise PULL's anti-dilution advantage, which only appears with LARGE/noisy real telemetry (the #2/#1 regime). So PULL>PUSH stays GATED on real telemetry (pilot / Tier-1 / probe signals). Deliverable = the working mechanism + production-shaped tool interface (binds to Wazuh/Zeek/baseline/probes), NOT a corpus-wide lift. | `triage-corpus/agentic_pull_demo.json`, `etbert-lab/agentic_investigate.py` |
| ET-BERT live-heavy re-cert (#35) — hardened FP claim | Prior τ=0 FP ≤0.053% rested on only 76 live samples (small-sample artifact). Re-certified on **93,956 live-captured benign flows**: τ=0 observed FP **0.102%**, Wilson-95% **≤0.121%**, certifies at α=0.01 (LB 0.99879). 18× more data, live-distribution — slightly higher but far more defensible; operating point holds at scale. | `etbert-lab/benign_corpus/eval/step4_recert_livepool.json` |
| ET-BERT weak-family recall (#30): calibration can't fix cross-family recall | 66 families, cross-family macro recall 0.224 (3 strong / 29 weak / 34 near-blind). Per-family-floor fix REFUTED: recovers recall 0.224->0.521 but benign FP explodes 1.7%->22.7% (malicious/benign overlap in the 0.85-0.95 band). The cosine layer is a high-precision known-threat matcher; ~22% unseen-family recall is architectural, not tunable. Real levers = corpus growth or a better encoder (#59). Claim as 'known-bad flow detection, ~0.1% FP', NOT 'encrypted-threat detection'. | `etbert-lab/benign_corpus/eval/step6_perfamily_recall.json` |
| Knowledge-library nodes (#58): retrieval-augmented adjudication — mechanism+principle win, efficacy data-gated | Real 239-card LOLBAS index (EmbeddingGemma 768d), retrieval precise (14/64 malicious, **0/48 benign** false-retrieval), air-gap Docker image, KB-hash bound into Flow-Ledger provenance (#53). VALIDATION: v0 injected the full card incl. its 'legitimate binary, mere presence not malicious' framing → HURT the escalation node (recall 0.969->0.875, the #1/#2/#3 dilution effect at a 3rd layer). v1 ONE-DIRECTIONAL abuse-only injection → RECOVERED (ER 0.969/0.938 = E no-knowledge, no harm) + lifted a NEUTRAL node 0.844->0.906 + fixed the wuauclt under-call WITH a cited justification (audit value). **Efficacy WIN not established on this corpus** — knowledge is redundant with the escalation-default prior for recall, and its unique PRECISION benefit (correctly ignoring genuinely-benign LOLBin use) is UNTESTABLE here (0 benign LOLBin cases). Design rule: inject one-directional abuse-evidence, never balanced prose. | `triage-corpus/rag_nodes_v1.json`, `etbert-lab/{build_knowledge_index,validate_triage_rag}.py`, `knowledge-lib/` |

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
Scripts — **this repo** (reproducible here; the input corpus `prismpath/benchmark/routing_bench.jsonl` is
included): `research/gaussian_route_eval.py`, `research/gaussian_route_pca.py`, `research/learning_curve.py`,
`research/embedder_succession.py`, `research/embeddinggemma_scout.py`, `prismpath/ledger_ots.py`. **First-party
`etbert-lab/` lab repo** (SOC-triage + pilot instruments — they need the private triage / knowledge-library /
SIEM corpora and are not reproducible from this repo; see the provenance note above): `suppression.py`,
`flywheel.py`, `shadow_agreement.py`, `validate_triage_*.py`, `lm_deepdive.py`, `agentic_investigate.py`,
`build_knowledge_index.py`, `{build_benign_corpus,step2_margin_eval,step3_grow_calibrate}.py`. Each emits JSON
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

**Methodology lesson (vindicates the BLIND approach):** the blind "be a company, write your docs" framing produced realistic artifacts (SSP/IR plan/roster/draft RA) and a better test; the "author evidence labeled X" framing produced degenerate circular text. Prefer blind generation. A valid positive test still needs a corpus with genuine met-worthy implementation evidence (concrete config/logs/screenshots), or a human/third-model reference.

### Semantic retrieval (EmbeddingGemma) — retrieval was NOT the bottleneck (2026-07-23)

**Method:** replaced lexical TF-IDF ingestion with EmbeddingGemma-300m (CPU, GPU/gemma untouched) semantic retrieval over the 15 blind company docs → 14 breadth controls (semantic_retrieve.py under jupyterlab venv; ingest_company.py --map adjudicates under prismpath venv).

**Result:** routing quality improved for TOPICAL prose (MP->Media_Protection_Standard 0.64, IR->IR_Plan 0.52, RA->Risk_Assessment, PE->Physical_Policy) — real improvement over lexical. BUT disposition distribution UNCHANGED: 14/14 not-met, identical to lexical, control-for-control (zero flips).

**Conclusion:** retrieval was NOT the cause of uniform not-met (earlier hypothesis FALSIFIED). Dispositions are driven by evidence quality; agy's blind company is genuinely paper-only (policies/SSP/draft RA/template IR plan) and correctly fails escalation-default regardless of routing. Triangulated across lexical + semantic + gap-summary inspection -> adjudicator is evidence-driven and correctly strict.

**Residuals (logged):** semantic retrieval is a genuine keep (routes prose well) but can't route RAW ARTIFACTS (logs/configs/CSVs — content is data not prose) -> needs doc-type/metadata-aware HYBRID ingestion. SSP legitimately dominates (discusses all families). Still no clean POSITIVE test (company with genuinely-met controls).

**Env note:** installed sentence-transformers into ~/jupyterlab/.venv (torch already present); bumped its transformers 4.56.1->4.57.6 (4.56.1 warned EmbeddingGemma bidirectional may fall back to causal; briefly hit 5.14.1 which broke peft HybridCache, pinned back to <5). EmbeddingGemma-300m cached at ~/.cache/huggingface (1.2G).

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

**Result:** **114/114 of the declared subset** certified in-kernel, byte-matching the reference — the *same* 114/1067 subset the FPGA C-target certifies (#72), by the same filter: in-fragment condition + the fields it reads representable on the i32 table (126 of the 1067 corpus conditions are in-fragment; 114 vectors have a runnable i32 context). The 953 excluded vectors are itemized — 941 conditions outside the match-action fragment (field-vs-field, string-ordering, **float constants**, `is`, non-literal collections, constant-only, substring/nested) + 12 in-fragment conditions whose read-field context isn't i32-representable (11 non-scalar, 1 float value) — none an eBPF limit (operand-stack depth well under `STACK_MAX=4`). *(Float constants in a condition now fold into the fragment-exclusion bucket, not a separate "float" line: the classifier rejects `field OP <float>` up front — the i32 fragment has no float domain — so `compile_predicate` never reaches its `float-value` guard except for a float in a read-field value.)* *(An earlier draft of this row cited 66/66 from an over-strict `cert_corpus.py` filter that also rejected non-scalar values in fields the condition never reads; corrected to match the FPGA subset.)* **27/27 real alerts** routed identically in-kernel and by the reference, branching correctly (`benign` vs `stage_containment`) on real LLM verdicts — including the LLM correctly downgrading a loopback-sourced brute-force to benign. Kernel 6.17 (aarch64), libbpf 1.3, in `prismpath/prismpath-ebpf/`.

### #78 — eBPF target on live network traffic: real-packet classification, sub-microsecond latency, live policy hot-swap (2026-08-09)

**Claim:** the eBPF target runs as a real in-kernel match-action layer on live traffic — parsing on-wire packets, classifying at sub-microsecond cost, and accepting a policy change (an edited Markdown flow) without a reload.

**Method:** `ppt_net.bpf.c` adds a real-packet front-end (Ethernet/IPv4/TCP-UDP → a fixed canonical register file) to the verified eval back-end, observe-only (`XDP_PASS`). Attached to `span0` (a gretap mirroring all home traffic). Latency via `BPF_PROG_TEST_RUN` ×1e6 on representative packets. Live policy hot-swap via `netupdate`, which repopulates the running program's table maps via its map-IDs — no detach.

**Result:** thousands of real packets classified in-kernel with a sensible TLS-dominant distribution (`(no-match)` bucket 0 — table exhaustive over real traffic; Zeek/AF_PACKET unaffected). Per-packet latency **132–182 ns** (parse + Level M eval), **~5.5–7.6 Mpps/core** (aarch64, generic/SKB XDP) — sub-microsecond, measured. Live hot-swap proven: edited `net_triage.md` (split `quic`=UDP/443 from `https`=TCP/443), recompiled, `netupdate` swapped a 7-class table for an 8-class one while `result_map.pkt_count` climbed straight through — one uninterrupted program instance, policy changed in place. The "swap the map, change the policy, no reprogram" property on the kernel substrate. **Not yet earned:** inline enforcement (observe-only so far), native-driver XDP (this is generic/SKB), and end-to-end wire latency (the figure is program compute cost).

### #79 — Level M fragment change (float rejected, chained normalized) re-certified spec → C → RTL → silicon (2026-08-09)

**Claim:** the classifier change — float constants rejected as non-i32, chained comparisons desugar-then-classified through one shared `_desugar_chains` (classifier ≡ compiler, 0 corpus disagreements) — is safe all the way to the fabric: it changes *which flows are declared* Level M, not *what runs on the board*, and produces byte-identical table images.

**Method:** recompiled `incident_severity` with the changed `ppt_compile` and compared the image SHA to the pre-change image already resident on the board. Re-ran the full stack: `run_vectors.py` (C target, `interp.c`), `make -C tb` (RTL `ppt_interp.sv` under cocotb 1.9.2 / Verilator 5.020), then routed a deterministic 44-sample sweep (both bools × 11 `error_rate` points spanning every ladder threshold) through the **physical Zynq-7020 fabric** — the overlay loaded, `PPT1` magic read back from silicon, table loaded — over a board-initiated reverse-SSH bridge, and diffed each fabric decision against the reference engine.

**Result:** the recompiled image is **byte-identical** — SHA `314b033cd1251b6da7671cbd8a209be0b46d3babd77e254bed1b669ea4d83065`, the same image cited in #75, so no certified number moves. Zero divergence at every layer: **C target 114/114 predicate + 6/6 engine**; **RTL 114 + 6**; **fabric 44/44** across all four severity branches (`watch`/`sev3_ticket`/`sev2_oncall`/`sev1_page`), round-trip **91/93/105 µs** min/median/max. Software gate alongside: full suite 570 green, fuzz 20k clean, all JS conformance runners CONFORMANT. Provenance: `prismpath-hw/evidence/fabric_recert_float_chained.ndjson`.

**Live mid-stream policy swap (measured, same session):** with a **constant** input streamed at 10 Hz to the fabric (`data_at_risk=false, user_facing=true, error_rate=20`), the sev1 threshold was edited `25 → 15`, recompiled, and the new table image `cp`'d over `live.ppt` mid-stream. The identical input flipped **`sev2_oncall` (62 samples) → `sev1_page` (78 samples)** as a clean step — the *policy* changed, not the data. The watcher's `*** TABLE RELOADED in 3.2 ms ***` (the BRAM reprogram) fired with the **bitstream SHA unchanged** (`2b69d54d…`, no resynthesis); only the table image moved (`314b033c…` → `dfc51f4c…`). Swap→effect latency **201 ms** (file-watcher ≤500 ms poll + 3.2 ms reload); per-sample fabric round-trip **93/98/163 µs**. This is the "edit-to-silicon, swap the table, change the policy, never touch the circuit" property, measured on the Zynq-7020. Provenance: `prismpath-hw/evidence/fabric_hotswap_midstream.ndjson`.

### #80 — eBPF target certified on a second architecture (x86_64) + observe-only on a real edge gateway (2026-08-09)

**Claim:** the Level M / PPT eBPF target certifies in-kernel on a second architecture (x86_64) with a newer toolchain, and runs observe-only classifying live traffic on a real inline-capable Linux edge gateway — extending the kernel target from a single aarch64 host to a cross-arch, deployable claim.

**Method:** the `prismpath-ebpf` target was rebuilt clean and certified on an x86_64 Proxmox-based edge appliance (kernel 6.17.2, clang 19.1.7, libbpf) — a different arch AND newer clang than the original aarch64 host (a newer clang can re-open verifier issues, per the maintenance checklist, so this is a real re-verification, not a formality). `make` (native x86_64 build) → `cert_corpus.py` (build corpus + `interp.c` cross-check) → `loader … certify` (in-kernel via `BPF_PROG_TEST_RUN`). Then `ppt_net` was attached **observe-only** (`XDP_PASS`, SKB/generic) to the device-facing interface, scoped to this host's own traffic — never the WAN or LAN production datapath — with a systemd dead-man's-switch auto-detach as insurance, since the attach rode the control link itself.

**Result:** **114/114 in-kernel on x86_64**, byte-matching the reference (`interp.c` cross-check 114/114) — the SAME declared subset the aarch64 host and the FPGA C-target certify; the newer clang/verifier accepted the program unchanged, confirming the fragment→verifier property holds across arch + toolchain. Per-packet latency (`BPF_PROG_TEST_RUN` ×1e6): **81–217 ns/pkt** (dns 81 / jumbo 165 / https 169 / icmp 190 / other 217; ~4.6–12.4 Mpps/core), comparable to the aarch64 132–182 ns. Observe-only attach classified **live traffic in-kernel** — 2,908 packets in ~6 s, https-dominant (2,347 https / 384 other / 115 quic / 31 ssh / 26 http / 5 icmp) — with **zero disruption**: carrier stayed up, the control session was intact throughout, clean detach (pins removed), watchdog never needed. First run of the target on a real inline-capable edge gateway. Enforcement remains **observe-only** (no inline `DROP`/`REDIRECT` — a separate, explicit decision). Provenance: `prismpath-ebpf` (`make`, `loader certify`, `loader netbench`, `loader netattach`/`netstats`/`netdetach`).

### #81 — decision-preserving telemetry adapter: minimum-sufficient-statistic compression on a self-framing wire, benchmark-gated (2026-08-09)

**Claim:** because a flow's routes are decidable functions of `field OP const` thresholds, the coarsest symbol that still resolves every routing decision is the minimum sufficient statistic for that flow's telemetry; an adapter can transmit only that — self-framed, self-healing — with the routing decisions provably preserved. Benchmark-gated, and honestly early (Python reference on modeled data; the hardware codec tier is not built).

**Method:** `adapters/telemetry/` — a decision-preserving quantizer extracts each field's decision cells from the flow (the same `field OP const` atoms `model_check`/`ppt_compile` read), maps a reading to one small symbol per decision-relevant field, and entropy-codes the stream on a Zeckendorf/Fibonacci self-framing wire. A frozen decisions-preserved conformance corpus (`conformance/decisions.json`, `conformance/spiral.json`) replays boundary-probing readings and asserts the wire round-trip (quantize, code, decode, reconstruct) routes identically at every node — the same referee pattern the portable/hardware vectors use. Benchmarks (`bench/`) are go/no-go over synthetic value regimes + a Gilbert-Elliott burst-loss channel model; self-heal reuses the repo's real Merkle primitive (`ledger_ots`). Arch-guard-isolated; 106 standalone tests; the priority date is OpenTimestamps-anchored (`evidence/SHA256SUMS.ots`, confirmed Bitcoin block).

**Result:** the decision stream holds **~2.0 bits/reading** on a wide-range field **independent of magnitude** (~14–16× vs fixed-32; **~1.1–3.1× vs a delta+varint baseline** — the honest comparison); `delta+zz+fib` beats the streaming baselines ~2–3× (batch compressors win on a buffered block but are not self-framing/line-rate — stated, not hidden); selective MMR retransmission is **0.086–0.342 of a full resend** under sparse Gilbert-Elliott loss. Tier-6 decision-first spiral packing (`spiral.py`): one **band ID routes correctly at 1.9×/2.8×/3.6× fewer bits** than the per-field wire for k=2/3/4 correlated dimensions (**no win at k=1, by design**), at fidelity parity, surviving burst loss better (96.4% vs 92.9% light; 80.0% vs 68.1% heavy) — gate **PASS**. **Honest scope:** Python reference on synthetic/modeled data (never field-proven); Phase C **partial** — the word-packed wire (C1) and spiral (C3) landed; a hardware shift-register codec (C2) and a vector-quantization tier (C4) are designed but **not built**. Provenance: `adapters/telemetry/` (`README.md`, `bench/results.md`, `bench/spiral_results.md`, `conformance/`, `evidence/`).

### #82 — cyber-physical decision fusion: one Level M flow joins IMU posture and SIEM verdicts, spiral-tessellated and conformance-frozen (2026-08-12)

**Claim:** a single decidable flow (`fusion_triage`) fuses a physical verdict stream (IMU posture: stability + peak deviation) with a cyber verdict stream (SIEM rule level + triage action) and is proved Level M in-suite; its joint decision space (4 fields, 108 cells) packs onto the Tier-6 spiral with the baseline verdict central and severity radiating outward in 7 bands — and every threshold in the flow is a pre-existing operational boundary, none invented for the demo.

**Method:** `adapters/fusion/` (arch-guard-registered; sensor and SOC vocabulary stay out of core). Thresholds inherited verbatim: 150/500/2500 dev_mg are the sensor bridge's own DEADBAND/MOVE_DEV/SHAKE_DEV constants (`prismpath-hw/bridge/field_bridge.py`); 7 and 12 are the SIEM's triage floor and the wazuh_triage flow's containment edge. `model_check.flow_level_m` → `(True, [])` asserted in-suite; the tessellation (fields `[dev_mg, rule_level, soc_action, stability]`, radices `[4,3,3,3]`, 108 cells, 7 bands, widths growing outward 2→4→9→9→18→24→42) is frozen in `conformance/spiral_fusion.json` with the flow's sha256 pinned and 34 boundary probes replayed three ways (direct evaluation, quantize→wire round-trip, spiral index→band) — the telemetry referee pattern. Mixed numeric/categorical fields exercised the spiral machinery's first cross-kind corpus; no telemetry change was needed.

**Result:** Level M proof green; 34/34 probes decisions-preserved on all three paths; the frozen corpus regenerates byte-identically; 106 adapter tests + the untouched telemetry suite (106) green. The OTHER-collapse is visible and tested: `"still"` is not a flow constant, so it lands in the categorical OTHER cell with any unknown label — the minimum-sufficient-statistic property, not an accident. **Honest scope:** software (Python) proof only — no substrate certification of this flow yet (it is in-fragment by construction; eBPF/FPGA cert + hardware retest is a named follow-on). Provenance: `adapters/fusion/` (`flows/fusion_triage.md`, `conformance/spiral_fusion.json`, `tests/`).

### #83 — fused-band census: a real month-scale SIEM backlog (2.50M alerts) + real IMU sessions weight the tessellation, pairings labeled (2026-08-12)

**Claim:** the fusion tessellation's bands can be weighted with real data — the cyber axis from the live indexer backlog, the physical axis from recorded sensor sessions — and the honest headline is that without time-coincident capture the coincident bands stay empty: the emptiness is the finding.

**Method:** `adapters/fusion/census.py`. Cyber marginal via one read-only aggregation (under the decidable projection `soc_action = f(rule_level)` — the wazuh_triage flow's own 12/7 boundaries, stated verbatim in the artifact — the cyber marginal IS the level histogram; no LLM calls, no 64k document pull). IMU marginal from the three posture-bearing recorded sessions (10,421 rows used; 2,564 derived-dev rows excluded by default, itemized). Two pairings, both labeled in the artifact: `assume_still` (every alert × the baseline posture; the physical axis asserts nothing about the joint) and `independence_expected` (marginals measured, joint modeled, "NOT time-coincident" in the label). Committed artifact is aggregates-only; a privacy regression test walks the committed JSON asserting no agent/srcip/description/full_log keys, no IP-like values, no internal hostnames.

**Result:** `evidence/census_2026-08.json` — cyber N=64,483 at level≥7 (backlog total 2,498,693, span 2026-07-09→2026-08-12); `assume_still`: cyber_watch 64,480 / cyber_containment 3 / all five fusion bands 0. `independence_expected`: physical_escalation 1,330 / tandem_watch 179 / coincident_critical **0** — even under modeled independence a coincident-critical event is not expected in a month, which is exactly what makes a real one meaningful. **Honest scope:** the projection is decidable, so `soc_action` is a deterministic function of `rule_level` in this census (the two facets separate only on the adjudicator path); no pairing here is a joint observation; the live coincident capture is the named follow-on that can fill the fusion bands honestly. Provenance: `adapters/fusion/census.py`, `adapters/fusion/evidence/census_2026-08.json`, `tests/test_census.py`.

### #84 — bandwidth, measured over the whole triage backlog: the fused decision wire is ~1.5 B/alert with its integrity apparatus counted — 1,992× under raw alert JSON, 45× under minimal JSON (2026-08-12)

**Claim:** for the task "the aggregator needs the fused verdict, auditably," the decision-code wire replaces per-alert JSON at three orders of magnitude under the as-shipped raw alert and >10× under even a minimal 4-field JSON — with every overhead byte (Merkle roots, epoch chaining, ACK channel, word padding) itemized and included, on the full real population, not a sample.

**Method:** `adapters/fusion/bench/bandwidth.py` — a `search_after` pager streams every level≥7 alert from the live indexer (the read replicates the pre-measured size sample as a pager-correctness check). Baselines per alert: B0 compact JSON of the full `_source`; B1 the SOC adapter's normalized alert; B2 the four fused decision fields as JSON (the apples-to-apples line); B3 zlib-9/zstd-19 over batch NDJSON (the buffered-batch bound). Ours: O1 the per-field decision stream (`encode_readings` → packed words), O2 the band-ID stream (`SpiralLayout.encode_decision`), both sealed in 4,096-reading epochs of 1,024-bit Merkle-committed blocks (+32 B root, +32 B chained root per epoch; 32 B ACK itemized on its own line), plus a Gilbert-Elliott loss row (selective block repair + 32·⌈log2 N⌉ B inclusion proofs paid on serve).

**Result:** n=**64,484** (every triage-grade alert in the backlog): B0 **3,020 B/alert** (194.8 MB total) · B1 660 · B2 68.1 · **O1 1.516 B/alert** (97.8 KB total, epochs + padding included) · **O2 0.516 B/alert** (33.3 KB — ~4.1 bits per fused decision; the month's entire triage decision history in one floppy-disk-percent). Gates: O1 ≥10× under B2 (**45×**), ≥500× under B0 (**1,992×**), O2 ≤ O1 — **PASS**. Stated before anyone else can: zstd-19 over the minimal-JSON batch (0.22 B/alert) undercuts the streams on pure size — it needs the whole batch buffered, is not self-framing or per-reading streamable, and carries no tamper-evidence; the streams pay their integrity apparatus and stay within striking distance. **Honest scope:** decision-sufficient telemetry, not a lossless alert record — B2 is the honest ratio class; the physical posture in this run is the assume-still baseline (the wire cost is field-shape-invariant); protobuf/OTLP baseline not yet built (named follow-on). Provenance: `adapters/fusion/bench/bandwidth.py`, `adapters/fusion/bench/results.md`, `bench/results.json`.

### #85 — cyber-physical fusion proven on the live rig: real IMU + real SIEM fused in real time, on-chip fusion cross-checked, multi-modal bandwidth measured (2026-08-12)

**Claim:** the fusion pipeline runs end-to-end on real hardware — a BNO086 IMU on this host and the live Wazuh indexer — fused through `fusion_triage` in real time; the sensor's own on-chip fusion classifier independently corroborates our derived posture; and the multi-modal-to-decision bandwidth gap is measured live, per reading. The high-value coincident bands stay empty across every session, which is the honest finding, not a gap.

**Method:** `adapters/fusion/live_capture.py` runs two real streams in the same wall-clock window: the sensor bridge (`prismpath-hw/bridge/field_bridge_multi.py`, the accel-derived decision fields kept byte-identical to the committed pipeline PLUS the on-chip fusion suite — quaternion→orientation and the chip's own stability classifier — at 10 Hz, the sustainable trio rate on the MCP2221A HID pipe; the full six-channel suite saturates it, which is the case for wiring the sensor directly to the FPGA), and the live SIEM (read-only). Each alert is joined to the worst device posture within ±3 s of when it fired and routed through the flow. A genuine high-severity event was self-triggered as authorized detection-validation (a burst of failed SSH logins as non-existent users on the host, no account lockout risk), producing a real level-10 "multiple authentication failures" alert. Three sessions (~10 min total) were captured; committed artifacts are aggregate-only (privacy regression test enforced). Board diagnostics: `prismpath-hw/bridge/probe_reports.py` / `probe_combined.py` confirmed all eight report channels stream on this rig (the earlier accel-only restriction was the old Mac stack, not this host).

**Result:** across the aggregate of 3 live sessions — **4,369 real sensor readings + 90 real SIEM alerts** — the pipeline fused every reading in real time. The chip's own AI classifier agreed with our threshold-derived posture **96.3%** of the time (an independent on-device validation). Multi-modal bandwidth, live per reading: **~252 B** of full on-chip-fusion JSON vs **~6 bits** of decision code — **333× smaller**, decision-lossless (not data-lossless), and a per-reading stream where a batch compressor (zstd) is not a valid competitor. Joint verdicts that fired: `physical_escalation` 55, `all_quiet` 14, `cyber_watch` 1. **Honest scope / not yet earned:** `tandem_watch` and `coincident_critical` were **zero across all sessions** — the triggered level-10 landed during a shake (folding into physical escalation) and the burst did not reach the level-12 breakin rule, so no high-severity cyber event coincided with the right posture; those empty rings are the rare signal the system exists to catch, honestly unlit. Full-rate multi-channel capture and in-hardware fusion await wiring the sensor directly to the FPGA. Provenance: `adapters/fusion/live_capture.py`, `evidence/coincident_2026-08-12.json` (richest single session), `evidence/coincident_aggregate_2026-08-12.json` (3-session union), `prismpath-hw/bridge/field_bridge_multi.py`.
