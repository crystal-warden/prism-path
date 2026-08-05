# PrismPath Adapter Standard

How we **create, stage, architect, develop, and verify** a domain adapter. Every use case follows this;
the two reference adapters (`soc/`, `compliance/`) conform, and the next domain starts here.

The thesis: **the engine is domain-agnostic; a domain is a set of small decisions plugged in behind
ports.** If you find yourself adding domain vocabulary to the core, stop — it belongs in an adapter.

---

## 1. What an adapter is

An adapter turns a stream of domain inputs into **attested, escalation-default decisions**, using only
the engine's ports. It adds **zero domain nouns to the core** — `tools/arch_guard.py` Signal-1 (a domain
term in the `prismpath/` package) is a **hard fail**. The engine owns routing, attestation, and the
toolchain; the adapter owns the domain knowledge, the decision prompts, and the sinks.

## 2. The six ports

| Port | Responsibility | Core primitive it reuses | Required? |
|---|---|---|---|
| **Ingestion** | pull the next unit of work + hash its inputs | `connector.BaseConnector.ingest_payload` / `compute_ingestion_hash` (override) | ✅ |
| **Retrieval** | the domain knowledge as *decision criteria*, one-directional (the dilution rule: criteria in, never a context dump) | `BaseConnector.retrieve_criteria` / `compute_knowledge_hash`; `prismpath` embedder / a catalog | ✅ |
| **Adjudicator** | the escalation-default determination (the decision node — never assumes an LLM) | `BaseConnector.adjudicate` + `adjudication_prompt` (flat, overridable); optional `guard.guarded_exchange` | ✅ |
| **Action / Sink** | write the record / emit the standard artifact | `BaseConnector.emit_record` (idempotent JSONL default; override for OSCAL/CycloneDX/…) | ✅ |
| **Attestation** | bind the decision to its inputs, tamper-evident | `BaseConnector.attest_decision` / `policy_hash_for` → `ledger_airgap.provenance_manifest` / `verify_manifest` / `override_manifest`; `ledger` CLI | ✅ |
| **Deferral** | suspend for human review (HITL override) or missing-input discovery; resume with the actor | `BaseConnector.defer_decision` / `resume_decision` → `deferral.py` (FileDeferralStore, injectable) | recommended |

Minimum viable adapter = Ingestion + Adjudicator + Sink + Attestation. Add Retrieval when decisions need
domain knowledge, Deferral when a human must be able to override or evidence is requested.

**Auxiliary (not ports):** the *cheap gate* (`prismpath.prefilter.PrefilterCache`, §4.7) and the
*embedder* are shared infrastructure an adapter may use — they appear in adapter contracts as extra
rows, but the boundary is the six ports above.

## 2b. Building on the Connector SDK

`prismpath.connector.BaseConnector` implements all six ports as one subclassable surface, plus
`PayloadFlattener` (the nested-payload → flat key/value middleware behind invariant §4.3) and
node-handler dispatch that makes a connector instance a flow agent (with `_worker` provenance on
every outcome). Both reference adapters consume it — `WazuhTriageConnector` (SOC) and
`ComplianceConnector` (compliance) — each keeping its module-level functions as the stable API and
delegating to the connector, so an SDK upgrade lands in every adapter at once. A connector becomes
a pip-installable plugin in one line: ``WORKERS = MyConnector().get_workers()`` under a
``prismpath.plugins`` entry point. Start a new adapter by subclassing; override only the ports the
domain actually bends.

## 3. Standard directory layout

```
adapters/<domain>/
  <domain>_adapter.py     # the ports + runtime wiring (the one file that IS the adapter)
  <sink>.py               # emit/rollup/record modules (Sink), if non-trivial
  knowledge/ | catalog/   # Retrieval content (domain knowledge / control catalog / detection library)
  flows/                  # the decomposed map(s) — `prismpath validate` must pass
  schemas/                # output-schema validation, if the Sink emits a standard (OSCAL/CycloneDX/…)
  requests/ | corpus/     # sample inputs / fixtures
  tests/                  # deterministic + adversarial + property + opt-in live (see §6)
  efficacy/               # held-out blind-corpus harness (optional, strongly recommended — see §6)
  ADAPTER_CONTRACT.md     # the port boundary + domain-specific rules (the normative contract)
  TESTING.md              # the test methodology + how to run
  README.md               # file map + quickstart
```

## 4. Design invariants (the rules every adapter follows)

1. **Escalation-default framing.** The safe outcome is the default: *NOT X unless the input positively
   demonstrates X.* (`not-met` unless evidenced; `contain/escalate` unless benign is shown.)
2. **Decomposed flow, routed by a domain profile.** Narrow decision nodes beat a monolith (#54). Route
   by the axis that changes the evidence bar — assessment-method profile (compliance), MITRE tactic
   (SOC) — into per-profile escalation-default adjudicators.
3. **FLAT adjudication schemas.** The served model degenerates on nested object-array JSON schemas —
   keep determination schemas flat (enums + string/array-of-string), with a concise-retry fallback.
4. **Attestation reuses the core, never re-implements it.** `provenance_manifest` binds
   `policy_hash` (the flow-content hash) + `gate_id` + `knowledge_base_hash` + `ingestion_hashes`.
   Human overrides are a **superseding** `override_manifest` (attest the AI decision first, immutable).
5. **Retrieval is one-directional.** Knowledge flows in as criteria; a decision never writes back into
   the knowledge base mid-run. Inject criteria per-item, not as an undifferentiated dump.
6. **No domain nouns in core.** Register the domain's nouns in `tools/arch_guard.config.json`
   (`domain_nouns.<domain>`) so Signal-1 guards the boundary; list the adapter under `adapters.<domain>`.
8. **Model I/O crosses the guard.** Every call into a model or tool goes through
   `prismpath.guard.guarded_exchange`, composed from the statutory floor plus any augmentation the
   adapter's domain needs. The safety boundary is a layer, not an adapter concern: an adapter may add
   strictness and can never subtract it (the policy language has no permitting verb). Bind
   `guard.policy_hash` into the attestation manifest so *which safety policy ran* is provable. See
   `prismpath/SPEC_guard_onion.md`.

7. **A cheap gate before the expensive node, where inputs recur.** If one adjudication node dominates
   cost and inputs repeat, put a `PrefilterCache` (SOC) or a retrieval/skip in front — measured, opt-in.

## 5. The development lifecycle (create → stage → architect → develop → verify)

1. **Scaffold** the dir (§3) from this template. Register in `arch_guard.config` (domain_nouns + adapter).
2. **Retrieval** — build the knowledge (`catalog/` or `knowledge/`); give it a stable `*_hash()`.
3. **Flow** — author the decomposed map (§4.2); `prismpath validate` until clean; it is the `policy_hash`.
4. **Adjudicator** — flat schema (§4.3) + escalation-default prompt (§4.1) + per-profile guidance.
5. **Sink** — write the record; emit the standard artifact + schema-validate it if applicable.
6. **Attestation** — reuse `ledger_airgap`; bind flow + knowledge + ingestion hashes.
7. **Deferral / HITL** — wire defer/resume; overrides as superseding commits.
8. **Tests** — the §6 layers.
9. **Efficacy** — a held-out **blind** corpus from an *independent* model + a differential harness (§6).
10. **Gate** — `arch_guard` Signal-1 PASS, `docs_health` clean, full suite green. Only then is it done.

## 6. Testing standard (this is the bar — eyeball demos are not tests)

- **Deterministic matrix** — every branch/state, parametrized; no model.
- **Negative** — the guard must *bite*: malformed/invalid input is rejected (a validator that never
  rejects proves nothing).
- **Adversarial attestation** — tamper any bound field → `verify_manifest` false; overrides can't be
  silently re-pointed; deferral resume/double-resume/persistence.
- **Property-based (hypothesis)** — the invariants hold for *any* input (always valid, provenance always
  embedded, monotonic scores).
- **Opt-in live** — real model / real environment behind a marker (`-m gemma`, `-m live`); kept out of
  the default fast run.
- **Efficacy (held-out)** — an *independent* model authors a **blind** corpus ("be a company", "here is
  a day of alerts"), the adapter dispositions it, and a **differential** compares against an independent
  reference; disagreements route to the HITL queue. Framed honestly as model-vs-model, not certification.
  Lesson learned: *"author data labeled X"* makes a model write the conclusion — always go blind.

## 7. The two reference adapters (how each maps the standard)

| | **compliance** (NIST 800-171) | **soc** (blue-team triage) |
|---|---|---|
| Ingestion | control + evidence bundle | Wazuh alert (SIEM) |
| Retrieval | dual catalog (Rev 2 / Rev 3), selectable | detection knowledge + prefilter corpus |
| Route axis | assessment-method profile | MITRE ATT&CK tactic |
| Adjudicator | met / partially-met / not-met | contain / watch / ignore |
| Cheap gate | (none) | `PrefilterCache` — ~59% auto-resolve, measured |
| Sink | OSCAL + CycloneDX + SPRS rollup | finding + staged (never applied) containment |
| Attestation | provenance + override + OTS air-gap | Flow-Ledger proof-commits |
| Deferral | HITL override + evidence discovery | human-gated containment |
| Tests | ~130 (det + adversarial + property + gemma) | flow-compile + structure + opt-in live-SIEM |

Both are escalation-default, decomposed, and attested. They differ only where the *domain* differs —
which is the whole point of the ports.

## 8. Registering a new adapter

In `tools/arch_guard.config.json`: add `domain_nouns.<domain>` (the terms that must never appear in core)
and an `adapters.<domain>` entry (`code`, `flows`). Then arch_guard guards your boundary automatically.
