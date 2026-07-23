# PrismPath — Developer Handoff

_Last updated: 2026-07-23. Written by the dev at the end of a long session that built the compliance
adapter and stress-tested the engine's decision quality. Read this first if you are picking up PrismPath._

---

## 1. Orientation — what exists and where it lives

PrismPath is **agent workflows as data**: one markdown file (a "map & directions") is a decision graph
the engine walks. The engine + toolchain + control plane are documented in [../README.md](../README.md)
(read it — this handoff assumes it).

**Two-repo reality (important):**
- `~/cwprojects/prismpath` — the **published engine package** (`prismpath/`). Core kernel, routing,
  the attestation tier (`ledger_airgap.py`, `ledger_ots.py`), the Deferral port (`deferral.py`),
  `tools/arch_guard.py`, the 379-test suite. This is the thing to keep clean.
- `~/cwprojects/mdflow` — the **internal working tree** where domain **adapters** live
  (`adapters/compliance/`, plus the SOC flows). Adapters `import prismpath` (the published core).
  The mdflow root also holds a lot of retired/legacy files from before the mdflow→prismpath rename;
  its `git status` shows large deletions from that restructure — **left uncommitted on purpose**, not
  mine to reconcile.

**Hexagonal boundary:** the engine owns routing/attestation/toolchain; domains plug in behind six
**ports** (Ingestion, Retrieval, Adjudicator, Action/Sink, Attestation, Deferral). `tools/arch_guard.py`
Signal-1 (a domain noun in the core) is a **hard fail** — keep it green.

---

## 2. What this session built — the compliance adapter (#60–#72)

A second reference adapter (after SOC triage), proving the hexagon generalizes. In
`mdflow/adapters/compliance/`:

- **Ports & runtime** (`compliance_adapter.py`): Retrieval (runtime-selectable catalog), Ingestion,
  Adjudicator (escalation-default, method-profile-aware), Sink, Attestation (reuses core
  `ledger_airgap`), Deferral (HITL override + evidence discovery).
- **Dual catalog** (`catalog/nist_800171_r2.json`, `_r3.json`; built by `build_catalogs.py`):
  Rev 2 (110 controls / 14 families, DoD SPRS weights, from an unofficial OSCAL mirror — flagged
  provisional) and Rev 3 (130 / 17, **official** NIST OSCAL). `use_standard()` selects at runtime;
  `catalog_hash()` binds the active standard into every attestation.
- **Family-agnostic flow** (`flows/nist_800171_generic.md`): routes by assessment-method profile
  (technical / procedural / operational / general), escalation-default at every adjudicator, with an
  **in-graph bounded discovery loop** (`check_evidence ⇄ request_evidence`, `when visits > 3`).
- **Dual emitter** (`emit.py`): OSCAL (AR + POA&M) **and** CycloneDX 1.6, schema-validated against
  cached NIST/OWASP schemas in `schemas/`. Every report carries the Flow-Ledger provenance.
- **System rollup** (`rollup.py`): partial SPRS score (honest caveats; Rev 2 only) + scope binding +
  a rollup attestation whose inputs are the per-control manifests.
- **Attestation core additions** (in `prismpath`): `verify_manifest` (tamper verifier),
  `override_manifest` (superseding human-override commit), `deferral.py` (the Deferral port).
- **Tests** (`tests/`): ~130 (deterministic + adversarial attestation-tamper + hypothesis property +
  opt-in `-m gemma` live). Run methodology in `TESTING.md`. Boundary in `ADAPTER_CONTRACT.md`.

### The efficacy investigation (#72) — the honest part
We stress-tested *decision quality* with an independent model (**agy** = Antigravity CLI, an interactively-authenticated frontier agent the project
owner drives) authoring held-out corpora, so we were not grading tests we wrote.

Findings (all in `docs/papers/SUPPORTING_EVIDENCE.md`), triangulated:
1. **Blind company docs** (agy authored a realistic small-firm doc package) → 14/14 not-met, with
   *specific* gap citations (draft policy, template IR plan, incomplete roster). The adjudicator reads
   evidence and is not padded.
2. **Labeled corpus** (agy authored evidence + labels) → **invalid**: agy wrote *circular* evidence
   (restated objectives + "all objectives are met"), so the labels track a preamble, not evidence.
   Gemma correctly rejected all of it → **not gamed by assertions.** Lesson: "author evidence labeled
   X" makes a model write the conclusion; **blind "be a company" is the better framing.**
3. **Semantic retrieval** (EmbeddingGemma, CPU) vs lexical TF-IDF → **zero** disposition change.
   Retrieval was **not** the bottleneck; evidence quality drives verdicts. Semantic routes prose
   better but cannot route raw artifacts (logs/configs/CSVs).
4. **agy authored a valid PrismPath map** from the spec alone (`flows/agy_800171_assessment.md`,
   compiles clean) — an **engine authorability / generalization** win.

**Open question worth a deliberate decision:** escalation-default is so conservative it may rarely award
"met" on the realistically-thin evidence small clients actually have. For an auditor-*multiplier* that
is arguably correct (never falsely pass; queue for human review), but it is a calibration dial, not an
accident. #62 confirms it *does* award met/partial on genuine implementation evidence.

**The oracle problem is real:** agy is an unreliable grader. A certified accuracy number needs a
credentialed human assessor (a monetarily-gated pilot reality) or a much more carefully authored
positive corpus.

---

## 3. Current state (as of 2026-07-23)

**Git — nothing pushed, `master` untouched in both repos:**
- `mdflow` @ branch `compliance-adapter-full-breadth`: `c98e4b3` (#60–#71) + `177535e` (efficacy + folded
  discovery loop).
- `prismpath` @ branch `attestation-deferral-verify`: `0757641` (core attestation/deferral/verify) +
  `7dae61d` (efficacy findings in SUPPORTING_EVIDENCE).
- **Uncommitted after those commits:** this `docs/HANDOFF.md` and the README update (commit them).
  Generated corpora/reports under `efficacy/` are gitignored.

**Tests green:** core `pytest prismpath/tests` = 379 (373 pass / 6 skip); compliance adapter = ~130
(126 deterministic + 4 opt-in gemma). arch_guard Signal-1 PASS, 0 violations.

**Environments on GB10:**
- `~/cwprojects/prismpath/.venv` — pytest + hypothesis + jsonschema + editable prismpath (the test env).
- `~/jupyterlab/.venv` — has torch; I added `sentence-transformers` and pinned `transformers==4.57.6`
  (`<5`; 5.x breaks `peft`). This is the env that runs EmbeddingGemma (`semantic_retrieve.py`), **CPU**
  to keep the GPU/gemma free. EmbeddingGemma-300m cached at `~/.cache/huggingface` (1.2 GB).
- Gemma-4-31B served by vLLM at `http://127.0.0.1:8888` (`gemma4`, chat). Do not OOM it.

---

## 4. How to run things

```bash
GB10=gb10   # ssh alias in ~/.ssh/config (192.168.4.10, user cwadmin, key gb10_ed25519)

# Core engine tests
ssh $GB10 'cd ~/cwprojects/prismpath && .venv/bin/python -m pytest prismpath/tests -q'

# Validate a map compiles
ssh $GB10 'cd ~/cwprojects/mdflow/adapters/compliance && ~/cwprojects/prismpath/.venv/bin/python -m prismpath.cli validate flows/nist_800171_generic.md'

# Compliance adapter suite (fast + opt-in live-gemma)
ssh $GB10 'cd ~/cwprojects/mdflow/adapters/compliance && ~/cwprojects/prismpath/.venv/bin/python -m pytest -q'      # deterministic
ssh $GB10 'cd ~/cwprojects/mdflow/adapters/compliance && ~/cwprojects/prismpath/.venv/bin/python -m pytest -m gemma -q'  # live

# Rebuild catalogs / switch standard
#   use_standard("nist_800171_r2" | "nist_800171_r3") in compliance_adapter

# Efficacy harness (agy = Antigravity, user-authenticated; headless ssh cannot OAuth)
#   see the agy memory; task prompts staged under efficacy/*.md
# Semantic retrieval (EmbeddingGemma, CPU):
ssh $GB10 'cd ~/cwprojects/mdflow/adapters/compliance && ~/jupyterlab/.venv/bin/python semantic_retrieve.py'
ssh $GB10 'cd ~/cwprojects/mdflow/adapters/compliance && python3 ingest_company.py --map efficacy/semantic_map.json'
```

### Gotchas the next dev will hit
- **Anti-OOM (hard rule):** never stand a model up beside gemma on the GPU. EmbeddingGemma runs CPU.
- **agy needs interactive OAuth** — the user drives it; headless ssh cannot authenticate.
- **ssh single-quote + apostrophe trap:** an apostrophe in an `ssh $GB10 '...'` command closes the
  quote. Write scripts/messages to a file and `scp` them (used throughout).
- **Credential-scanning guardrail:** reading `/proc/<pid>/environ` / grepping configs for tokens is
  blocked. Don't.
- **gemma structured output degenerates on nested-object-array JSON schemas** — keep adjudication
  schemas FLAT (see ADAPTER_CONTRACT).
- Firewall/OPNsense work is stage-only, never apply. Never print credentials.

---

## 5. Next major direction — the Tutor adapter (the third domain)

The generalization thesis wants a third, maximally-different domain (education, not security). Per the
project owner, the Tutor work is **not** just another engine adapter — it needs a **product shell built
first**, then combined with this engine as the backend:

- **A Tauri shell** (desktop app) plus a number of other front-end/runtime components to be developed
  before wiring PrismPath in as the decision backend.
- Carry forward the three patterns this session proved: **blind generation** for held-out testing, the
  **differential/HITL harness**, and **semantic retrieval** (EmbeddingGemma for text; ET-BERT is the
  flow embedder).
- The adapter side (behind the ports) should mirror compliance: a domain catalog (curriculum), a
  decomposed flow (pedagogy), escalation-default-style adjudication (mastery), attestation of learner
  decisions, and a Deferral/HITL path (mentor escalation).

Do the shell/components first; the engine plugs in behind the same six ports when they are ready.

---

## 6. Logged follow-ups (not done; deliberately deferred)

- **Raw-artifact ingestion:** logs/configs/CSVs don't embed near objective prose → needs a
  doc-type/metadata-aware **hybrid** retrieval (filename + type + semantic). Semantic alone isn't enough.
- **Positive efficacy corpus:** a company/bundle set with genuinely *met*-worthy implementation
  evidence, to get a clean graded number (needs a strict authoring spec or a human reference).
- **Escalation-default calibration:** decide, deliberately, how conservative "met" should be.
- **Maps execution:** wire the engine to actually *walk* an agy-authored map with gemma as the node
  agent (today the compliance adapter dispositions in Python; the `.md` is a validated playbook).
- **Adapter extraction:** promote `adapters/*` out of the mdflow working tree into first-class plugin
  packages; relocate the SOC adapter under `adapters/soc/`.
- **Semantic ingestion not wired as the adapter default** (dependency weight); it's a test-path today.

---

## 7. Where the receipts are
- Engine: [../README.md](../README.md), [AUTHORING.md](AUTHORING.md), [../SPEC.md](../SPEC.md).
- Adapter: `mdflow/adapters/compliance/ADAPTER_CONTRACT.md`, `TESTING.md`.
- Results ledger (every claim above): [docs/papers/SUPPORTING_EVIDENCE.md](docs/papers/SUPPORTING_EVIDENCE.md).
- Architecture boundary: `tools/arch_guard.py` + `arch_guard.config.json`.
