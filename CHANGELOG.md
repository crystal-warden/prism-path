# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/). Versioning: the **package** follows
SemVer; the **format spec** is versioned independently (SPEC.md §8) — any regeneration of the
frozen conformance vectors that changes an existing case bumps the spec version, and that diff
is the spec-change review. Pre-1.0, minor versions may break APIs; the flow *format* is already
spec-stable.

## [Unreleased]

### Added
- **LEARNING_PLAN.md** — three roads into the same document: parallel tracks for the analyst
  (no code, ever), the developer, and the platform engineer, over the same artifacts, converging
  on the PR-is-the-process-change loop. Centerpiece: the shared-vocabulary table (one concept,
  three dialects, one standardized term) and a checkable "done when" per stage. Grown to six
  personas + a sidebar: SecOps (containment behind human gates, `@field_only` as the
  prompt-injection boundary, air-gap P0 deployment), the auditor (reconstruct any decision
  from artifacts alone; routing changes only by reviewed diff), the decision-maker's hour
  (five questions, reading only), and the human in the queue (a tier, not a fallback). Also
  fixed the README's stale "unbounded run state" limitation (superseded by `@state_bound`).
- **`prismpath ci-report` + the PR comment** — the money demo as a living product: for every flow a
  PR changes, one sticky comment with validate findings, fixture verdicts, and the routing topology
  **before → after as live Mermaid diagrams** (GitHub renders them in the conversation). The Action
  gained a `comment` input (needs `pull-requests: write`); the command works locally too
  (`prismpath ci-report --base origin/main`). Gate semantics: errors and failing fixture rows exit 1;
  advisories inform. Fixture tables needing the embedding tier report "skipped" on kernel-only
  runners instead of failing. Flow detection requires front-matter, so prose docs that embed flow
  snippets are never misreported.
- **URL-shareable playground flows** — 🔗 Share encodes the whole flow (+ scripted outcomes) into
  the URL fragment (base64url; nothing leaves the page — there is no server). Every flow is now a
  link: click it, watch it route, edit the rules live. Cold-load and hashchange both verified in a
  real browser, unicode round-trips.
- **`prismpath run --agent ollama:MODEL`** (and `openai:MODEL@BASE` for vLLM / LM Studio /
  llama.cpp) — a real local model as the worker, one flag after clone (`chat_agent.py`, stdlib
  only). JSON replies feed `when` predicates; endpoint failures ride the flow's `on error` edges.
  Verified live against a local OpenAI-compatible endpoint and pinned by 7 stub-server tests.
- **Three more gallery templates** — `pr_review` (approval with a human gate + the visits-cap
  idiom), `fanout_review` (parent + `review_one` child — `prismpath init --template` now copies a
  template's whole working set, so `@spawn` children travel), `support_triage` (semantic
  classification + deterministic money/severity guard rails). All validate clean; all fixture
  tables green with no model installed.
- **The editor surface** (`prismpath/editor/vscode/`) — a VS Code extension, all thin wrappers over the
  repo's own tooling: a TextMate *injection* grammar coloring edge lines by tier (deterministic /
  semantic / error / event / always) + `@annotations` inside plain Markdown; a live preview webview
  hosting the SAME `prismpath/portable/playground.html` + JS kernel as the browser playground (seeded from the
  buffer, re-fed on every edit — tier badges, checks, ▶ Run, Mermaid; **no Python needed**); and
  optional validate-on-save diagnostics mapped to `## node` lines. The playground gained a
  postMessage embedding hook any host page can use. Grammar tier-classification is pinned by tests.
- **`prismpath init --template <name>`** — every gallery entry doubles as a starter (`--template list`);
  copies the flow AND its routing tests, and the model-free `validate → test` loop works immediately.
- **`prismpath plugins --new <name>`** — scaffold a pip-installable **worker pack** (pyproject with the
  `prismpath.plugins` entry point, `WORKERS` module with a pure example + the `CliWorker` bridge
  comment, pytest, README). Verified end-to-end: `pip install -e` → appears in `prismpath plugins` as
  `[entry-point]` → `@worker(<name>.<worker>)` resolves.
- **The plugin ecosystem** (`prismpath/plugins/registry.py`) — harness-side extension with the engine's
  purity untouched. Plugins (bundled, or pip-installed via the ``prismpath.plugins`` entry-point group)
  provide **workers** (tools a flow binds in the document with `@worker(plugin.name)`), **gates**
  (build targets — roblox), and **CLI** subcommands. Auditable end to end: `prismpath plugins [--json]`
  lists what's installed and what each provides; `prismpath plugins --check flow.md` verifies every
  binding resolves (CI gate); `registry.worker_agent(graph, default=…)` resolves bindings at
  construction (fail-fast) and stamps dispatched outcomes with `_worker` provenance.
- **The council plugin** (`prismpath/plugins/council/`) — the deliberation *expansion* (optional; the
  exception, not the default): `council.roll` (seeded, replayable Oblique-Strategies dice) and
  `council.tally` (coverage/balance-weighted vote tally, deterministic tie-break). `dice.py` moved
  in; a root shim keeps existing imports working.
- **`prismpath init`** — scaffold a starter flow + routing-test table; `init → validate → test` is a
  zero-config, model-free first success (the starter's semantic edges light up once
  `[embeddings]` is installed).
- **`@state_bound(transcript=N)`** — a flow-declared sliding-window bound on persisted run state,
  closing the papers' last open critique (unbounded state growth). The engine windows the transcript
  on append and the re-seeded path/step history on resume, so a long-lived run's checkpoint payload
  stays flat across unlimited resumes; drops are counted deterministically in `_state_dropped`
  (engine stays pure). Routing is unaffected by construction — predicates read fields plus per-node
  `visits`/`error_count` counters, which are never windowed. Malformed bounds fail loudly at run
  start. Engine override: `run(..., max_transcript=N)`.
- **Gate zero delivered** — a human maintainer blind-relabeled all 301 benchmark cases (gold hidden)
  at **Cohen's κ = 0.961 vs gold** ("almost perfect", every stratum ≥ 0.945); an independent
  cross-family model (Gemini) agrees with the human at **κ = 0.682** ("substantial"), with 90% of its
  disagreements concentrated where the model dissents alone against human+gold — mostly the polarity
  stratum (44%), the negation trap the benchmark is built to probe. Write-up:
  `prismpath/benchmark/gate_zero/findings.md`; papers and benchmark README updated from "future work" to
  delivered.
- `prismpath/benchmark/make_blind.py`, `prismpath/benchmark/collect_blind.py` (with explicit, audited
  `--drop-invalid` and `--split-compound FLOW/NODE` modes), `prismpath/benchmark/parse_annotate_transcript.py`
  — the reproducible second-annotator pipeline around `prismpath annotate` / `prismpath kappa`.

## [0.1.0] — first public release

The initial release is the whole system; highlights rather than an exhaustive list:

### The format
- **SPEC.md v1 (draft)** — document grammar, the four edge tiers (deterministic / semantic /
  error / event), normative predicate semantics, engine contract, portability levels P0/P1/P2,
  and the synthesizable **match-action fragment** (Level M).
- **Frozen conformance vectors** (`prismpath/portable/conformance/`): 1,067 predicate cases + 27 engine
  fixtures, generated deterministically from the reference implementation, enforced in both
  directions in CI. Any runtime that passes them is conformant, by definition.

### The reference implementation
- Pure engine with the routing spectrum; safe predicate evaluator (fuzz-gated: ~20k adversarial
  inputs, zero exec, zero uncaught crash); hybrid embed→LLM routing with margin escalation.
- **Data-plane toolchain**: `validate`/`lint` (16 in-graph + 4 cross-flow decidable checks),
  Markdown flow tests, routing lockfile (+ composition-tree pinning, learned-centroid pins),
  risk-controlled calibration (Wilson-bound τ), prototype/centroid routing, Mermaid export,
  OTel spans, LangGraph importer, routing-decision label workbench, portability tiering.
- **Durable execution**: atomic checkpoints with flow-hash-bound resume, human queue,
  wait-for-event + reference timeout scheduler, fan-out/sub-flow composition (`@spawn`,
  deterministic child identity, join policies), git Flow-Ledger proof-commits with
  resume-from-ledger.
- **Prefilter cache** with continuous shadow-sampled reuse-error monitoring, windowed drift
  quarantine, and policy-hash invalidation.
- **CLI workers** (`cli_worker`): any command-line program as a worker; JSON-on-stdout feeds
  predicates; failures ride the error tier.

### The portable kernel
- `portable/prismpath.mjs` — parser + predicate sandbox + engine for the ML-free subset in one
  dependency-free ES module (browser/edge/Node), certified against the vectors; the
  **playground** (`portable/playground.html`) runs it client-side.

### Measured
- N=300/301 labeled routing suite + reproducible head-to-head vs LangGraph / CrewAI /
  LLM-router; **hybrid-over-centroids**: 90.0% @ 160 LLM calls/1k, 95.3% @ 360, 98.0% @ 507
  (5-fold CV, shared LLM pass; `benchmark/hybrid_sweep.py`); polarity 0.52 → 0.92. Prefilter
  reuse audited live (97% oracle agreement, zero unsafe downgrades).
