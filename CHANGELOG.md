# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/). Versioning: the **package** follows
SemVer; the **format spec** is versioned independently (SPEC.md §8) — any regeneration of the
frozen conformance vectors that changes an existing case bumps the spec version, and that diff
is the spec-change review. Pre-1.0, minor versions may break APIs; the flow *format* is already
spec-stable.

## [Unreleased]

### Added
- **eBPF target: real-packet classification on live traffic + measured latency + live policy hot-swap.**
  `ppt_net.bpf.c` reuses the verified eval back-end with a real-packet front-end (parses on-wire
  Ethernet/IPv4/TCP-UDP into a fixed canonical register file) and classifies each packet with a Level M
  table, observe-only. Attached to `span0` (the home-traffic mirror) it classified thousands of real
  packets in-kernel with a sensible TLS-dominant distribution. Per-packet latency measured via
  `BPF_PROG_TEST_RUN`: **132–182 ns/packet, ~5.5–7.6 Mpps/core** — sub-microsecond, earned not asserted.
  `netupdate` **hot-swaps the policy of a running program in place** (repopulates the table maps via the
  program's map-IDs — no detach, no reload); demonstrated live by editing `net_triage.md`, recompiling,
  and swapping a 7-class table for an 8-class one while classification continued uninterrupted. New:
  `ppt_net.bpf.c`, `net_triage.md`, `net_compile.py`, loader `netattach`/`netstats`/`netdetach`/
  `netbench`/`netupdate`. Honestly bounded (README §9): observe-only (no inline drop yet), generic/SKB
  XDP, latency is program compute cost not end-to-end wire latency.
- **eBPF target: in-kernel conformance + whole-flow execution.** The `prismpath-ebpf` loader gained
  `certify` / `run` / `runbatch` modes that drive the actual verifier-accepted XDP program in-kernel via
  `BPF_PROG_TEST_RUN`. The eBPF target now **certifies 66/66 of the Level M fragment** of the frozen
  `predicates.json` corpus in-kernel (byte-matching `interp.c`; the other 1001 vectors are excluded as
  not-match-action, each reason itemized, none an eBPF limit — max stack depth used = 2 of 4). Real
  multi-node flows execute in-kernel: the 12-node `adapters/soc/flows/wazuh_triage.md` routed a **live
  Wazuh alert stream** (real LLM verdicts) 27/27 identically to the reference. New harness:
  `cert_corpus.py`, `cert_vectors.py`, `run_flow_demo.py`, `run_stream_demo.py`, `run_incident_demo.py`.
  Framing: the Level M corpus is the cross-substrate standard; richer tiers are named, never a lump "+X."
  Not yet done (stated honestly in the target README): live line-rate deployment, a real-packet parser
  front-end, and measured performance.
- **`prismpath context <flow.md>`** (`prismpath/flow_context.py`) — emits the kernel's own *verified*
  facts about a flow (nodes, edges, declared fields, reachability, Level M status, capability tiers) as
  grounding for an agent authoring/editing it. Composes `model_check` primitives; JSON or prose.

### Changed
- **Sprint-engine hygiene: it never deletes your files, and the game-flavored "council" is gone.**
  `run_sprint.py` no longer auto-wipes `SPRINT_PROJ` — the old `SPRINT_FRESH=1` default ran
  `shutil.rmtree`, one typo from erasing a real project. Greenfield now requires an empty dir (or
  `SPRINT_EXTEND=1` to build on an existing tree), else it errors clearly; choosing and clearing the
  location is the user's call. The **council** deliberation subsystem (`prismpath/plugins/council/`,
  the `prismpath/dice.py` shim, `council_next`, the role lenses) is **deleted** — the swarm backend
  uses the `review` role. Game-flavored language ("player", "gameplay", "one more run", "world object",
  …) is removed from the core: PrismPath itself carries no game flavor; that lives only in
  ports/adapters/examples.

### Added
- **eBPF/XDP target — a decidable PrismPath table runs in the Linux kernel** (`prismpath-ebpf/`). A
  third certified substrate beside the Python reference and the FPGA C-table (`prismpath-hw/`): a
  Level M / PPT table image is loaded into BPF maps and executed by an XDP program whose interpreter
  (nested `bpf_loop` for the edge + prog machines, a constant-indexed operand stack, a per-CPU-map
  register file) is **accepted by the kernel verifier** and computes verdicts **byte-identical to the
  C reference `interp.c`** on real packets — proven end-to-end (`sudo make smoke`) at full 32/64/64
  bounds on kernel 6.17. Declared subset: operand-stack depth ≤ 4. The PPT format + reference
  interpreter stay canonical in `prismpath-hw` (referenced, not duplicated). `prismpath-ebpf/README.md`
  has the full verifier analysis, including the approaches that failed and why.
- **Portability matrix + reachability, now in the portable kernel and provably in sync** — two
  analyses that used to be Python-only are ported to `prismpath/portable/prismpath.mjs`:
  `capabilityReport` (which targets a flow compiles to — python / portable JS-Rust-Go / Level M
  hardware — and, for the ones it doesn't, the blocking edges) and `checkReach` (three-valued
  yes/may/no bounded-model-checking reachability with `assume`/visit-caps/witnesses). Each is a faithful
  port of its `model_check` reference and is **certified against a frozen corpus** so the CLI and the
  browser can never disagree: `capability.json` (6 cases) and `reach.json` (11 cases), checked from
  Python (`test_capability_conformance.py`, `test_reach_conformance.py`) and JS
  (`run_capability.mjs`, `run_reach.mjs`). New CLI subcommand `prismpath capability <flow>` prints the
  matrix (`--json` for machine output). The website playground gains a live **Targets** matrix and a
  **Prove reachability** panel (node picker + optional `assume`, verdict + witness path), all
  client-side.
- **Code nodes — governed workers with a capability-scoped sandbox** (`prismpath/code_nodes.py`,
  `prismpath/sandbox.py`). A node's worker can be plain code; the flow still governs the routing
  (branching stays on the edges). Each code node declares an `@code(net, fs, timeout_s, mem_mb)`
  capability envelope — statically checkable (`check_code_nodes`, verifiable like Level M) — and runs
  **fail-closed**: no undeclared code, no invalid envelope, and (via `SandboxRunner`) a `bwrap`
  subprocess whose profile is derived from the envelope, **refusing rather than degrading** when the
  sandbox is unavailable. Guide: [`docs/guides/code-nodes.md`](docs/guides/code-nodes.md); 14 tests.
- **Security posture clarified** ([`docs/design/spec-guard-onion.md`](docs/design/spec-guard-onion.md)
  §1.5): PrismPath owns provable **routing** and governed code **execution** (the code-node sandbox);
  **content** safety is delegated to the model or an opt-in guard — the routing layer is the wrong place
  for a content filter. The content guard is therefore an **optional**
  floor (`guard.py`, Journeyman's `guard.ts`), deliberately **not** embedded in the portable Rust/Go/JS
  kernels; each kernel's `CONFORMANCE.md` now states "a conformant kernel is not a content-guarded one."
- **Mission Control rebuilt as a proving + observability command center**
  (`prismpath/mission_control/`, now a FastAPI package; run `python -m prismpath.mission_control`).
  A single-user, loopback console over a **versioned JSON API** (`/api/v1`, OpenAPI at `/docs`): the
  flow topology (vendored Cytoscape) with live run-state over SSE; **text-in proving** — `POST
  /prove/level-m` and `POST /prove/reach` run the real `model_check` against a posted flow document,
  never a server path (closing the old arbitrary-read surface); audit self-verify; RAG-retrieval
  visibility (`/retrievals`, per node); a **buffered/unbuffered** launch toggle. The proving/
  observability API is the driving adapter other services connect to; the browser console is its
  first client. It runs **no models** — inference belongs to the worker tier. Needs the
  `control-plane` extra (fastapi/uvicorn/pydantic). Guide:
  [`docs/guides/mission-control-api.md`](docs/guides/mission-control-api.md); 13-test TestClient suite.
  **Removed** with the old multi-user scope: Tailscale identity, the Gemma chat, RAG doc-upload, and
  the AGY tab; the stdlib `http.server` console (`python -u prismpath/mission_control.py`) is retired.
- **The sprint engine goes language-agnostic** — a **pysprint gate** plugin
  (`prismpath/plugins/pysprint/`) runs pytest as the definition-of-done, so a sprint can build Python
  targets, not just web; plus a **feature-extend mode** (`SPRINT_EXTEND` — skip greenfield ideate to
  extend an existing tree) and an **uncheatable frozen gate** (tests read from a read-only dir outside
  the sandbox). `run_sprint.py` now honors the gate plugin's `FILE_EXTS`.
- **mdflow interop** (`prismpath/examples/mdflow_interop/`) — mdflow tasks run as PrismPath workers
  behind the routing kernel ("PrismPath governs the routing; mdflow provides the action"), via mdflow's
  `--json` envelope; gated example + tests.
- **The Level M hardware target ([`prismpath-hw/`](prismpath-hw/README.md))** —
  a Level M flow compiles to a binary table image (`wazuh_triage`, unmodified: 302 bytes)
  interpreted by one fixed FPGA circuit on a Zynq-7020; C and RTL interpreters certified on a
  **declared subset** of the frozen corpus (114/1,067 predicate + 6/27 engine vectors, zero
  divergence, machine-readable exclusion reasons — deliberately *not* SPEC §8 conformance);
  timing-clean at 50 MHz (1,064 LUTs = 2.0% of the part, WCET 100–420 ns/decision); 2,985 live
  sensor samples routed in fabric; evidence hashes OTS-anchored. Gates: `make cert` + the cocotb
  suites under `prismpath-hw/`; evidence ledger rows #72–#76. Built off to the side, landed as
  a top-level target directory beside `prismpath-rs/` and `prismpath-go/` after clearing the
  repo's gates (the CLI integration, `compile --target c-table`, stays open on the roadmap).
- **Four conformant kernels** — `prismpath-go` joins Python / JS (`prismpath/portable/prismpath.mjs`) /
  Rust (`prismpath-rs`): a dependency-free Go P0 kernel at 1,067/1,067 predicates and 27/27 flows
  against the frozen vectors. Conformance is now a refereed sport with three independent referees.
- **`prismpath verify` — formal model checking** (`prismpath/model_check.py`): "state X can never be
  reached under condition Y", answered by adversarial-worker reachability with first-match
  semantics. Exact verdicts with concrete witness outcomes over the **Level M match-action
  fragment** (SPEC §4.3 membership is now reported per edge, and `portability_tier` carries a
  `level_m` flag); sound over-approximation outside it (semantic/error/event hops labeled "may");
  `visits` modeled with saturation so UNREACHABLE is proven for all bounds. `--reach/--forbid/
  --assume/--bound/--level-m/--json`.
- **`prismpath lsp` — a Language Server, stdlib only** (`prismpath/lsp.py`): live diagnostics (the
  full validate check set, anchored to the offending edge line), completion (targets, derived
  predicate fields, tier keywords, annotations), hover, document symbols, and a `prismpath/graph`
  Mermaid request — for Neovim, JetBrains (LSP4IJ), VS Code, and any LSP editor. Client setup in
  `prismpath/editor/README.md`.
- **Fan-out debugging + live visualization** — `composer.fanout_tree()` (read-only composition
  trees: all child stop states, join progress with the gate-aware done-criterion, `child_error`
  reasons, nested fan-outs) behind Mission Control's new **Flows tab** (`/api/fanouts`,
  `/api/fanout/ckpt` queue-dir-confined).
- **The Connector SDK, complete** (`prismpath/connector.py`): all six hexagonal ports —
  Adjudicator (callable-driven, never assumes an LLM; flat prompts via `PayloadFlattener`;
  optional `guard.guarded_exchange` routing), Deferral (`DeferralStore` wiring), an idempotent
  JSONL sink default, `checkpoint.flow_hash()` (public) as the attestation policy hash, and the
  proven one-line plugin pattern `WORKERS = MyConnector().get_workers()`.
- **Production SIEM integrations** (`adapters/soc/siem.py`): a `SIEMSource` ingestion port with
  `ElasticSource` (any Elasticsearch/OpenSearch-compatible indexer; env-configured, TLS
  verification on by default), `WazuhSource` (lazy, opt-in legacy credentials), `NDJSONFileSource`
  (air-gap/replay), and a best-effort `SplunkSource`. The SOC agent now rides the Connector SDK
  (`WazuhTriageConnector`) with env seams matching the compliance adapter, plus `cw-triage`
  systemd units.
- **Automatic prefilter tuning** — `prefilter.tune()` derives the cache's operating point from
  evidence: a (threshold × min_conf) sweep with a **Wilson upper bound** certifying the
  reuse-error rate ≤ `--risk` (the `calibrate` pattern applied to reuse); refuses to choose when
  the evidence can't clear the bound. `tuning.json` slots under explicit args and env in
  precedence; the SOC adapter's `labels` command feeds the tuner its own adjudication history.

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
  (build targets), and **CLI** subcommands. Auditable end to end: `prismpath plugins [--json]`
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

- **`docs/decoder-ring.md` — the glossary and repo map.** Every term the papers borrow from
  statistics, formal methods, and distributed systems, explained in plain language: the Wilson
  interval (and why it is read from both ends), selective classification and abstention, δ vs τ,
  Learn-Then-Test and why this is *not* conformal prediction, James-Stein shrinkage, Cohen's κ,
  the match-action fragment and one-sided soundness, hexagonal ports, Merkle batching. Plus an
  A–Z glossary, an index of every document / kernel / CLI command / module, and ordered reading
  paths. Caveats travel with their concepts — the κ entry states that 0.961 is the author agreeing
  with the author's own labeling process, not inter-annotator reliability — so a reader who never
  opens a paper still can't over-claim from it.

### Changed
- **Documentation consolidated into a top-level `docs/` tree** — the 12 standalone documents were
  scattered across the repo root, the package dir, and `prismpath/docs/papers/`; they now live in
  `docs/{guides,design,research}/` with kebab-case names. Deliberately *not* moved: files tooling
  reads at the root only (README, LICENSE, CITATION.cff, action.yml), the community-health files
  GitHub surfaces in its UI, SPEC/GETTING_STARTED/ROADMAP as normative text and entry points,
  subsystem READMEs (a README documents its own directory), and program data that merely looks
  like docs (`flows/`, `gallery/`, `nudges/`, `policies/statutory_floor.md`,
  `tests/fixtures/broken/`). `prismpath/docs/` is gone, so the package dir holds only code and
  runtime data. All 12 moves preserve `git log --follow` history; every relative link re-resolved
  (0 broken across 108 files) and 53 bare-path prose citations rewritten.
- **Docs ship in the wheel** under `share/doc/prismpath/`, mirroring the repo layout rather than
  flattened — flattening collides `README.md` with `docs/README.md` and dangles every relative
  cross-doc link. New `MANIFEST.in` carries the same set into sdists.
- **The roblox plugin is gone** (deep excision): the game-dev-origin gate plugin (~9 MB incl. its
  RAG index) was never meant to fuse into PrismPath. The sprint control plane is now fully
  target-generic; the council deliberation expansion stays. `plugins.load_gate` no longer aliases
  `luau`.
- **APP_ARCHITECTURE.md → `prismpath/nudges/`** — it is a coder-prompt contract, not a doc; all
  reference sites now resolve it `__file__`-relative (CWD-independent).

### Fixed
- **The Level M classifier accepted `is`/`is not` — the evaluator rejects them**
  (`prismpath/model_check.py`): `_atom_reason` never checked the comparison operator against the
  evaluator's allowed set, so `verify --level-m` could call an edge table-compilable that
  `eval_condition` refuses as unsafe (the corpus records such predicates as ERROR). Found by the
  hardware target's compiler — the classifier's first external consumer — on its first day.
  Operator gate added + regression rows; check, eval, and classify accept the same language again.
- **CI red on Python 3.10/3.11 — a backslash inside an f-string expression** (`prismpath/lsp.py`).
  Legal only on 3.12+, a `SyntaxError` on the older interpreters CI tests against, which aborted
  the entire collection. The expression is hoisted to a variable; the full suite now passes under
  3.11 (verified locally) and the whole package compiles clean under `python3.11 -m compileall`.
- **The wheel was missing files shipped code opens** — `package-data` omitted
  `prismpath/policies/statutory_floor.md` (loaded by `guard`, `measure_p1`, `bypass_report` and
  three test modules) and `prismpath/tests/fixtures/broken/*.md` (read by `test_analysis`). Present
  in the repo, absent from an installed wheel. Both now declared, along with `policies/*.json`.
- **`tools/docs_health.py` failed silently on a stale path** — the evidence-ledger location was
  hardcoded behind an `if os.path.exists(...) else ""`, so a wrong path degraded into reporting
  *every* task and artifact as a coverage gap with no error. Repointed, and it now asserts loudly
  rather than degrading.
- **`tools/arch_guard.py` recreated the directory the reorganization removed** — it wrote its
  scorecard into `prismpath/docs/`. Now writes `docs/design/arch-scorecard.md`, git-ignored, with
  `tools/arch_scorecard.json` remaining the committed artifact. Also caught a genuine **Signal-1
  HARD FAIL** it had not been run against: a Connector SDK docstring used "FPGA", a registered
  sensor-domain noun, inside core. Reworded; Signal-1 passes with 0 violations.
- **The README's headline example did not compile** — the front-page `support_triage` flow routed
  to `billing`, `retention`, and `general` without defining them: three `undefined-target` errors,
  in the showcase for a project whose headline feature is "your flow compiles." The three terminal
  nodes are now present, and the Mermaid beside it is verbatim `prismpath graph` output rather than
  a hand-drawing captioned as tool output. A sweep now validates every self-contained flow snippet
  in the docs; the two paper excerpts it also caught are fixed, and the annotated anatomy diagrams
  in SPEC.md / authoring.md are correctly exempt.
- **The mdflow → prismpath rename had corrupted both papers** — a blanket substitution overwrote a
  *third party's* project name in Related Work ("Lindquist's `prismpath` task runner, unrelated to
  this system"), destroying the attribution and inverting the disambiguation. Restored to `mdflow`
  with a note that explains itself. Also 11 uncopyable commands (`python -m PrismPath.cli`, the
  whitepaper's entire CLI reference block) and two article artifacts ("an PrismPath author"). The
  research paper had been using the correct lowercase form 12 times elsewhere.
- **OTS anchoring read the wrong ledger** — `ledger_ots.from_ledger()` defaulted to the
  pre-rename `refs/mdflow/runs` namespace and `Mdflow-Output-Hash` trailer key, which the ledger
  writer never produces; `prismpath ledger anchor` always found nothing. Now matches `ledger.py`
  exactly (verified against a real ledger). Part of a repo-wide mdflow-leftover sweep that also
  restored the seven `research/` scripts and the compliance adapter's tooling paths.

## [0.1.0] — the initial baseline (pre-release)

The baseline is the whole system; highlights rather than an exhaustive list. (Released
2026-08-06, OpenTimestamps-anchored in Bitcoin block 961224 — see the README's "The launch is
anchored" — with a Zenodo DOI in `CITATION.cff`. On the *next* release, [Unreleased] folds
forward into its notes.)

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
- `prismpath/portable/prismpath.mjs` — parser + predicate sandbox + engine for the ML-free subset in one
  dependency-free ES module (browser/edge/Node), certified against the vectors; the
  **playground** (`prismpath/portable/playground.html`) runs it client-side.

### Measured
- N=300/301 labeled routing suite + reproducible head-to-head vs LangGraph / CrewAI /
  LLM-router; **hybrid-over-centroids**: 90.0% @ 160 LLM calls/1k, 95.3% @ 360, 98.0% @ 507
  (5-fold CV, shared LLM pass; `prismpath/benchmark/hybrid_sweep.py`); polarity 0.52 → 0.92. Prefilter
  reuse audited live (97% oracle agreement, zero unsafe downgrades).
