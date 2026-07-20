# PrismPath: A Routing Spectrum for Human-Authored LLM-Agent Workflows — When Control Flow Is Data, Not Code

*Preprint / workshop-style manuscript. Crystal Warden Labs, 2026-07-10.*
*Target venue class: an ICSE/FSE/NeurIPS-workshop or arXiv preprint (cs.SE / cs.AI).*

---

## Abstract

Orchestrating multi-step LLM-agent work forces a false choice. Code-first graph frameworks
(e.g. LangGraph `StateGraph`) express control flow as Python routing functions — deterministic and
cheap, but authorable only by engineers and opaque to the domain experts who own the process.
LLM-as-router approaches make every transition a model call — expressive, but costly,
non-deterministic, and prone to logical errors (negation, thresholds). We present **PrismPath**, whose
workflow *is a single Markdown file* — each `## heading` is a node whose prose is the instruction to
an agent, and `-> target: condition` lines are edges — and whose central contribution is a
**routing spectrum** of **four edge tiers**, each selected by the syntactic form of the condition
string: (1) a **deterministic** tier — a safe predicate evaluator for conditions expressible as logic;
(2) a **semantic** tier — sentence-embedding similarity for conditions expressible as intent, on which
a *hybrid* router escalates to a one-shot LLM **only when the embedding decision is low-confidence**;
and two further tiers, (3) **error** (`on error [when …]`) and (4) **event** (`on event <name>` /
`on timeout`) — so control, intent, failure, and external signals are each handled by the machinery
that suits them, all in one git-diffable surface syntax. On an N=301
labeled routing suite we find embedding similarity is strong where the correct edge is an intent
distinction (0.81) but **collapses to near-chance on logical polarity (0.52)** — 0.69 overall vs 0.53
for a lexical baseline — a split that *motivates* the spectrum: logic where logic exists, intent where
it does not, and a rare LLM call for the residue.
Against three orchestration frameworks practitioners actually use (LangGraph, CrewAI, a naive
LLM-router), a measured head-to-head on the same suite shows PrismPath reaching **83.7%** accuracy at
**2.6× fewer LLM calls (383 vs 1000 per 1k) and ~2× lower median latency (205 ms vs ~435 ms)**,
because it is the only arm that exposes a routing cost model and can decline the call when a cheaper
signal suffices. We state the tradeoff plainly: because an escalated hop pays an embedding *and* then
the LLM, PrismPath's latency is bimodal — it **wins on median and throughput but loses on the p95 tail
(655 ms vs ~445 ms)**, so a hard-p95-SLA user should route straight to the LLM; the three external
arms tie identically at 99.0% / 1000 calls / ~435 ms. Stacking the two delivered routing levers —
LLM-on-doubt escalation over **learned per-condition centroids** — dominates the zero-shot hybrid at
every call budget: **90.0% at 160 calls/1k and 95.3% at 360/1k** (five-fold cross-validated, one
shared LLM pass), recovering most of the accuracy gap while keeping the cost model. The structural
reason PrismPath can decline a call
is that **PrismPath's control flow is *data*, not code** — a framing that generates a family of operations
ill-defined against a Python routing callback: a routing **lockfile** that pins semantic routing
bit-for-bit, **risk-controlled calibration** that *derives* the escalation threshold with a
finite-sample risk guarantee, a decidable
**static-analysis** pass ("your flow compiles"), a **polarity lint** that catches the embedder's
negation blind-spot at authoring time, **Markdown flow tests** that run without a model, and a
one-way **LangGraph importer**. We further describe **durable, resumable execution** — atomic
checkpoints with flow-hash-bound resume and a human-in-the-loop queue, and a **commit-as-state
Flow-Ledger** in which each gate-green unit is a content-addressed git proof-commit and "done" is a
projection over the log — and a control-plane methodology (machine-enforced "gates as the definition
of done") distilled from a real spec-driven build. We are explicit about the provenance of the
routing evaluation's labels; the once-open bounded-state critique is now closed (§6).

---

## 1. Introduction

An LLM "agent" workflow is a graph: *do some work, look at the outcome, decide what to do next,
repeat.* Two dominant patterns express the "decide" step, and both have a structural flaw.

**Routing-in-code.** Frameworks such as LangGraph model the graph as code — nodes are functions and
edges are conditional routing functions over a typed state object. This is deterministic, testable,
and free at inference time. But the *control flow lives in Python*: the analyst, PM, SOC lead, or
domain expert who actually owns the process cannot read or author it, and the graph is not a
first-class, diffable artifact — it is scattered across function definitions.

**Task-level Markdown runners.** A complementary family of tools treats a *single task* as a
Markdown document — frontmatter selecting the engine and its flags, prose as the prompt — executed
by a CLI (e.g. Lindquist's `prismpath` task runner, unrelated to this system). These operate one
layer below us and compose naturally: such a runner can serve as a node's *worker* through the
generic CLI-worker contract (stdout as outcome, exit codes onto the error tier), while our system
routes *between* tasks by outcome. The layering — every task a document, the workflow over them a
document — is complementary, not competing.

**Routing-by-LLM.** Alternatively, each decision is delegated to an LLM ("given the outcome, which
edge?"). This is maximally expressive and needs no code for the branch logic — but it spends a model
call on *every* transition (latency + cost), is non-deterministic, and, notoriously, gets **logic**
wrong: negation ("tests did *not* pass"), counts, and thresholds are exactly where language models
are unreliable, yet they are the cheapest things to compute exactly.

PrismPath's thesis is that **the two failure modes are complementary and should be composed, not
chosen between.** A second, deeper thesis underlies everything that follows: **because a PrismPath flow
*is* an inspectable Markdown document, its control flow is *data*, not code.** Every edge condition is
a string in that file, and
that single fact is the generator of a family of operations that are well-defined against data and
ill-defined against a Python routing callback: you can diff a decision, lint the graph for a
contradiction *without running it*, pin an embedding, draw the true topology, test the routing with
no model, and translate a foreign code graph into it. We contribute:

1. **Markdown-as-graph.** The workflow is one human-authored, git-diffable Markdown file. A node is a
   heading plus prose; an edge is `-> target: condition`. The artifact a PM reads *is* the artifact
   the engine runs — no translation layer.
2. **The routing spectrum, extended to four edge tiers.** A transition is resolved by the cheapest
   sufficient mechanism, and the engine — not the author — chooses the mechanism per edge by the
   *syntactic form* of the condition string. Beyond the original **deterministic** (`when <expr>`)
   and **semantic** (natural-language) tiers, the same classifier partitions two further forms:
   **error** edges (`on error [when …]`) that fire only when the worker raises, and **event** edges
   (`on event <name>` / `on timeout`) that suspend the run until an external signal.
3. **A hybrid router with a confidence frontier.** Embeddings settle the confident transitions for
   free; a one-shot LLM is consulted only when the top-1↔top-2 similarity margin is below a
   threshold δ, bounding LLM calls while repairing the cases embeddings get wrong.
4. **Durable, resumable execution and a commit-as-state Flow-Ledger** — an *agent-agnostic* control
   plane. A run is made crash-resumable and suspendable-for-a-human by atomic JSON checkpoints whose
   resume is bound to a content hash of the flow; each gate-green *unit* of work becomes a
   content-addressed git proof-commit on a per-run orphan ref, so "which units are done" is a
   *projection over `git log`*, not an asserted status field.
5. **The flow-is-data toolchain**, delivered: a routing **lockfile** (reproducible semantic routing),
   **risk-controlled calibration** of the escalation threshold with a finite-sample guarantee, a decidable
   **static-analysis** pass, an authoring-time **polarity lint**, **Markdown flow tests**, a Mermaid
   **graph export**, **OpenTelemetry** decision-spans, and a **LangGraph importer** — each a lever on
   the data-not-code asymmetry (§2, §3.3, §3.4, §4.3).
6. **An empirical characterization** of *where* each tier is needed, a **measured head-to-head**
   against LangGraph, CrewAI, and an LLM-router (§4.4), and a control-plane methodology
   (gates-as-definition-of-done, spec-driven drift control) drawn from a real build.

---

## 2. Related work

**Code-first agent/graph frameworks.** LangGraph (`StateGraph`), and agent frameworks generally,
encode control flow as code. PrismPath keeps the graph as a declarative, human-owned document and makes
*routing* the pluggable concern. This is not merely a stylistic choice: PrismPath ships a **one-way
importer** (`prismpath import` — the `prismpath` command throughout this paper is the `console_scripts`
entry point `prismpath = prismpath.cli:main` from `pip install prismpath`; equivalently `python -m PrismPath.cli
<cmd>`) that walks a LangGraph `StateGraph`'s
Python AST — `add_node` /
`add_edge` / `set_entry_point` / `add_conditional_edges` — into a skeleton flow, mechanically
translating everything already structural and leaving a per-branch `TODO` exactly where a routing
*function* (opaque code, not data) must be rewritten as a prose condition (`langgraph_import.py`).
The importer *targets* roughly a 70/30 split — a design goal stated in `langgraph_import.py`'s
docstring ("Fidelity is deliberately ~70%"), not a measured statistic — between what imports cleanly
and what needs a human: that heuristic boundary *is* the code-vs-data boundary made visible, and the
importer doubles as an adoption wedge.

**Observability and evaluation platforms.** LangSmith, Langfuse, Arize Phoenix, and W&B Weave
trace agent runs, evaluate outputs (often LLM-as-judge), queue traces for human annotation, and
version prompts. The relationship to PrismPath is threefold rather than competitive. First, a
meaningful fraction of that category exists *because* code-shaped control flow is opaque: tracing
reconstructs a topology that cannot be read, and dashboards surface drift nothing else will catch.
PrismPath removes those needs at the substrate — the topology is static data before any run
(`prismpath graph`, §3.4); a routing decision explains itself because it *is* scored data (margin,
top-1/top-2, escalated-or-not are attributes of the decision, not forensics reconstructed after
it); versioning is git because the whole artifact is a file; and drift detection is the lockfile's
fingerprint check (§3.3), a loud refusal rather than a chart to watch. Second, where the layers
genuinely overlap they differ in kind: output evaluation is inherently fuzzy and judge-mediated,
while `prismpath test` (§3.4) asserts *routing* — exact, model-free, milliseconds in CI; and where
their annotation queues terminate in evaluation dashboards, `prismpath label`'s labels terminate in
the router — they become the calibrated escalation threshold of §4.3. Third, the layers compose:
PrismPath deliberately emits OpenTelemetry decision-spans into whatever observability stack a team
already runs (§3.4) rather than shipping its own pane of glass, and a worker that is internally a
LangChain chain can keep LangSmith pointed at its interior while PrismPath's spans cover the
decisions *between* workers — different altitudes, no collision. What these platforms do beyond
this scope — output-quality evaluation at scale, token/cost accounting, cohort analytics, prompt
experimentation, multi-tenant RBAC — PrismPath does not attempt.

**Business-process and workflow languages.** BPMN, YAWL, and durable-workflow engines (Temporal,
Airflow, Dagster) offer declarative graphs but with *deterministic* gateways over structured data;
they have no notion of routing on the *natural-language outcome* of a probabilistic worker. We state
the prior art precisely to avoid over-claiming: BPMN *already* has deterministic gateways, error
boundary events, **and** timer events, so PrismPath's error and event tiers are each individually old.
What is new is the **composition**: a *semantic* tier over a probabilistic worker's natural-language
outcome, expressed in one plaintext line a non-engineer can author, with the condition string as the
sole tier selector — so control, intent, failure, and external signal share one git-diffable surface.

**Behavior trees / finite-state machines.** Classic robotics/game control structures are readable
and deterministic but, again, branch on typed conditions only. PrismPath's deterministic predicate tier
is essentially an FSM guard; the novelty is the *graceful fallthrough* to semantic routing.

**Semantic routing and LLM routers.** Sentence-embedding routers (e.g. "semantic-router" style
utterance→route matching) and LLM-as-judge routing are each used in isolation. Model-cascade /
LLM-routing work (routing *queries to models* by difficulty, e.g. RouteLLM) shares the
"cheap-first, escalate-on-doubt" shape, but routes *which model answers*, not *which workflow edge is
taken*. PrismPath applies the cascade idea to **control-flow transitions** and grounds the escalation
signal in the embedding decision's own confidence (top-1↔top-2 margin).

**Semantic caching.** Reusing an LLM answer when a new prompt is embedding-near a prior one is
established (GPTCache and kin). PrismPath's prefilter (§5) does not claim caching as novel; its
contributions are (a) a **two-threshold gate** — similarity asks *"is this the same situation?"* and
the *stored confidence* asks *"was the prior verdict trustworthy?"* — (b) **explicit scoping** (embed
the stable fields, deliberately exclude volatile context) so a reuse is sound, and (c) the deployment
**finding** that memoizing the *worker* (an adjudication node) dominates memoizing the transition.

**Spec-driven and gated agent construction.** Test-driven / spec-driven agent loops exist; PrismPath's
control plane contributes the strong, repeatedly-stated operating principle **"never write a
completeness claim a gate doesn't enforce,"** and empirical findings on multi-agent *specification
drift* and its mitigation via a shared glossary.

### 2.1 Control flow is data, not code

The routing spectrum, taken alone, understates PrismPath's position. The sharper statement is a structural
one: **your control flow is *data*, theirs is code.** In LangGraph, CrewAI, and other Python-native
frameworks, the routing logic (which node runs next, and why) lives inside callbacks — conditional-edge
functions, `@router` methods, `Command` returns — that are executable and opaque to anything that is not
a Python interpreter. In PrismPath the flow is a Markdown document and every edge condition is an inert
string. This asymmetry generates a concrete list of operations, all of which PrismPath ships (below).

Concretely, the data-not-code asymmetry enables — and PrismPath ships — a routing **lockfile** that pins
semantic routing bit-for-bit (§3.3); **Markdown flow tests** that run the real routers without a model
(§3.4); first-class **error edges** (`on error [when …]`) as data in the document (§3.2); **`PrismPath
graph`** Mermaid export of the true topology (§3.4); **OpenTelemetry** decision-spans (§3.4); a one-way
**LangGraph importer** (§2); and **wait-for-event** suspension (`on event <name>` / `on timeout`) as the
fourth edge tier (§3.2). Each is a lever that is well-defined against a string and ill-defined against a
Python routing callback.

These are a subset of a broader data-not-code toolchain we deliver (below), which also includes
**risk-controlled calibration** of the escalation threshold and an authoring-time **polarity lint**:

- **Reproducibility of semantic routing** — the routing **lockfile** (§3.3): because a condition is a
  string embedded into a vector, that vector can be committed as bit-exact, diffable data and routed
  against, so an embedder update is *detected*, not silently mis-routing. You cannot lock the numerics
  of a Python router you re-run.
- **A calibrated, not hand-tuned, escalation threshold** — **risk-controlled calibration** (§4.3;
  Learn-Then-Test / RCPS, a Wilson finite-sample lower bound): the margin is a scalar confidence and
  escalation is abstention, so a labeled set of decisions yields a threshold τ with a finite-sample
  risk guarantee. There is no confidence score to bound over a Python `if`.
- **"Your flow compiles"** — a decidable **static-analysis** pass and an authoring-time **polarity
  lint** (§3.3): the whole control-flow topology is on disk, so reachability, exhaustiveness,
  shadowing, cycle-caps, and predicate satisfiability are decidable *without running anything* — a
  guarantee a runtime-assembled graph structurally cannot give.
- **Flows are drawable, traceable, and testable as data** — Mermaid **graph export**, **OpenTelemetry**
  decision-spans, **Markdown flow tests** run without a model, and a routelog **labeling** workbench
  (§3.4).

We situate these as the honest answer to "why not just LangGraph or CrewAI?": not rhetoric, but a
measured comparison (§4.4) *grounded in* the structural asymmetry. (Both previously-open
objections are now delivered: field-only routing — §3.4, §7 — and the bound on state growth,
`@state_bound` — §6.)

---

## 3. Design

### 3.1 The flow kernel

A flow is a Markdown file with optional YAML front-matter (`name`, `start`). Each `## Heading`
introduces a **node**; the prose beneath it is the node's **instruction**. Lines matching
`-> target: condition` are the node's **edges**. A node with no edges is **terminal**.

```markdown
---
name: bugfix
start: triage
---

## triage
Understand the bug report and decide what to do next.
-> implement: the bug is reproduced and the root cause is clear
-> gather_info: it cannot be reproduced or more information is needed
-> close: it is a duplicate or invalid
```

The engine is agent-agnostic. The **agent contract** is a single callable:

```
agent(node_name: str, instruction: str, state: dict) -> str | dict
```

Returning a **string** yields the text used for semantic routing. Returning a **dict** `{"text":…,
<field>:<value>,…}` additionally exposes structured fields to the deterministic predicate evaluator
(e.g. a testing node returns `{"tests_pass": True, "text": "all tests passed"}`). Shared `state`
carries a `transcript` and a per-node `visits` counter, seeded by the engine. This decoupling makes
the worker pluggable: a hosted LLM, a local agent swarm, a shell step, or a mock all satisfy the
contract.

### 3.2 The routing spectrum: four edge tiers (contribution)

At a node with an outcome, the next edge is chosen by a spectrum, **selected entirely by the
syntactic form of each condition string**. There are **four** such forms, and the classifiers that
recognize them (`predicates.py`) are a *partition*: `is_deterministic`, `is_error`, and `is_event`
each match a keyword prefix, and `is_semantic` is defined as the residual — the negation of the other
three (`predicates.py:82-84`). Every edge therefore belongs to exactly one tier, and the four tiers
compose hierarchically: the engine resolves the deterministic, error, and event tiers itself in pure
Python, and *only* the semantic tier ever reaches a router.

| Tier | Edge syntax | Mechanism | Cost | Guarantee |
|---|---|---|---|---|
| **Deterministic** | `-> t: when <expr>` (or `always`/`else`/`false`) | safe AST evaluation over outcome fields + `visits` | free | exact, reproducible |
| **Semantic** | `-> t: <natural language>` | cosine(embed(outcome), embed(condition)) | one embedding | approximate |
| &nbsp;&nbsp;↳ *hybrid* (router mode on semantic edges) | (same semantic edges) | embed-first; 1-shot LLM iff low-confidence | ~free + rare LLM | approximate, higher accuracy |
| **Error** | `-> t: on error [when <expr>]` | try/except wrap; predicate over the *error context* | free | unmatched ⇒ re-raise (backward-compatible) |
| **Event** | `-> t: on event <name>` / `on timeout` | out-of-band suspension; resumed by delivering the event | free | durable; refuses an unknown event |

The four **tiers** are the four bold rows above — deterministic, semantic, error, event; *hybrid* is
not a fifth tier but a router mode *on* the semantic tier (the indented row), which is why the
classifier partition (`predicates.py:82-84`) recognizes exactly four syntactic forms.

**Decision procedure.** Deterministic edges are evaluated **first, in document order; first true
wins** (`first_deterministic`, `engine.py:58-71`). Only if none match are the semantic edges handed
to the router. This yields the design maxim: *logic where logic exists, intent where it doesn't* —
negation, counts, and thresholds are authored as `when` predicates (free, never misrouted), and
genuine judgment is left to the semantic tier. If a node has *only* deterministic edges and none
match, the run halts as **stuck** (a detectable authoring error), rather than guessing.

**The hybrid router.** For semantic edges, `HybridRouter` first computes the embedding decision and
its **margin** = (top-1 similarity − top-2 similarity). If `margin ≥ δ` (and an absolute-score
floor), it accepts the embedding pick; otherwise it issues a single LLM call ("pick the option that
best matches the outcome") and records that it escalated. δ is the primary knob trading LLM-call rate
against accuracy. A distinct **single** case arises when a node offers exactly one semantic edge:
there is no top-2 to form a margin, so the edge cannot be escalated on ambiguity — but it is still
*scored* (recorded `used=single`, its absolute similarity kept) rather than taken blindly, precisely
so a `human_floor` can suspend a barely-matching lone outcome as `needs_human` (`router.py:109`).

The full routing precedence at a node is therefore: **deterministic edges → the `HybridRouter`
(which escalates to the LLM when the top-1↔top-2 margin is below δ) → then, only if the router did
*not* escalate and the chosen embedding score is below an absolute `human_floor`, suspend as
`needs_human`.** `human_floor` is opt-in — a second `run()` parameter, default `None`
(`engine.py:77,174`) — so the "route to a person instead of guessing" behavior is off unless an author
asks for it; the margin knob δ and the confidence floor `human_floor` compose.

**The error tier.** Failure handling becomes a *first-class edge in the document* rather than a
`try/except` buried in a callback. The engine wraps every agent call; on a raise it walks the node's
`on error` edges in document order and takes the first whose optional `when` clause is satisfied over
an **error context** — `{error, error_type, error_message, error_count, visits}`, where `error_count`
is a **cumulative per-node lifetime raise counter that is *never reset on success*** (`engine.py:108-136`).
So `-> retry: on error when error_count < 3` bounds the *total* raises at that node over the run, not
consecutive ones — a node that fails, succeeds, then fails again still increments toward the cap. An
author can likewise write `-> escalate: on error when error_type == "TimeoutError"`. A bare `on error`
matches unconditionally. The safety property is **backward-compatible propagation**: if no error edge
matches, the engine re-raises the original exception, so a flow with no error edges behaves exactly as
it did before the tier existed (`engine.py:126-127`). Because the recovery topology is now data, it is
visible in the graph, analyzable, and drawable like any other edge.

**The event tier.** An `on event <name>` / `on timeout` edge does *not* fire during a normal step; it
arms an out-of-band suspension. When the worker returns a truthy `wait` field, the engine gathers the
node's event edges, records what the run is awaiting (`pending.awaiting`, an optional `timeout_s`),
sets `stopped="waiting"`, and returns — the engine is pure and performs no I/O, so it neither blocks
nor times out itself (`engine.py:152-160`). Resumption is external and durable: `checkpoint.resume(…,
event=<name>)` re-parses the read-only flow, matches the delivered event against the awaiting edges'
`event_name` (`__timeout__` for a timeout), and re-enters `run()` at that edge's target
(`checkpoint.py:184-199`). It refuses an event no edge awaits. Suspension and resume are thus expressed
*as data* — the checkpoint records what it awaits — rather than as an in-process blocking call. So the
`on timeout` tier is not merely documented: a **reference timer ships in the harness, not the engine**
(`scheduler.py`) — a dependency-free scanner that, on a tick, finds every `waiting` checkpoint whose
`timeout_s` has elapsed since it was saved and delivers `__timeout__` via `checkpoint.resume`, firing
the node's `on timeout` edge. The timer lives outside the pure engine by design, so the engine keeps
its no-I/O property while the tier still fires in a deployment. The event tier is the routing-layer
face of the durable-execution machinery of §3.4.

### 3.3 Determinism and safety

- **Determinism, and a routing lockfile (delivered).** Given fixed outcome fields, deterministic
  routing is a pure function; the embedding tier is deterministic for a fixed model; only the (rare)
  LLM escalation introduces stochasticity, and only for low-confidence transitions. The residual
  "fixed model" caveat — that embedding routing depends on the embedder's exact weights and numerics,
  which a model update or a different build can shift silently across the escalation threshold with
  *no diff anywhere in the flow* — is addressed by a **routing lockfile**. `prismpath lock <flow>` writes
  `<flow>.lock` committing, as data, each semantic condition's embedding (base64 little-endian
  float32), the embedder's name and a **fingerprint** (a fixed probe sentence and its embedding), the
  escalation δ, and a SHA-256 of the flow file (`lockfile.py`). At runtime a `LockedEmbeddingRouter`
  (`router.py:52-74`) looks each condition up in the committed dict instead of embedding it live —
  only the *outcome* is embedded locally, so the condition side is bit-for-bit fixed across machines
  and years. `verify_lock` recomputes the probe cosine and requires it ≥ `LOCK_COSINE_MIN = 0.9999`;
  on drift, `prismpath_LOCK_POLICY` (or an explicit arg) selects `refuse` (default — raise), `warn`, or
  `allow`, and `prismpath lock --check` runs the verification alone. We are explicit that `0.9999` is a
  *chosen* constant, not one measured across torch/ONNX/fp16 and CPU-vs-GPU builds, so a benign
  cross-platform numeric wobble could false-refuse; `policy=warn` is the mitigation for that case. This
  is a `package-lock.json` for control flow — possible *only because* a condition is data with a
  serializable numeric representation; you cannot lock the numerics of a Python router you re-run. It
  is the direct answer to the reproducibility critique of §2.1. The lockfile (over vectors) and
  `calibrate` (over the escalation threshold τ, §4.3) compose cleanly: the lock governs *which vectors*
  route while τ governs *when to escalate*, and neither constrains the other.
- **Decidable static analysis — "your flow compiles" (delivered).** Because the flow *is* the graph
  on disk, its topology is inspectable with **no model, no embeddings, no execution**. `analysis.py`
  runs a suite of decidable checks whose governing constraint is *soundness over completeness* —
  predicate reasoning is confined to the tiny decidable fragment the `when` language admits, so real
  flows get **no false positives** (a property pinned by a regression test). Four are **errors** (the
  flow will not run correctly) — `undefined-start`, `undefined-target`, `unsafe-predicate` (a purely
  *structural* AST check via `check_predicate`, catching e.g. an attribute access before it can crash
  at runtime), and `no-terminal` (no terminal node is reachable, so the run could only ever hit
  `max_steps`). The rest are advisory **warnings**: `unreachable-node`, `possible-stuck` (a
  deterministic-only node whose conditions may all miss — *suppressed* when a complementary `X`/`not X`
  pair is proven exhaustive by an operator-negation table), `shadowed-edge` (an always-true edge kills
  everything ordered after it), `shadowed-error-edge` (a bare `on error` shadows every later
  conditional `on error when …` edge — the same first-match hazard as a deterministic catch-all, but on
  the error tier), `unbounded-cycle` (**Tarjan SCC** detection of a loop with no edge
  referencing the `visits` counter — a bounded-by-`max_steps`-only loop), `always-false-edge` (a
  **single-variable interval-unsatisfiability** solver over the conjuncts), and `duplicate-condition` —
  **eleven checks in all**. All are wired into `prismpath validate` (decidable checks only — the compile
  gate, exits non-zero iff any error) and `prismpath lint` with `--json`; the exit code is the mechanical
  meaning of "does not compile." A broken-flow corpus (`tests/fixtures/broken/`) is the spec, one file
  per failure class, with a coverage test asserting the corpus exercises *every* code the analyzer can
  emit. This is the guarantee a runtime-assembled graph structurally cannot give (§2.1).
- **Polarity lint — the negation blind-spot, caught at authoring time (delivered).** One failure
  class needs the *embedder* and so lives in a separate advisory linter (`lint.py`), not the decidable
  pass: two sibling semantic conditions that are **topically near-identical but logically opposite** —
  "the tests pass" vs "the tests fail", "ready" vs "not ready". An embedding encodes topic, and a
  negation or antonym flip barely moves the vector, so a nearest-condition router misroutes these
  *confidently and systematically*. `polarity_mirror` fires only when **both** a similarity gate
  (cosine ≥ `POLARITY_SIM = 0.72`, deliberately *below* the plain-ambiguity 0.86 to catch the
  close-but-not-tied band) and a cheap, model-free lexical polarity signal (asymmetric negation
  markers, or a hardcoded antonym flip like pass/fail, valid/invalid) agree — two conjunctive gates
  tuned to stay silent on synonyms. Its prescribed fix restates the project thesis: have the worker
  emit a structured field and rewrite the branch as `when <field>` / `when not <field>`, demoting the
  polarity decision from the unreliable embedding tier into the decidable predicate fragment — at
  which point the static analyzer can even *prove* the resulting pair exhaustive. This directly targets
  the negation failure class the Q1 finding is about (§4.2).
- **Sandboxed predicates (a security property).** The `when` evaluator walks a Python AST but
  permits **only** names, constants, boolean ops, `not`, comparisons, and literal collections — **no
  calls, attribute access, or subscripts.** Unknown names resolve to `None` (falsy). Predicates
  therefore cannot execute arbitrary code, so authoring a flow (a Markdown file, potentially from an
  untrusted source) cannot achieve code execution through the condition language. This is a
  meaningful property for a system where non-engineers author control flow. The property is
  fuzz-tested (~8k adversarial + random inputs, zero executions, zero uncaught crashes), and is
  enforced at two layers: the static `check_predicate` above (wired into the static-analysis pass as
  the `unsafe-predicate` error), and a fail-safe evaluator in which a missing or type-mismatched
  operand yields an *unsatisfied* comparison rather than a runtime exception.

### 3.4 Durable execution, human-in-the-loop, and the flow-is-data toolchain

The engine (`engine.py`) is a **pure, ephemeral** transition function: its `RunResult.state` is
discarded when `run()` returns, and it never writes the flow `.md`. Durability is added *around* it
in two independent slices that both preserve one invariant — **the flow document is read-only source
and is never mutated** — which is precisely why durable state lives outside the document.

**Slice 0 — the JSON checkpoint** (`checkpoint.py`) makes a single run crash-resumable and
suspendable-for-a-human. `save_checkpoint` serializes a fixed schema (version, absolutized flow path,
a flow hash, the pending node, a `stopped` reason, the path, state, and a human-evidence packet)
through `_atomic_write`: write to a temp file, `flush` + `fsync`, then `os.replace` — atomic on POSIX,
so a crash mid-write leaves the previous valid checkpoint or the new one, never a torn file
(`checkpoint.py:49-58`). Checkpointing is best-effort and *self-disabling*: if state is not
JSON-serializable the per-step hook warns and continues, degrading durability without breaking the run.
The engine emits three *suspension* reasons, all durably captured before returning: `needs_human` — a
worker-requested handoff, or a semantic route whose score falls below an absolute-confidence
`human_floor` (a `run()` parameter, opt-in, default `None` — the "route to a person instead of
guessing" outcome, `engine.py:143-184`) — and
`waiting`, the event-tier suspension of §3.2. Resume re-parses the read-only flow and re-enters the
*same* pure `run()` in one of three ways: `choose=<edge>` (validated against the pending node's actual
edge targets) for a human decision, `event=<name>` for event delivery, or — on a bare crash-resume —
re-running the pending node itself, which makes crash-resume idempotent at node granularity for the
deterministic tier (`checkpoint.py:139-219`).

**Flow-hash binding.** Every checkpoint stores `"sha256:" + sha256(flow bytes)` at write time; on
resume `_check_flow_unchanged` recomputes and compares. If the flow was edited while the run was
suspended, `prismpath_RESUME_ON_FLOW_CHANGE` decides: `refuse` (default — raise, the audit-safe choice),
`warn`, or `allow` (`checkpoint.py:93-115`). This answers "which version of the flow governs a
continuation?" in code, not policy docs — a checkpoint predating flow-hashing carries an empty hash
and is not blocked, for backward compatibility. It is the direct fix to the *resume-against-an-edited-
flow* critique.

**Human queue.** Suspended `needs_human` checkpoints are surfaced to an operator: `list_queue` scans a
state directory for checkpoints whose `stopped == "needs_human"` and projects an evidence packet per
item (node, reason, `would_pick`, per-candidate scores); `record_decision` atomically writes a
validated `{choose, decided_by}` back, which a later `resume` with no explicit `choose` picks up
(`checkpoint.py:231-289`). The operator surface is Mission Control, whose HTTP layer calls exactly
these functions (`mission_control.py:704-706`, `782-788`), closing the loop: a run that declines to
guess suspends, a human picks the edge in a console, and `resume(choose=…)` applies it.

**Slice 1 — the commit-as-state Flow-Ledger** (`ledger.py`, `ledger_runner.py`) makes each *completed
unit* a durable, content-addressed proof rather than an asserted status. Ledgers live in a **separate
bare git repo** under `$XDG_STATE_HOME/prismpath/<flow>.git`, written entirely via git *plumbing*
(`hash-object` / `write-tree` / `commit-tree` / `update-ref`) with `GIT_DIR` pinned — so a project's
own repo (its refs, index, working tree) is never touched, and a destructive `SPRINT_FRESH` rmtree of
the project *cannot* delete the ledger, because it lives outside the tree (`ledger.py:10-21`). Each run
is one **orphan-then-linear** ref (`refs/prismpath/runs/<run-id>`); each **gate-green unit** is exactly
one commit whose git tree is the cumulative content-hashed state the gate blessed, carrying
machine-parseable RFC-822 trailers (`prismpath-Flow/-Run/-Unit/-Node/-Gate/-Output-Hash/…`). Git author
and committer dates are *pinned* constants (so the plumbing is deterministic), which means the commit
SHA is time-dependent *by design* once real green-time is added; that green-time is therefore recorded
in a dedicated **`prismpath-Wallclock`** trailer, and the proof is content-addressed via the
order-independent **`prismpath-Output-Hash`** (`sha256_files`), *not* the SHA. Tamper-evidence is scoped
to **accident**: any edit re-hashes the chain, so an incidental corruption is detected — but an
adversary with filesystem access can rewrite the whole chain, so we do not claim adversarial
integrity; anchoring the ref heads with **OpenTimestamps** is the honest adversarial upgrade (future
work). Every ref write is a **compare-and-swap** (`update-ref <new> <old>`); on a concurrent ref move
it **re-reads the tip and rebuilds on it, retrying rather than dropping the proof** (`ledger.py`).

**Done-ness is a projection, not a field.** `done_set()` folds the append-only log into `{unit →
latest green record}`, newest-wins, so re-running a unit supersedes the old proof — "the ledger's
replacement for the mutable status field: progress derived from the log, never a separate pointer"
(`ledger.py:221-229`). This is event sourcing: the log is the source of truth, and "which units are
done" is a *derived* quantity that cannot go stale or lie because there is no status field to lie. A
routing flow marks one node `@checkpoint(unit=<state-key>, proof=<state-key>, gate=<field>)` (parsed at
`parser.py:106`); `ledger_runner.run_ledgered_loop` seeds `state['_done_units']` from `done_set()` each
pass so already-proven items are skipped, and a stopped run restarts at the first item with no green
commit — no separate processed-list to keep in sync (`ledger_runner.py:63-105`). The same mechanism
backs *build* flows: behind `SPRINT_LEDGER=1`, a sprint whose `.kg.json` was wiped by `SPRINT_FRESH`
restarts at the first *unproven* node instead of rebuilding what git already attests
(`run_sprint.py:1135-1170`). Both layers are strictly off the critical path: any serialization or git
failure degrades to the existing `.lastgood`/`.kg.json` path — the ledger records progress, it never
drives or breaks a run.

**The flow-is-data toolchain.** Because the flow and its routing surface are data, an entire toolchain
becomes available that is ill-defined against a Python routing callback (the §2.1 asymmetry, delivered):

- **`prismpath test`** runs a sibling `<flow>.tests.md` — a GFM table of `(node, outcome, fields,
  expect)` rows — against the *real* deterministic and embedding tiers, **never the LLM**
  (`flow_test.py`). Crucially the runner calls the *same* `engine.first_deterministic` that `run()`
  uses, "so the two can never disagree on how a node routes," and it prefers a committed lockfile so
  tests are bit-for-bit reproducible. A PM writes scenarios in prose; CI asserts the routing; every
  past mis-route becomes a regression row. `--emit-labels` appends one label record per case in exactly
  the format `prismpath calibrate` consumes (§4.3), so authoring tests grows the calibration corpus for
  free.
- **`prismpath graph`** emits Mermaid directly from `graph.nodes`/`node.edges` — a solid arrow for a
  deterministic edge, a dashed arrow for a semantic one, a pill for a terminal — so the true routing
  topology (including the deterministic-vs-semantic spectrum) renders natively in a GitHub README or PR
  (`graph_export.py`). A code router's real graph is only knowable by running it.
- **OpenTelemetry export** (`otel.py`, library API) turns each node execution and each semantic routing
  *decision* (with `margin`, `top1`, `top2`, `escalated` as span attributes) into an OTel span-record —
  attributes that exist *only* because a branch is a scored decision over embedded data. The records are
  OTel-shaped dicts, testable with no SDK installed.
- **`prismpath label`** is a labeling workbench over the routelog: every semantic decision a run makes can
  be appended to JSONL (candidate edges, scores, margin, chosen), and the workbench turns those records
  into ground-truth labels — a closed loop from running to a calibrated threshold. You cannot "label"
  the execution of a Python `if`; there is no candidate set or score to adjudicate.

## 4. Evaluation

We ask two questions: **(Q1)** how good is embedding-only routing, and specifically *where does it
fail*? **(Q2)** does the hybrid escalation repair those failures while keeping LLM calls rare?

### 4.1 Setup

We label realistic agent outcomes with the edge they *should* take, over an **N=301** suite
(`benchmark/routing_bench.jsonl`, regenerated by `benchmark/reproduce.py`) spanning 8 flows and 11
semantic-decision nodes, stratified so the split is legible:

- **intent** (104 cases): the correct edge is an intent/topic distinction — where embeddings should do well.
- **abstraction** (98 cases): the edge hinges on a level-of-abstraction mismatch (e.g. "I'm blocked:
  change the public API or keep it?" → `triage`, phrased like implementation talk).
- **polarity** (99 cases): **logical-polarity** traps ("all tests pass" → `review` vs "three tests
  still fail" → `implement`) — topically near-identical, logically opposite.

All scored edges are semantic (no `when`), so every case exercises the embedder; deterministic edges
are excluded from scoring (exact by construction).

*Provenance (stated honestly).* The suite is **17 hand-crafted gold cases** (the original hard suite,
author-labeled) plus **284 generated cases** each passed through an **independent blind second-labeler**
— a separate pass given *only* the outcome and the node's edges, never the intended label. Only cases
where the two annotators agreed were kept, at an inter-annotator agreement of **0.979**; every kept
label was validated to be a real semantic edge of its node. Because both automated annotators are AI of
the same model family, that 0.979 is an AI-vs-AI *upper bound* on label quality — correlated errors go
uncaught — so we ran the gate a human, which earlier drafts filed as future work.

*Gate zero (now delivered).* A human maintainer **blind-relabeled all 301 cases** (the gold label
hidden; `prismpath annotate`) and agrees with the gold at **Cohen's κ = 0.961** ("almost perfect"), every
stratum ≥ 0.945 (intent 0.99, abstraction 0.95, polarity 0.95). As a second, cross-family check we ran
an **independent model** (Gemini, a different family) over the same blind sheet: human-vs-model
**κ = 0.682** ("substantial"). This is *not* a substitute for inter-human reliability — a second human
remains the release-gating measure — but it is informative twice over. First, of the 89 human-vs-model
disagreements, on **80 (90%) the human matches gold and the model is the lone dissenter**: the labels
are not contested, an independent model simply reads some of them differently. Second, that divergence
concentrates on the **polarity stratum (44% disagreement, vs 17% for intent)** — the negated/contrastive
outcomes ("I could *not* reproduce it", "staging is *not* unhealthy") — so a blind zero-shot model,
reading surface sentiment, reproduces exactly the polarity trap that motivates the deterministic and
hybrid tiers. The full write-up, including a disjunctive-edge finding the independent model surfaced (a
compound `A or B` condition it correctly read as two edges), is in `benchmark/gate_zero/`.

Embedder: `BAAI/bge-base-en-v1.5`, CPU, outcome-as-query / conditions-as-passages, cosine argmax.
Baseline: **lexical** token-overlap argmax.

### 4.2 Results — embedding vs lexical (Q1)

| stratum | n | Embedding | Lexical baseline |
|---|---|---|---|
| intent | 104 | **0.81** | 0.69 |
| abstraction | 98 | **0.74** | 0.48 |
| polarity | 99 | **0.52** | 0.42 |
| ALL | 301 | **0.69** | 0.53 |

(Source: `benchmark/reproduce.py`.) **The split is the finding, and it sharpens at scale:** with ~100
cases per stratum, embeddings are strong where the correct edge is an intent distinction (0.81),
**degrade on abstraction (0.74)**, and **collapse to near-chance on logical polarity (0.52)** —
barely above the lexical floor (0.42). Overall the embedder scores 0.69 vs 0.53 lexical. The polarity
result is the sharpest: a negation or antonym flip barely moves the embedding vector, so the router
misroutes the "tests pass" / "tests fail" family confidently and systematically. Three representative
failures, one per stratum:

1. *polarity* — *"Not a bug — the reported behavior is correct per the spec."* → **should** `close`;
   embed picks `implement` (0.65 vs 0.52) — the token "correct" pulls toward the fix action.
2. *abstraction* — *"I'm blocked: should we change the public API signature or keep it?"* → **should**
   `triage`; embed picks `implement` — a design question phrased as implementation.
3. *intent-near-tie* — *"I reproduced the crash; a null dereference in parse_config()."* → **should**
   `implement`; embed picks `close` — a near-tie (0.48 vs 0.43) with no lexical anchor.

Case (3) is precisely what a low-margin escalation targets (a near-tie); (1)–(2) are what a
deterministic field would resolve exactly if the worker emitted one. **This is the empirical
argument for the spectrum:** neither tier alone suffices; composed, they cover each other's gaps.

The **logical-polarity** subclass here — the "all tests pass" / "three tests fail" trap that motivates
the whole hard suite — is now caught *at authoring time*, before it ever reaches a benchmark: the
polarity lint of §3.3 flags a pair of sibling semantic conditions that are topically close but
logically opposite and prescribes demoting them to a `when <field>` / `when not <field>` deterministic
pair. In other words, the empirical failure mode this section characterizes has a shipped, decidable
authoring-time defense, closing the loop between the finding and the tooling.

### 4.3 Results — the hybrid frontier (Q2)

We ran the full three-arm evaluation with the **LLM arm served by the deployed local gemma4 endpoint —
measured first-party**, not reported. On the N=301 suite the bounding arms are **EMBED-only at 0.69
and zero LLM calls; LLM-only at 99.0%**, and the hybrid router sweeps between them. The canonical
δ=0.05 operating point is **83.7% accuracy while escalating 38.3% of decisions (383 LLM calls per
1000)** — embeddings resolve ~62% of transitions for free and the model repairs the low-confidence
residue. The escalation signal being the embedding decision's *own* confidence is what concentrates
LLM spend on the hard cases rather than paying it uniformly.

**PrismPath is a knob, not a point.** 83.7% is the δ=0.05 operating point (escalating 38.3% of decisions);
sweeping δ upward — or, better, *deriving* the threshold with the risk-controlled τ below — trades
toward ~99% accuracy at a higher call rate. Raising δ costs LLM calls monotonically while accuracy
climbs then plateaus; two nuances of that frontier shape are worth stating, because they refine the
thesis and neither depends on the exact operating point:

1. **The frontier was re-derived at full scale, and the N=17 "knee" did not survive.** An earlier
   draft, measured on the N=17 pilot, claimed a sharp knee near δ≈0.05; the re-derived frontier
   (N=300 decisions, one deterministic sweep over cached per-case embed margins and one LLM pass —
   `benchmark/hybrid_sweep.py`, which cross-checks by reproducing the head-to-head's operating
   point to within 0.3pt/0.3pp) is **smooth**: 0.69 at zero escalation, 0.79 at 25%, 0.84 at 38%
   (the δ=0.05 point), 0.92 at 67%, 0.99 at 93%. There is a mild flat spot just past δ=0.05
   (0.840→0.847 costs four escalation points for +0.7 accuracy) but no knee an operator could
   navigate by; δ is a genuine dial, and choosing its value belongs to the risk-controlled τ
   below, not to a folk constant.
2. **The margin has a blind spot for *confident* errors.** The last gap to full accuracy closes only at
   a very high LLM rate, because the residual errors are high-margin: the embedder is *confidently
   wrong* (e.g. the "correct per spec" case, top-1 0.65 vs top-2 0.52, margin ≈0.13) and so is not
   escalated until δ exceeds that margin. The margin reliably detects near-ties but not confident
   mistakes.

Observation (2) is itself an argument for the full spectrum rather than the hybrid router alone: the
one case that resists escalation (the "correct per spec" case) is exactly the kind
a **deterministic field** would resolve for free if the worker emitted one. No single tier is
sufficient; the deterministic and semantic tiers cover the hybrid router's blind spot.

**Prototype routing attacks the blind spot from the data side (delivered, measured).** Confident
errors arise because a condition's *authored wording* is a poor anchor for what outcomes routed
along it actually look like. `CentroidRouter` (`centroid.py`, `prismpath centroids`) replaces each
semantic condition's anchor with the **centroid of historical correct outcomes** for that edge,
shrunk toward the authored-condition vector when history is thin (a James-Stein-style blend with a
pseudo-count prior; with zero history it *is* the zero-shot router). On the N=301 suite under
**5-fold cross-validation with a near-duplicate leakage audit** (max train–test cosine 0.887; the
baseline reproduces `reproduce.py` bit-for-bit), centroids lift embedding-only routing from **0.69
to 0.83 overall (+0.14)** and — the targeted claim — from **0.52 to 0.75 (+0.23) on the polarity
stratum**, exactly the confidently-wrong class the margin cannot escalate. An ablation confirms the
gain is the learned prototypes, not the embedding-space change (passage-space alone *hurts*, −0.03),
and the result is robust across shrinkage priors. Because centroids are unit vectors like any other
committed condition embedding, they **pin in the routing lockfile** (`PrismPath lock --centroids
<labeled.jsonl>` commits the shrunk vectors), making the learned improvement bit-for-bit
reproducible rather than an artifact of a mutable corpus. The escalation tier thereby becomes a
*teacher*: every LLM repair and human label enriches the prototypes that let the cheap tier answer
the same question next time.

**Stacking the two levers — hybrid-over-centroids — is the recommended configuration.** The same
LLM-on-doubt escalation applied on top of the CentroidRouter's five-fold predictions (same fold
split as the CV above, same routing prompt as the head-to-head, one shared LLM pass;
`benchmark/hybrid_sweep.py`, artifact `hybrid_sweep.json`) dominates the zero-shot hybrid at every
call budget: **90.0% at 160 LLM calls per 1k** (δ=0.01 — better accuracy than the old headline at
2.4× fewer calls), **95.3% at 360/1k** (δ=0.03 — the old operating point's call budget, +11.6
accuracy points), **98.0% at 507/1k** (δ=0.05), converging to the LLM arms' 99.7% as δ grows. On
the polarity stratum — the near-chance failure that motivates the spectrum — the stack reaches
**0.92 at δ=0.03** (from 0.52 zero-shot, 0.75 centroids-alone). The two mechanisms are
complementary by construction: centroids repair the *confident* errors the margin cannot see
(observation 2), and escalation repairs the near-ties the centroids leave; together they recover
most of the accuracy gap to the always-call arms while preserving the cost model that
distinguishes the system.

**δ need not be a magic constant: risk-controlled calibration (delivered).** The δ swept above is
hand-chosen; it can instead be *derived* with a guarantee. The margin is a confidence score and
escalating to the LLM is *abstention*, so this is **risk-controlled selective classification** — a
single-threshold instance of the **Learn-Then-Test / Risk-Controlling-Prediction-Sets** family
(Angelopoulos, Bates, et al.), **not conformal prediction** (there is no nonconformity-score quantile
and no exchangeable prediction-set construction). Given a set of labeled routing decisions (the JSONL
that `prismpath test --emit-labels` and `prismpath label` both produce, §3.4), `prismpath calibrate --alpha α`
finds the smallest threshold **τ** such that the decisions the router does *not* escalate (margin ≥ τ)
are correct at rate ≥ 1−α — certified by a finite-sample **Wilson lower bound** (scipy-free), so the
guarantee holds *beyond* the calibration sample, not just on it (`calibrate.py:35-94`). `calibrate` now
reports the **effective N** at τ and the **width** of the guarantee (the point accuracy vs the certified
lower bound), so the strength of the certificate is inspectable rather than implied. A
`RiskControlledHybridRouter` (with `ConformalHybridRouter` kept as a back-compat alias) is then an
ordinary `HybridRouter` whose escalation margin *is* τ — identical runtime behavior, but the threshold
now carries the certificate — and if no threshold meets the bound it escalates *everything* and
**warns loudly** that τ=None has reverted routing to LLM-router economics (a fail-safe toward the LLM,
not a silent one; `calibrate.py:107-127`). This closes the loop opened by the routelog: authoring or
running produces labels; calibration turns them into a risk-controlled τ. Computing a Wilson bound over
routing decisions is only meaningful because each branch emits a scalar margin paired with a
ground-truth label — a dataset that does not exist for a Python `if`.

### 4.4 Head-to-head against orchestration frameworks (Q3)

The EMBED/LLM/hybrid arms above are PrismPath-internal. To situate the hybrid frontier against the tools
practitioners actually reach for, we implemented the `bugfix` flow in three external stacks and scored
all four on the N=301 labeled suite under identical conditions (same local gemma4 endpoint, same
routing prompt, δ=0.05, 2 repeats): a **LangGraph** `StateGraph` whose conditional edge issues an LLM
call (the idiomatic content-based branch), a **CrewAI** `Flow` whose `@router` method issues an LLM
call (CrewAI's only conditional-branch mechanism), and the naive **LLM-router** (one call per hop).

| metric | PrismPath (hybrid, δ=0.05) | LangGraph | LLM-router | CrewAI |
|---|---|---|---|---|
| routing accuracy | **83.7%** | 99.0% | 99.0% | 99.0% |
| LLM calls / 1k | **383** | 1000 | 1000 | 1000 |
| median latency | **205 ms** | 435 ms | 437 ms | 430 ms |
| p95 latency | **655 ms** | 445 ms | 453 ms | 442 ms |
| determinism | 100% | 100% | 100% | 100% |

**On a semantic branch, all three external stacks collapse to the same measured behavior** — one LLM
call, in imperative code, on every transition — and so tie *identically* at 99.0% accuracy, 1000
calls/1k, and ~435 ms/hop. This is not a weakness of their engineering but of the *position*: none
exposes a routing cost model, so none can decline the model call when a cheaper signal suffices. PrismPath
spends the model on only the 38.3% low-confidence residue (§4.3), reaching **2.6× fewer LLM calls
(383 vs 1000) and ~2× lower median latency (205 ms vs ~435 ms)**. The right way to read the call
reduction is **throughput**, not dollar cost: on a shared local endpoint the marginal cost of an
inference is essentially electricity, so the win is that ~2.6× fewer generations means ~2.6× more
concurrent streams per box (GPU-seconds), not a cheaper invoice.

**We name the tradeoff plainly, because it is a real loss.** PrismPath's latency is **bimodal**: the
median hop (205 ms) is embed-only and fast, but an *escalated* hop pays the embedding *then* the LLM
(≈205 + 450 ms), which is *slower* than a pure LLM hop (~435 ms). So PrismPath's **p95 is 655 ms vs the
external arms' ~445 ms** — PrismPath **wins on median and throughput but loses on the tail**. A user under
a hard p95 SLA should route straight to the LLM; PrismPath's advantage is average-case throughput, not
worst-case latency. Two further points strengthen the honest reading. First, the LLM arm fell from
100% on the earlier small pilot suite to 99.0% at N=301, and would fall further at larger N — so the
accuracy gap to PrismPath narrows as the benchmark grows. Second, **83.7% is an operating point, not a
ceiling**: because PrismPath exposes δ (and the risk-controlled τ of §4.3), the same system trades toward
~99% at a higher call rate; the other three arms have no such dial. Determinism did not separate the
arms on this suite/model (gemma4 was deterministic across the 2 repeats at temperature 0.0, the config
we measured; it is re-runnable at other temperatures via `python -m PrismPath.comparisons.run_comparison
--temperature 0.7`); the structural guarantee — embedding hops deterministic by construction and, with
a lockfile (§3.3), bit-for-bit across machines — is real but not exercised into a measured gap here,
and we do not claim one. The distinguishing tax of the external stacks is therefore structural rather
than accuracy: control flow expressed as code (a routing function, a `@router` method) rather than as a
diffable per-edge condition a domain expert can read.

*Threat to validity.* The LangGraph and CrewAI baselines were authored by an PrismPath author; a more
idiomatic implementation avoiding a per-hop LLM call would tighten the comparison. The reproducer and
both reference implementations are released in `comparisons/`.

---

## 5. The control plane (systems contribution)

Above the kernel, PrismPath adds an **agent-agnostic control plane** for spec-driven feature sprints: a
fixed loop in which *whatever* chooses the next unit of work hands it to an executor that edits the
real source tree, and **machine-enforced gates decide "done"** — compiles, type-checks, builds, tests,
and is wired-in and reachable. *How* the next unit is chosen is a **pluggable mode**, and the loop, the
gates, the durable proofs (§3.4), and the human-in-the-loop escalation are identical across all of
them. The default and what PrismPath was built for is a **deterministic** order — a knowledge-graph walk
over an authored spec whose `##` are requirements, or a flat ordered spec list (`run_sprint.py`
selects the mode by env config, `kg_next`/`spec_next`/`council_next` all returning the *same*
`{done, target, instruction}` contract). The **exception, not the default**, is an optional
**"council"** expansion strategy that arose from a Roblox game-development use case, where the goal was
AI-driven *breadth* across a game's many aspects: role-lensed agents propose net-new subsystems and
vote, steered by a seeded "dice" roll toward under-explored areas — an open, dice-driven "what should
this grow into?" loop. Council is the least deterministic mode and is load-bearing for *none* of the
control-plane guarantees; the systems contribution below is the control plane and its durable proofs,
not the council. The findings that generalize concern that constant machinery:

- **Gates as the machine-enforced definition of done.** A build is not "done" until it compiles,
  type-checks, builds, passes tests, *and is wired into a composition root and reachable*. The
  operating rule — **"never write a completeness claim a gate doesn't enforce"** — converts silent
  drift (dead modules, unreachable surfaces, stale contracts) from a thing you must remember to check
  into an invariant a deterministic gate enforces.
- **Commit-as-state: a git Flow-Ledger of gate-green proofs.** The gate decides "done"; the
  commit-as-state Flow-Ledger (§3.4) makes that decision *durable and content-addressed* — this is
  what turns "gates as definition of done" from an operating rule into a persisted, inspectable
  proof-chain a human can `git show` and diff, strictly off the critical path.
- **Specification drift is a cheap-layer problem.** Fanning out one agent per module-spec is fast but
  each independently invents names for shared cross-references (observed: ~15 hard type/name
  mismatches across 10 specs — each a would-be build failure). The mitigation — author a **shared
  glossary** of canonical types/signatures *first*, feed it to every spec agent, and reconcile with a
  consistency pass — catches drift at the **Markdown** layer (≈ free to fix) instead of as broken
  code (a stuck swarm). A complementary finding: tasking a small (7B) model as a conformance *judge*
  requires a tightly-scoped persona (kill the tool instinct; audit only contract-surface names;
  few-shot both a flag and an ignore; deterministic post-filter), consistent with small models
  excelling at *narrow conformance-to-an-explicit-contract*.
- **Decision memoization dominates routing cost, and the reuse is safe.** The spectrum makes
  *transitions* cheap, but in a security-triage flow the binding cost is one *adjudication node* (an
  LLM classification) whose inputs recur near-identically. A **prefilter cache** — store each
  adjudicated (document → verdict) pair as a normalized embedding; reuse a prior verdict when a new
  document matches at cosine ≥ 0.97 **and** the stored verdict's confidence ≥ 0.8; otherwise
  adjudicate and *learn* the fresh verdict — auto-resolved **58.3% of alerts (233 hits over 400)** in a
  streaming, self-learning **replay over 400 real alerts sampled from the author's own Wazuh instance**
  (not a live SOC deployment), a **~2.4×** effective capacity gain before the LLM tier is touched.
  The obvious objection is that a wrong reuse *compounds* (a bad verdict re-seeds the cache), so we
  measured it directly: for every one of the 233 hits we also ran the LLM **fresh** — the same
  prompt+model as production — and compared the reused action against the fresh one. Result: **97%
  reuse agreement (226/233), and zero unsafe downgrades** — the cache never reused a watch/ignore
  verdict where the fresh LLM would `contain` (the exact compounding risk). All 7 disagreements are
  `contain → ignore`: the cache *over-blocks*, the safe direction, and containment drafts are
  human-reviewed anyway. This measures agreement with a **fresh LLM oracle, not human ground truth**
  (which would need a human audit and is noted as such). Two design points carry: the gate needs
  *both* thresholds (similarity asks "is this the same situation?"; stored confidence asks "was the
  prior verdict trustworthy?"), and the rate is distribution-dependent — repetitive alert streams
  cache well; novelty-heavy streams will not —
  so cold-start and steady-state rates must be reported separately. The pattern additionally
  presumes the verdict is a function of the embedded document alone: the triage flow embeds the
  *stable* alert fields and deliberately excludes the volatile 24-hour context, trading
  context-sensitivity for cache stability — a scoping decision the author must make explicitly.
  This is the cascade idea applied one level *below* the routing spectrum — memoize the worker,
  not just the transition — and it is applicable to triage-shaped flows, not workflows in general.
  The mechanism is now factored as a generic, reusable `PrefilterCache` with a single pluggable
  `embed_fn(list[str]) -> unit-normalized [n,d]` swap point (`prefilter.py`), so any modality encoder
  (a network-flow encoder, not only a text embedder) can feed the same two-threshold gate — the
  "memoize the expensive node" pattern generalized beyond SOC text.

These are engineering findings, not theorems, but they are the kind of reproducible operating
knowledge that a systems paper should record.

---

## 6. Limitations and threats to validity

We are deliberately explicit here.

- **Scale and annotation.** The routing benchmark is N=301 (17 hand-crafted gold cases + 284
  generated cases gated by an independent blind second-labeler at 0.979 inter-annotator agreement);
  absolute accuracies should be read as *characterizing behavior*, not as leaderboard numbers. The
  0.979 is an AI-vs-AI upper bound (both automated annotators share a model family). **Gate zero is now
  delivered** (§4): a human **blind-relabeled all 301 cases** at **κ = 0.961 vs gold** (every stratum
  ≥ 0.945), and an independent cross-family model agrees at **κ = 0.682** ("substantial") — with 90% of
  its disagreements being cases where the human matches gold and the model is the lone dissenter,
  clustered on the polarity stratum. A second *human* annotator (κ against the maintainer) remains the
  strongest, still-open reliability measure; what we have is one human vs. gold plus an independent
  cross-family check.
- **Hybrid arm now first-party.** §4.3/§4.4 were measured on the deployed Gemma endpoint (not merely
  reported) on the N=301 suite; a larger, *human*-annotated δ-sweep across more flows and embedders is
  the obvious next step, and would test whether the frontier shape and the confident-error blind spot
  generalize.
- **Single embedder / single language.** Results use one English `bge` model; cross-embedder and
  multilingual behavior are unmeasured.
- **Label subjectivity.** "The edge it should take" is a human judgment; some cases are genuinely
  ambiguous (which is *itself* an argument for a hybrid that expresses uncertainty).
- **Domain coverage.** Flows are software-process / support / release / SOC-triage; generalization to
  very different process families is untested.
- **Control-plane findings are anecdotal-empirical** (one substantial build), offered as operating
  lessons, not controlled experiments.
- **Both critiques now closed.** *(closed) Field-only routing* — the
  prompt-injection concern (routing influenced by raw upstream worker prose, attacker-influenced in
  adversarial settings) is now addressed as delivered, decidable machinery: a node declares its
  emitted fields (`@emits`), may be marked `@field_only`, and the static analyzer enforces the
  provenance boundary (`undeclared-field`, `field-only-violation`, `emits-type-mismatch`) — a
  `@field_only` node with a semantic edge (which routes on raw text) is a compile-time **error**.
  See §3.4 and §7; the residual honest caveat is adoption, not existence: flows must opt in per
  node, and unannotated nodes retain the old exposure. *(closed) Bounded state growth* — a flow may
  declare `@state_bound(transcript=N)`: the engine sliding-windows the transcript on append and the
  re-seeded path/step history on resume, so the persisted checkpoint payload stays **flat across
  unlimited resumes** (measured in the test suite: strictly-growing without the bound, constant with
  it). Drops are counted deterministically in `_state_dropped` rather than summarized by a model —
  the engine stays pure — and the window cannot change a routing decision by construction:
  predicates read worker fields plus the per-node `visits`/`error_count` counters, which are
  separate ints and never trimmed (`_outcomes` is last-write-per-node, already bounded by node
  count). The residual honest caveats: the bound is opt-in per flow (the default remains unbounded),
  and the dropped history is gone — a *summarized* tail, if ever wanted, belongs in an impure
  harness, not the engine.
- **Residual limits of the delivered tooling.** Risk-controlled calibration (§4.3) needs a *labeled*
  set of routing decisions to derive τ, and its guarantee is only as good as that set's coverage
  (and, per §4.1, its labels are AI-annotated); the routing
  lockfile (§3.3) assumes a *stable embedder identity* — its probe-cosine fingerprint detects drift but
  cannot itself re-derive a correct lock, so a deliberate embedder change requires a re-`lock`.

---

## 7. Conclusion and future work

PrismPath reframes LLM-agent orchestration around a simple observation: **routing conditions come in a
few flavors — at core logic and intent, plus failure and external signal — and the cheapest sufficient
mechanism should resolve each**, with a rare LLM call for the residue. The condition string is both the
edge and the selector of its mechanism, which is what lets one git-diffable surface syntax carry all
four tiers (§3.2). Making the graph a human-authored Markdown file collapses the gap between the
process a domain expert owns and the artifact an engine runs — and, more deeply, it makes the control
flow *data* rather than code, which is the structural reason a lockfile, a static analyzer, a Mermaid
render, decision-spans, Markdown tests, and a LangGraph importer are even well-defined (§2.1). The
measured split — embeddings strong on intent (0.81) but collapsing to near-chance on logical polarity
(0.52), 0.69 overall vs 0.53 lexical — is the empirical case for the spectrum, and the measured
head-to-head (§4.4) is the case for the position: 83.7% accuracy at 2.6× fewer LLM calls and ~2× lower
median latency than the frameworks that cannot decline a call — a throughput win we do not oversell,
since it is paid for with a higher p95 tail on the escalated hops.

Several items once listed as future work now ship, and are treated above as delivered contributions:
**calibrated escalation thresholds** (risk-controlled calibration deriving τ with a finite-sample Wilson
guarantee, §4.3, replacing a hand-tuned global δ); **prototype routing** (per-condition centroids of
historical correct outcomes, +0.14 overall / +0.23 on the polarity stratum under leakage-audited
cross-validation, pinnable in the lockfile, §4.3); **static analysis over the graph** (a decidable
check suite — reachability, terminal reachability, exhaustiveness via complementary-pair detection,
shadowing, Tarjan cycle loop-caps, interval-unsatisfiability — with zero false positives and a
broken-flow corpus, §3.3); **durable, resumable execution with a git proof-ledger** (§3.4);
**field-only routing** enforced as decidable provenance lints (`@emits`/`@field_only`), which also
delimits an **ML-free portable subset**: flows whose reachable edges are all decidable run on a
dependency-free JavaScript port of the kernel whose routing parity with the Python engine is enforced
by a cross-language conformance suite rather than asserted; **fan-out and sub-flow composition** as
event edges plus a declarative `@spawn` annotation — the engine stays pure (it only records the spawn
spec), an out-of-band harness spawns durable child runs under deterministic ids and delivers the join
event, static analysis crosses the flow boundary (a missing join edge is a compile-time deadlock
error), and the lockfile pins the whole composition tree; **continuous reuse-error monitoring** for the
decision-memoization cache (shadow-sampling a fraction of cache hits through the live adjudicator,
with cumulative *and* windowed drift bounds that quarantine a drifting entry); and **applying the
spectrum to a security-triage flow** (the streaming replay over the author's own Wazuh instance where
the decision-memoization and reuse-accuracy findings of §5 were measured — a flow whose routing, we
note, falls entirely in the portable subset: the LLM lives in the workers, not the control flow).
What remains genuinely open: (i) a larger, *human*-annotated routing benchmark across more flows and
embedders, to test whether the frontier shape and the confident-error blind spot generalize; and (ii)
confidence-aware terminal behavior beyond the current `human_floor` suspension (ask-a-human as an even
more first-class low-confidence outcome). The former item (iii), a **bound on persisted state**, is
now delivered as `@state_bound` — a declared sliding window over the transcript and re-seeded history
with deterministic drop accounting (§6's critique (2), closed).

## Acknowledgments

Design review and adversarial critique of this work were conducted with an AI assistant (Claude),
consistent with venue AI-disclosure policy.

*Artifacts (parser, safe predicate evaluator, four-tier router, embedder, checkpoint + Flow-Ledger,
static analyzer, lockfile, calibration, the data-plane tools, evaluation harnesses, and the
`comparisons/` head-to-head, plus example flows) are self-contained and small enough to audit
end-to-end.*
