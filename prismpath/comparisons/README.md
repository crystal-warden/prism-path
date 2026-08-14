# Head-to-head: PrismPath vs LangGraph vs LLM-router vs CrewAI

*Area-5. This directory holds the same flow implemented across four orchestrators; each a **real,
runnable** implementation; so the comparison is reproducible, not rhetorical. The measured numbers
(routing accuracy, calls/1k, latency) are produced by `run_comparison.py` against the labeled suite
and recorded in `results.json`; the **structural** comparison below stands on its own.*

## The four baselines

| baseline | what it is | where the control flow lives |
|---|---|---|
| **PrismPath** | one Markdown file is the graph; routing is a cost spectrum | **the document**: `-> target: condition` edges a PM can read |
| **LangGraph** | `StateGraph`; nodes are functions, edges are routing functions | Python routing functions over a typed state object |
| **LLM-router** | every transition is one LLM call ("given the outcome, which edge?") | the model, at runtime, every hop |
| **CrewAI** | agents + tasks (Crews), or event-driven `@router` methods (Flows) | a fixed sequence (Crews) or Python `@router` methods (Flows) |

## Why CrewAI is the fourth baseline (the critic was right to ask for it)

CrewAI is the most popular "structured" alternative, so it's the comparison practitioners ask for
first. It has two paradigms, and **neither occupies PrismPath's position**:

- **Crews (`Process.sequential`)**: rigid turn-taking, task 1 → 2 → 3. There is *no conditional
  branching on a semantic outcome at all*. You cannot express "if it's a duplicate, close; else
  implement" without leaving the model. Auditable, but it can only encode a straight line.
- **Crews (`Process.hierarchical`)**: a manager LLM decides delegation. Flexible, but the routing
  is a non-deterministic, unauditable model call every time; the LLM-router's weakness, wearing a
  role.
- **Flows (`@start` / `@listen` / `@router`)**: the *fairer* comparison, because Flows **can**
  branch. But the branch logic is a Python `@router` method (see [`bugfix_crewai.py`](bugfix_crewai.py)).
  That's LangGraph's problem restated: control flow is **code, not a readable artifact**; there are
  no per-edge conditions a non-engineer can read or diff; there is no deterministic-vs-semantic tier
  distinction; and there is no routing-cost model.

So on any flow with conditional branching, CrewAI Crews lose by not expressing it, and CrewAI Flows
lose by expressing it in Python; the same place LangGraph keeps it.

## The axes

**Structural (decidable today; no runs needed):**

| capability | PrismPath | LangGraph | LLM-router | CrewAI |
|---|---|---|---|---|
| control flow is a readable/diffable artifact | ✅ the .md | ❌ Python | ❌ prompt | ❌ Python / a fixed list |
| per-edge conditions authored, not coded | ✅ | ❌ | ❌ | ❌ |
| deterministic tier (free, exact logic) | ✅ `when` | ✅ code | ❌ | partial (fixed order) |
| semantic tier (route on NL outcome) | ✅ embed | via an LLM call | ✅ always | via a manager LLM |
| **routing cost model** (embed → LLM-on-doubt) | ✅ measured | ❌ | ❌ (LLM every hop) | ❌ |
| **static analysis** ("your flow compiles") | ✅ `validate` | ❌ Turing-complete | ❌ | ❌ |
| **reproducible routing** across installs | ✅ (lockfile) | n/a | ❌ | n/a |
| durable resume + human-in-the-loop | ✅ checkpoint/queue | via extensions | ❌ | partial |
| fan-out / sub-flow composition, join authored in the artifact | ✅ `@spawn` + `on event all_done/any/quorum` | ❌ code | n/a | ❌ code |
| parallel execution (wall clock concurrency) | ❌ reference harness is sequential | ✅ | n/a | ✅ |
| connector & memory ecosystem | ❌ | ✅ | n/a | ✅ |

**Measured**: all four scored on the same labeled suite (`prismpath/benchmark/routing_bench.jsonl`, **N=301**),
same local model (gemma4, OpenAI-compatible endpoint), same routing prompt, δ=0.05, 2 repeats.
Regenerate with `python -m prismpath.comparisons.run_comparison` (see "Running it" below). Numbers below
are a representative run; latency is machine-specific, the ratios are the point.

| metric | PrismPath | LangGraph | LLM-router | CrewAI |
|---|---|---|---|---|
| routing accuracy | **83.7%** | 99.0% | 99.0% | 99.0% |
| LLM calls / 1k transitions | **383** | 1000 | 1000 | 1000 |
| median latency / transition | **205 ms** | 435 ms | 437 ms | 430 ms |
| p95 latency / transition | **655 ms** | 445 ms | 453 ms | 442 ms |
| determinism (identical across repeats) | 100% | 100% | 100% | 100% |

**Read this honestly; PrismPath both wins and loses here, and the losses are the point:**

- **The throughput win (the headline; framed correctly).** PrismPath escalates to the LLM on only
  **38%** of transitions (the low-margin ones), routing the suite at **383 model calls per 1,000 vs
  1,000 for every other baseline; 2.6× fewer**. On *local* inference the per-call dollar cost is
  ~electricity, so the honest framing is **throughput / GPU-seconds**: a call is capacity a shared
  endpoint can't spend elsewhere, so 2.6× fewer calls ≈ **2.6× more concurrent streams per box**.
  LangGraph, CrewAI-Flows, and the naive LLM-router all collapse to the same number: on a semantic
  branch each makes exactly one LLM call, in Python, every time; they tie identically at 99.0% / 1000.
- **The accuracy loss (stated plainly); and it's a knob, not a verdict; the knob is now measured.**
  The LLM baselines score 99.0%; PrismPath scores **83.7%** at δ=0.05 *with zero-shot embeddings*. The
  gap is the embedding tier's *confident errors*; the ~62% of hops it keeps are only ~75% right on
  this hard suite (kept-hop polarity collapses to 0.52), and those it's confident-but-wrong about are
  never escalated. But 83.7% is **one operating point on a measured frontier**
  (`prismpath/benchmark/hybrid_sweep.py`): the δ sweep is smooth (no knee), and swapping the zero-shot embedder
  for the **centroid router** (a few labeled examples per node, scored 5-fold cross-validated) moves
  the entire frontier; **90.0% at 160 calls/1k (δ=0.01), 95.3% at 360 (δ=0.03), 98.0% at 507
  (δ=0.05)**, with polarity recovering from 0.52 to 0.92. At δ=0.03 that is *more accurate than this
  table's arm at fewer calls*. The other three have **no such dial**: they ship pinned to one point.
  (The sweep's zero-shot arm reproduces this table's number; 84.0% @ 380 vs 83.7% @ 383; so the two
  artifacts cross-check.)
- **The tail-latency loss (the p95 tells the truth the median hides).** PrismPath's median hop is
  embed-only (205 ms), but its **p95 is 655 ms** (*higher than the LLM arms' ~445 ms*) because the
  latency is **bimodal**: an escalated hop pays the embedding *and then* the LLM (~205 + ~450), which
  is slower than a pure LLM hop. So PrismPath **wins on median + throughput and loses on the tail**; a
  hard-p95-SLA user (every decision must clear 500 ms) should route straight to the LLM. We report the
  p95 precisely so the tradeoff can't hide in the median.
- **The LLM arm fell below 100% at scale** (100% on the earlier tiny pilot → 99.0% at N=301), and
  would fall further at larger N; which narrows the gap and strengthens PrismPath's relative position.
  Determinism didn't separate the arms (all 100%, even at `--temperature 0.7`); PrismPath's confident
  hops are deterministic *by construction* and, with a lockfile, bit-for-bit across machines, but this
  suite/model didn't turn that into a measured gap and we don't claim one.

## The change test

The number a practitioner actually feels: apply one realistic business-rule change and measure the
diff. **"Billing disputes over $500 now route to a human."**

- **PrismPath**: add one edge to the flow file:
  `-> human_review: when dispute and amount > 500`. A one-line diff in a document a PM can read and
  approve. `validate` confirms it still compiles.
- **LangGraph**: edit the routing function: add a branch, ensure `amount` is on the state object,
  re-test the Python. An engineering change.
- **LLM-router** (reword the routing prompt and hope the model honors the threshold) the exact
  place LLMs are unreliable (a number comparison delegated to prose).
- **CrewAI**: add a `@router` branch (Flows) or restructure the task sequence (Crews); Python
  again, and for Crews you may not be able to express the conditional at all.

The measured version reports diff size, files touched, and whether the diff is readable by a
non-engineer; that last column is the thesis.

## Where PrismPath honestly loses

Stated plainly, because the table's credibility comes from the losses: PrismPath has **no parallel
executor**: fan-out/join *semantics* are first-class (`@spawn`, `all_done`/`any`/`quorum` joins,
durable deterministic-id children), but the reference harness steps children **sequentially**;
wall clock concurrency (leasing, at-least-once delivery) is deliberately deferred to a production
scheduler, so LangGraph and CrewAI execute in parallel today and PrismPath does not. It also has **no
connector/memory ecosystem** and **no enterprise deployment machinery** (RBAC, multi-tenancy);
LangGraph and CrewAI win outright there. PrismPath's claim
is narrower and, on that narrow claim, unmatched: *the auditable, testable, reproducible control-flow
layer (readable by the person who owns the process) run standalone or inside the platform you
already have.*

## The adjacent layer · observability & eval platforms (LangSmith, Langfuse, Phoenix, Weave)

The second question after "why not LangGraph?" is usually "isn't this just LangSmith for
Markdown?" It isn't; the relationship has three distinct parts:

- **Deleted by construction.** A meaningful fraction of the trace/eval category exists *because*
  code-shaped control flow is opaque: tracing reconstructs a topology you can't read; dashboards
  catch drift nothing else will. Here the topology is static data before any run (`prismpath graph`,
  `validate`); a routing decision **explains itself**: margin, top-1/top-2, escalated-or-not are
  attributes of the decision, not forensics; versioning is git; drift is the lockfile's loud
  fingerprint check, not a chart you have to watch.
- **Genuine overlap, different in kind.** Their evals judge *outputs* (inherently fuzzy,
  LLM-as-judge); `prismpath test` asserts *routing*; exact, model-free, milliseconds, CI-native.
  Their annotation queues feed evaluation dashboards; `prismpath label`'s labels feed `calibrate` and
  become τ, a runtime control knob. Their loop terminates in a dashboard; this one terminates in
  the router.
- **Compose, don't collide.** PrismPath emits OpenTelemetry decision-spans into the
  Grafana/Jaeger/Datadog you already run rather than shipping a new pane of glass; and a worker
  that is internally a LangChain chain can keep LangSmith pointed at its *interior* while PrismPath's
  spans cover the decisions *between* workers. Different altitudes. What that layer does beyond
  this scope; output-quality evals at scale, token/cost accounting, cohort analytics, prompt
  A/B, multi tenant RBAC; is theirs, and out of scope here by design.

## Running it

One command, scored against the same labeled outcomes (`prismpath/benchmark/routing_bench.jsonl`) so accuracy
is measured, not vibed:

```bash
# dedicated venv keeps the heavy framework installs isolated (bge model is cached on first use)
python -m venv prismpath/comparisons/.venv
prismpath/comparisons/.venv/bin/pip install -r prismpath/comparisons/requirements.txt   # + `pip install litellm` for CrewAI

# point at any OpenAI-compatible endpoint (defaults to the local gemma4 server on :8888)
export GEMMA_BASE=http://localhost:8888/v1 GEMMA_MODEL=gemma4
PYTHONPATH=. prismpath/comparisons/.venv/bin/python -m prismpath.comparisons.run_comparison --repeats 3
```

Writes `prismpath/comparisons/results.json` + `results_table.md` and prints the table above. Every baseline is
a **real** implementation of its stack; PrismPath's `HybridRouter`, a live LangGraph `StateGraph` whose
conditional edge is an LLM call, a CrewAI `Flow` whose `@router` is an LLM call, and the naive
one-call-per-hop LLM-router; all consulting the same model with the same prompt, so the differences
are the *routing strategy's*, not a model or prompt advantage. Baselines whose framework isn't
installed are skipped with a note, so the PrismPath / LLM-router numbers regenerate on a bare install.
Flags: `--margin` (PrismPath's δ), `--temperature`, `--only prismpath,llm_router`.

**Threats to validity (invited PRs).** The LangGraph and CrewAI baselines were written by a PrismPath
author; a more idiomatic implementation of either, especially one that avoids a per hop LLM call,
would strengthen the comparison, and a PR improving them is genuinely welcome. The suite is N=301
across 7 flows (built to stress semantic routing, where embeddings degrade), of which 17 are
hand-crafted gold and 284 are generated cases gated by an independent blind second-labeler (agreement
0.979, an AI-vs-AI upper bound). **Gate zero is delivered**: a human maintainer blind-relabeled all
301 cases (gold hidden) at **Cohen's κ = 0.961** vs gold (every stratum ≥ 0.945), and an independent
cross family model agrees with the human at κ = 0.682; see `prismpath/benchmark/gate_zero/findings.md`; a
second *human* annotator remains the venue-gating measure. Latency is single-machine, single local
endpoint; the reported ratios travel, the millisecond values do not.
