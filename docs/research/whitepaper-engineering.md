# PrismPath · A Technical White Paper

**One Markdown file is the workflow. The engine, not the author, decides how each transition is
routed; deterministic logic where it can, embeddings where it must, and a rare LLM call only when
it's genuinely unsure. And because the control flow is *data*, not code, you can lock it, test it,
draw it, trace it, resume it, and commit its progress to git.**

*Crystal Warden Labs · 2026 · engineering audience*

---

## Executive summary

*Supporting evidence for every number below: `docs/research/supporting-evidence.md` (results ledger + provenance, negative results included). The ET-BERT/SOC hardening findings it cites; silent-failure war-story, no-sudo capture, GPU-batch economics, per tenant suppression, the flywheel; were measured in a separate first party lab repository; see that ledger's provenance note.*

PrismPath is a control plane for LLM-agent workflows built on one idea: **the workflow graph should be a
human-authored artifact, and routing should be a spectrum, not a single mechanism.** A flow is a
Markdown file; `## headings` are nodes, the prose is the instruction handed to an agent, and
`-> target: condition` lines are edges. At runtime the engine resolves each transition with the
*cheapest sufficient* mechanism: a **deterministic predicate** for conditions that are logic
(`when tests_pass`), **sentence-embedding similarity** for conditions that are intent (`the customer
is disputing a charge`), and a **one-shot LLM only when the embedding decision is low-confidence.**

The payoff: workflows a PM or SOC lead can read and edit; near-zero routing cost in the common case;
and (because logic is handled by exact predicates rather than a language model) none of the
negation/threshold errors that plague LLM-only routers. The routing spectrum is now **four tiers**:
deterministic `when`, semantic natural language, an **error** tier (`-> t: on error`) that turns
failure-handling into a visible edge, and an **event** tier (`-> t: on event <name>` / `on timeout`)
that lets a run suspend on an external signal.

The deeper thesis is that **PrismPath's control flow is *data*, not code.** A flow is an inert,
inspectable Markdown document; every edge condition is a string. That one asymmetry is the generator
of an entire toolchain you cannot cleanly build against a Python routing callback: a **routing
lockfile** (`prismpath lock`) that pins the embedding numerics for bit for bit reproducible routing,
**flow tests in Markdown** (`prismpath test`) run without an LLM, a **static analyzer** that answers
"does this flow compile?", a native **Mermaid render** (`prismpath graph`), **OpenTelemetry**
decision spans, a one-way **LangGraph importer** (`prismpath import`), and a **risk controlled
calibrator** (`prismpath calibrate`) that *derives* the escalation threshold with a finite sample
(Wilson) lower-bound risk guarantee instead of hand-tuning it. Two later additions extend the same
asymmetry: a **bounded model checker** (`prismpath verify`) that proves a node unreachable under a
stated assumption (decidable because the deterministic tier is a finite match action table) and a
**language server** (`prismpath lsp`) that puts the analyzer's findings on the authoring line as you
type.

Two more layers make runs durable. A **JSON checkpoint** makes a single run crash-resumable and
suspendable for a human or an event; atomic sidecar writes, five stop reasons, and a **flow-hash
binding** that refuses to resume against a `.md` edited mid-suspension. A **git Flow-Ledger** makes
each gate green unit a content addressed **proof-commit** on an orphan ref in a side repo, so
done-ness is a *projection over `git log`*, not an asserted status field.

Above the kernel sits a spec driven build methodology whose central discovery is **"gates are the
definition of done"**: nothing is complete until a machine confirms it compiles, is wired, and is
reachable.

This paper covers the format, the agent contract, the four-tier routing spectrum, durable execution
and the Flow-Ledger, the data-plane toolchain, the runtime, the control plane, and the operational
lessons learned running it against a real local-model agent swarm.

---

## 1. Why not just LangGraph? Why not just an LLM router?

Two common approaches, two structural taxes.

**Graph-in-code (LangGraph `StateGraph` and friends).** Nodes are functions; edges are Python
routing functions over a typed state object. Deterministic and free; but the control flow *lives in
code*. The person who owns the process (analyst, PM, SOC lead) can't read it, can't author it, and
the graph isn't a single reviewable artifact; it's smeared across function definitions and
decorators. Every process change is an engineering change.

**Route-by-LLM.** Delegate each branch to a model: "given the outcome, which edge?" Maximally
flexible, no branch code; but you pay a model call on *every* transition, you lose determinism, and
you inherit the LLM's worst failure mode exactly where it's least necessary: **logic.** "Did the
tests pass?" is a boolean; asking a 30B model to infer it from prose is slow, costly, and
occasionally wrong on the negation.

PrismPath's position: **these failure modes are complementary. Compose them.** Author logic as logic,
intent as intent, and spend an LLM call only on the genuinely-ambiguous residue.

**The structural reason this is more than a router.** The difference is one line: **your control
flow is DATA, theirs is code.** In LangGraph, CrewAI, and every Python-native agent framework, the
routing logic (which node runs next, and why) lives inside Python callbacks: conditional-edge
functions, `@router` methods, `Command` returns. It is executable code, opaque to everything that is
not a Python interpreter. You cannot diff a decision, lint a callback for a contradiction, pin an
embedding so it can't drift, draw the true graph without running the program, or hand the routing
table to a non-programmer. In PrismPath the flow *is* a Markdown document and every edge condition is a
string in it, so an entire class of operations opens up; each one is something you do *to data*, not
to a routing callback. That asymmetry is not one feature; it is the generator of all of them (the
lockfile of §4.6, the Markdown fixture tests and Mermaid render and OTel spans of §8, the static
analyzer of §7.1, the LangGraph importer of §8, the risk controlled calibrator of §4.7). The honest
answer to "why not just LangGraph or CrewAI?" is therefore two concrete things: the **measured
comparison below**, *grounded in* this data-not-code asymmetry; not the other way around.

**Measured, not argued.** We implemented the `bugfix` flow four ways; PrismPath's hybrid router, a live
LangGraph `StateGraph` whose conditional edge is an LLM call, the naive one-call-per-hop LLM-router,
and a CrewAI `Flow` whose `@router` is an LLM call; and scored all four on the same labeled hard
suite (**N=301**), same local model (gemma4), same routing prompt, δ=0.05, 2 repeats
([`comparisons/`](../../prismpath/comparisons/), one-command reproducer). The N=301 suite is 17 hand-crafted
gold cases plus 284 generated cases each gated by an independent blind second-labeler (see the
provenance note in §4.3):

| metric | PrismPath | LangGraph | LLM-router | CrewAI |
|---|---|---|---|---|
| routing accuracy (hard suite) | **83.7%** | 99.0% | 99.0% | 99.0% |
| LLM calls / 1k transitions | **383** | 1000 | 1000 | 1000 |
| median latency / transition | **205 ms** | 435 ms | 437 ms | 430 ms |
| **p95 latency / transition** | **655 ms** | 445 ms | 453 ms | 442 ms |
| determinism (across repeats) | 100% | 100% | 100% | 100% |

On a semantic branch, LangGraph, CrewAI-Flows, and the LLM-router all reduce to the same thing; one
LLM call, in Python, every time; so they collapse to one call per hop and **tie identically** at
99.0% / 1,000 calls / ~435 ms. PrismPath escalates to the model on only the **38.3%** (383/1000) of hops
the embedding tier is unsure about, routing the suite at **~2.6× fewer model calls**. Frame that as
throughput, not dollars: on a shared local endpoint 2.6× fewer calls is ~2.6× fewer GPU-seconds and
so ~2.6× more concurrent streams per box; local inference's marginal cost is roughly electricity, so
the honest win is capacity, not a bill.

**Name the tradeoff plainly: PrismPath wins on median and throughput, and loses on tail latency.**
PrismPath's latency is **bimodal**. A typical hop is embed-only, so the median is **205 ms**: well under
the LLM arms' ~435 ms. But an *escalated* hop pays the embed **and then** the LLM (~205 + ~450), so
PrismPath's **p95 is 655 ms**, *slower* than a pure LLM hop's ~435 ms. A user with a hard p95 SLA should
route straight to the LLM; PrismPath is the wrong tool for a strict tail budget. This is the price of the
cheap common case, and we state it rather than hide it.

PrismPath also *loses ~16 points of accuracy* to the three LLM arms (83.7% vs 99.0%); but that is **an
operating point, not a ceiling.** PrismPath is **a knob, not a point**: 83.7% is the *zero shot* δ=0.05 setting; stacking the same escalation over learned
centroids (the recommended configuration) lifts this to **90.0% at δ=0.01, 95.3% at δ=0.03, and
98.0% at δ=0.05** (companion research write-up §4.3), converging toward the always-call arms' 99.0%
at higher call budgets; with one honest ceiling: escalation cannot reach the *confident* errors the
embedder is sure-but-wrong on (the margin blind spot), so closing the final gap to 99.0% is not free. The other three expose no such dial; they are pinned at one call per hop. And their 99.0% is
itself soft: the LLM arm scored 100% on the old 17-case gold set and fell to 99.0% at N=301, and would
fall further at larger N; which *strengthens* PrismPath's relative position, not weakens it.

**Seven capabilities the asymmetry makes possible; all shipped in PrismPath.** Because a flow is data,
seven concrete operations open up that a Python routing callback cannot cleanly support, and each
ships in the tree. Every one is a lever on "things you do to data, not to a Python callback": (1) a
**routing lockfile** (`prismpath lock`, §4.6); (2) **flow tests in Markdown** (`prismpath test`, §8); (3)
**error edges** (`-> t: on error`, §4.4); (4) **`prismpath graph` → Mermaid** (§8); (5) **OpenTelemetry**
decision spans (§8); (6) the **LangGraph importer** (`prismpath import`, §8); (7) **wait-for-event**
edges (`on event`/`on timeout`, §4.5, resumed from a checkpoint, §5). Two earlier objections are also
**closed**: **resume-against-an-edited-flow** (fixed by the flow-hash binding of §5) and
**embedding-routing reproducibility** (fixed by the lockfile of §4.6). Two objections remain **open**
and are named honestly in §11. Read the seven together as the concrete evidence that a data-shaped
control flow buys operations a code-shaped one cannot.

### 1.1 And why not just add LangSmith?

Because most of what that layer sells is compensation for a substrate this system doesn't have.
LangSmith (with Langfuse, Arize Phoenix, and W&B Weave as its cohort) is the observability /
evaluation / prompt-ops layer: trace every run, reconstruct what happened, judge the outputs,
watch dashboards for drift. A meaningful fraction of that exists *because* LangGraph-style control
flow is invisible: tracing is how you discover a topology that lives in callbacks, and a dashboard
is how you notice drift nothing else will catch. PrismPath ships with the hood open. The topology is
knowable before anything runs (`prismpath graph`, `validate`, §8); a routing decision **explains
itself natively**: margin, top-1/top-2, escalated-or-not are attributes *of* the decision, not
forensics reconstructed after it; versioning is git, because the whole artifact is a file; drift
detection is the lockfile's fingerprint check (§4.6); a loud refusal, not a chart you have to be
watching.

Where the layers genuinely overlap, the difference is in kind. Their evaluations judge *outputs*;
inherently fuzzy, mediated by model judges; `prismpath test` (§8) asserts *routing*; exact,
model free for the deterministic and embedding tiers, CI-native at millisecond speed. Their
annotation queues label traces for evaluation dashboards; `prismpath label`'s labels feed
`prismpath calibrate` and become τ (§4.7); a **runtime control knob**. That is the recurring pattern
across the whole comparison: their loop terminates in a dashboard; this one terminates in the
router.

And where that layer does things this system should not chase; worker-output quality evaluation
at scale, token/cost accounting per call, cohort analytics, alerting, prompt A/B experimentation,
multi tenant RBAC; the two **compose rather than collide**: PrismPath emits OpenTelemetry
decision spans (§8) into the Grafana/Jaeger/Datadog a team already runs instead of asking it to
adopt a new pane of glass, and a worker that is internally a LangChain chain can keep LangSmith
pointed at its interior while PrismPath's spans cover the decisions *between* workers. (One honest
kinship: the gates of §9 are the deterministic cousin of LLM-as-judge; "compiles, wired,
reachable" is output evaluation with a machine verdict instead of a model opinion; but that
covers build-shaped work, not generation quality in general.)

---

## 2. The mental model

> **The Markdown file a domain expert reads *is* the graph the engine runs.** No translation layer,
> no code-behind. `git diff` on a flow is a diff of the business process.

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

## implement
Write or revise the fix.
-> review: when tests_pass
-> implement: when visits < 4 and not tests_pass
-> triage: a design decision is needed before continuing

## review
Review the change.
-> done: the diff is correct and ready to merge
-> implement: the review found problems that need changes

## done
Summarize and finish.

## gather_info
Ask the reporter for what is missing.

## close
Close the report with a reason.
```

Read it top to bottom and you understand the whole process. Note `## implement` mixes tiers: two
**deterministic** edges (`when …`, exact) and one **semantic** edge (natural language). That mixing
is the design.

---

## 3. The format

- **Front-matter (optional):** YAML with `name` and `start`. If `start` is omitted, the first node.
- **Node:** `## Heading`. The heading (lowercased, spaces→underscores) is the node id; the prose
  under it is the **instruction** handed to the agent.
- **Edge:** a line `-> target: condition`. `target` is a node id; `condition` is one of four forms;
  a `when` predicate (a bare `always`/`else`/`false`), a natural language phrase, an **error** clause
  (`on error [when <expr>]`), or an **event** clause (`on event <name>` / `on timeout`). The engine
  classifies each edge by the text of its condition and dispatches it to the matching tier (§4).
- **Node annotation (optional):** a line `@checkpoint(unit=<state-key>, proof=<state-key>,
  gate=<field>)` under a heading marks the node whose completion the Flow-Ledger records as a
  proof-commit (§5.2). The kernel just parses annotations onto `Node.annotations`
  (`parser.py:33,106`); the control plane reads them.
- **Terminal node:** any node with no edges. The run ends when it reaches one.

### The agent contract

The engine is worker-agnostic. You pass a single callable:

```python
agent(node_name: str, instruction: str, state: dict) -> str | dict
```

- Return a **string** → it's the text used for semantic routing.
- Return a **dict** `{"text": ..., <field>: <value>, ...}` → `text` feeds semantic routing, and the
  other fields are the variables the `when` predicates see. Example: a run-tests node returns
  `{"tests_pass": True, "text": "all 240 tests passed"}` so `-> review: when tests_pass` fires
  *exactly*, and a downstream semantic edge can still read the text.

`state` is shared across the run; the engine seeds `state["transcript"]` (the running log) and
`state["visits"]` (per node entry counts; the basis for loop caps like `when visits < 4`).

Because the contract is just a callable, the *worker* is pluggable: a hosted LLM, a local agent
swarm, a shell command, a deterministic mock for testing. The engine never knows or cares.

---

## 4. The routing spectrum (the core)

At each node, PrismPath picks the next edge by the **form of the condition**. There are **four tiers**;
the classifiers in `predicates.py` partition every condition string into exactly one of them
(`is_deterministic`, `is_error`, `is_event`, and `is_semantic` as the residual;
`predicates.py:56-84`), so classification is total and non-overlapping:

| Edge you write | Tier | How it routes | Cost |
|---|---|---|---|
| `-> t: when <expr>` / `always` / `false` | deterministic | safe predicate over the outcome fields + `visits` | free, exact |
| `-> t: <natural language>` | semantic | cosine(embed(outcome), embed(condition)), argmax | one embedding |
| *(same, under HybridRouter)* | semantic (hybrid) | embed-first; **LLM only if low confidence** | ~free + rare LLM |
| `-> t: on error [when <expr>]` | error | fires *only if the worker raised*, on an error context | free, exact |
| `-> t: on event <name>` / `on timeout` | event | the run **suspends**; resumes when the event is delivered | out of band |

**Evaluation order.** On the *normal* return path: deterministic edges first, **in document order,
first-true-wins**; only if none match do the semantic edges go to the router. Error edges are
orthogonal; they are consulted *only* when the agent call raises, before any normal routing. Event
edges are inert during synchronous routing; they are armed only when the worker asks to `wait` and
resolved out of band on resume (§4.5). Design maxim: **logic where logic exists, intent where it
doesn't**: and the deterministic, error, and event tiers never consume an LLM call; only the
semantic tier can reach a router.

### 4.1 Deterministic predicates · and the safety property

`when` expressions are evaluated by a **sandboxed AST walker** that permits only names, constants,
`and`/`or`/`not`, comparisons, and literal lists; **no function calls, attribute access, or
subscripts.** Unknown names are `None` (falsy). Consequences:

- **Negation, counts, thresholds are exact and free**: `when not tests_pass`, `when severity >= 12`,
  `when visits > 3`, `when action == "contain"`. These are *never* misrouted, which is the whole
  point: don't ask a language model to do boolean algebra.
- **It cannot execute code.** A flow is a Markdown file that may come from a non-engineer (or an
  untrusted source); the condition language is provably side-effect-free. Authoring control flow is
  safe. The claim is fuzz-tested (`fuzz_predicates.py`): across ~8k adversarial + random inputs;
  including call/attribute/subscript/lambda/comprehension/f-string/walrus/`__import__` payloads;
  no input executed code, and none produced an uncaught crash. Two guarantees back this:
  `check_predicate(cond)` statically rejects any unsafe or unparseable predicate *without
  evaluating it* (wired into `validate`/`lint`, so it's a compile-time error), and `eval_condition`
  fails safe; a comparison against a missing or type-mismatched field is *unsatisfied* (matching
  "unknown name → falsy") rather than a crash, so a malformed predicate never kills a running flow.

### 4.2 Semantic edges

Natural language conditions are embedded once (cached per node) and matched against the agent's
outcome text by cosine similarity (default `bge-base-en-v1.5`, CPU; the model is tiny and this keeps
the GPU free). This nails **intent/topic** distinctions ("the customer is asking about a refund" vs
"the customer is reporting a crash") essentially perfectly.

### 4.3 The hybrid router · embed first, LLM on doubt

`HybridRouter` computes the embedding decision *and its margin* (top-1 similarity − top-2). If the
margin ≥ δ, it takes the embedding pick for free. If not; a near-tie, i.e. the model is *unsure*;
it makes **one** LLM call to break the tie, and records that it escalated. δ (default 0.05; the
default; the frontier is smooth (re-derived at N=301, see the companion research write-up) and best stacked over learned centroids) is the
single knob trading LLM-call rate for accuracy.

Why this matters in practice: embeddings are perfect on intent but fragile on *logical polarity* and
*abstraction* ("Not a bug; behavior is correct per spec" gets pulled toward "implement" by the word
"correct"). The margin is a natural detector for exactly those cases, so **LLM spend concentrates on
the genuinely-hard transitions instead of being paid on all of them.** Measured on the N=301 suite
(`reproduce.py`), the embedding tier alone scores **0.81 on intent, 0.74 on abstraction, and 0.52;
near chance; on polarity**, for **0.69 overall**; the split is the empirical case for having the
deterministic and LLM tiers at all (a lexical baseline scores 0.53 overall on the same suite). The
PrismPath head to head operating point at δ=0.05 (all strata) is **83.7%**, escalating **38.3%** of
decisions to the LLM (§1). N=301 is 17 hand-crafted gold cases plus 284 generated cases, each gated
by an **independent blind second-labeler**: given only the outcome text and the node's edges, never
the intended label; with only agreed cases kept (inter-annotator agreement **0.979**, an AI-vs-AI
upper bound: both automated annotators share a model family). **Gate zero is now delivered:** a human
**blind-relabeled all 301 cases** at **Cohen's κ = 0.961 vs gold** (every stratum ≥ 0.945), and an
independent cross family model (Gemini) agrees at **κ = 0.682** ("substantial"); 90% of its
disagreements are cases where the human matches gold and the model dissents alone, concentrated on the
polarity stratum, so a blind zero shot model reproduces the very trap named next. A second *human*
annotator remains the strongest still-open measure. Every retained label is a real edge of a real flow.

The **polarity trap** is worth its own name: two sibling semantic edges that are *topically
near identical but logically opposite*; "the tests pass" vs "the tests fail", "it is ready" vs "it
is not ready". An embedder encodes *topic*, and a negation barely moves the vector, so the two live
in almost the same place and the router misroutes them confidently. PrismPath catches this at
**authoring time**: `lint`'s `polarity_mirror` check (`lint.py:54`) flags a pair when it is both
topic-similar (cosine ≥ 0.72, deliberately a *lower* bar than the 0.86 `semantic_ambiguity`
threshold of §7.1, because the negation itself pushes the vectors apart) **and** carries a lexical
polarity signal; an
asymmetric negation marker or a hardcoded antonym flip (`_polarity_signal`, `lint.py:41`). The
prescribed fix matches the whole thesis: have the worker emit a structured field and rewrite the
branch as `when <field>` / `when not <field>`, demoting the decision out of the fragile embedding
tier into the exact deterministic one (see §7.1).

**Rule of thumb for authors:** if a condition is *logic* (a boolean/count/threshold on something the
worker can report), make the worker emit a field and write `when …`. If it's *judgment*, write it in
plain language and let the hybrid router handle it.

### 4.4 Error edges · failure handling as a visible edge

The **error tier** turns `try/except` into a first class edge in the document. When the agent call
raises, the engine wraps it (`engine.py:108-136`) and builds an error context;
`{error, error_type, error_message, error_count, visits}`, where `error_count` is a **cumulative
per node lifetime** raise counter (`engine.py:111-114`); it is **never reset on success**, so
`on error when error_count < 3` counts the *total* number of raises at that node over the whole run,
**not consecutive** ones. It then walks the node's edges in document order, considers only the
`is_error` ones, and takes the first whose predicate is satisfied. A bare `on error` matches any
error; `on error when <expr>` evaluates the same safe predicate grammar over the error context:

```markdown
## call_api
Call the upstream service and return its response.
-> parse: when ok
-> call_api: on error when error_count < 3        # transient: retry up to 3×
-> escalate: on error when error_type == "AuthError"
-> dead_letter: on error                          # any other error
```

Safety property: **backward-compatible propagation.** If no error edge matches, the engine
**re-raises** the original exception (`engine.py:126-127`); a flow without error edges behaves
exactly as it did before this tier existed. The error-predicate evaluation reuses the same total,
never-crashing `eval_condition`, so a malformed error predicate cannot itself crash the handler loop.
(This is one of the seven shipped capabilities of §1.)

### 4.5 Event edges · suspend on an external signal

The **event tier** lets a run pause until an external signal arrives; a webhook, an approval, a
timer. It does *not* fire during a normal step. Instead it is armed when the worker returns a truthy
`wait` field: the engine gathers the node's `on event <name>` / `on timeout` edges, sets
`stopped = "waiting"`, records a `pending` packet listing the awaited event names and an optional
`timeout_s`, and returns (`engine.py:150-160`). The engine is pure and does no I/O, so it does not
block or fire the timer itself; but the timer is not left inert: a **reference scheduler ships**
(`scheduler.py`) that scans waiting checkpoints and delivers the elapsed `on timeout` event. The timer
lives in the **harness, not the engine**; an external caller (a cron tick, a loop, a systemd timer)
delivers a named event or, via the scheduler, a `__timeout__` event:

```markdown
## await_approval
Post the change for approval and wait.  # worker returns {"wait": True}
-> deploy: on event approved
-> revise: on event rejected
-> escalate: on timeout
```

Resumption is out of band via `checkpoint.resume(ckpt, agent, event="approved")`, which finds the
edge whose `event_name` matches the delivered signal and re-enters `run()` at that target
(`checkpoint.py:184-199`); a timeout is delivered as the literal `"__timeout__"`; the reference
scheduler's `fire_due_timeouts` (`scheduler.py`) scans a queue of `waiting` checkpoints and delivers
it for every run whose `timeout_s` has elapsed since `saved_at`. An unknown event is refused with the
list of what the node is awaiting. Because this rides on the durable checkpoint (§5), the suspension
survives a process restart. (This is one of the seven shipped capabilities of §1.)

### 4.6 Reproducible routing · the lockfile

Because embedding routing depends on the embedder's exact numerics, a model update or a different
ONNX build or hardware float drift can shift a margin across δ and change routing **with no diff
anywhere in the flow**. `prismpath lock <flow>` writes a `<flow>.lock` (`lockfile.py:68-91`) committing,
*as data*: each semantic condition's embedding vector (base64 little-endian float32; bit-exact and
diffable, `lockfile.py:39-44`), an embedder **fingerprint** (a fixed probe sentence and its
embedding), δ (`DEFAULT_DELTA = 0.05`), and a SHA-256 of the flow file. At runtime,
`LockedEmbeddingRouter` (`router.py:52-74`) looks each condition's vector up in the committed dict
instead of embedding it live; only the *outcome* is embedded locally, the *condition* side is
bit for bit fixed; so a missing key means "the flow changed; re run `prismpath lock`". `verify_lock`
recomputes the probe cosine and checks the embedder matches (cosine ≥ `LOCK_COSINE_MIN = 0.9999`);
on a mismatch, `prismpath_LOCK_POLICY` chooses `refuse` (default; raise), `warn`, or `allow`.
`prismpath lock --check` runs that verification standalone. Semantic routing becomes bit for bit
reproducible across machines and years, and embedder drift becomes a *loud, policy-controlled signal*
instead of a silent misroute; a `package-lock.json` for control flow. You cannot "lock" a Python
`if`: there is no vector to commit and no fingerprint to diff. (This is the fix for the
embedding-reproducibility objection.)

A caveat we state rather than let a reviewer find: `LOCK_COSINE_MIN = 0.9999` is a **chosen** constant,
not one measured across the full matrix of torch/ONNX/fp16/CPU to GPU builds. A legitimate cross-platform
build could in principle drift the probe cosine below it and trigger a **false refuse**; `policy=warn`
(`prismpath_LOCK_POLICY`) mitigates that by downgrading the mismatch to a warning. Note also that the lock
and the calibrator **compose**: `lock(δ)` governs the condition *vectors* (fixing what gets embedded),
while `calibrate(τ)` (§4.7) governs *escalation* (when to consult the LLM); orthogonal knobs that
stack, not alternatives.

### 4.7 Calibrated escalation · the risk controlled τ

The hybrid router's δ is a hand-set constant. `prismpath calibrate` replaces it with a threshold
*derived from evidence with a coverage guarantee*. The routing margin (top-1 − top-2 similarity) is a
confidence score, and escalating to the LLM is *abstention*; i.e. **risk controlled selective
classification**. Given a set of labeled routing decisions, `calibrate(records, alpha)`
(`calibrate.py:60-94`) finds the smallest threshold **τ** such that the decisions the router does
*not* escalate (margin ≥ τ) are correct at rate ≥ 1−α, using a **finite sample Wilson lower bound**
(`_wilson_lower`, `calibrate.py:35-44`) so the guarantee holds beyond the calibration sample. This is
a single-threshold instance of the **Learn-Then-Test / Risk-Controlling-Prediction-Sets** family
(Angelopoulos, Bates, et al.), and the **Wilson lower bound is the certificate**. It is deliberately
**not conformal prediction**: there is no nonconformity-score quantile and no exchangeable
prediction-set construction; we say "risk controlled selective escalation" for exactly that reason.
`RiskControlledHybridRouter` (`calibrate.py:107-127`; `ConformalHybridRouter` is retained as a
back-compat alias) is an ordinary `HybridRouter` whose escalation margin *is* that calibrated τ;
identical runtime behavior, but the threshold now carries a risk guarantee. `calibrate` also reports
the **effective N and the width of the bound** (`tau_n_kept`, `tau_accuracy` vs `tau_acc_lower`), so
the guarantee is inspectable rather than a bare point estimate. If nothing meets the bound, τ is
`None` and the router **escalates everything** (fail safe toward the LLM) and the calibrator
**warns loudly** that this reverts to LLM-router economics rather than failing silently. The labeled
input comes for free from `prismpath test --emit-labels` and `prismpath label` (§8), which produce the same
record format `calibrate` consumes.

### 4.8 The prefilter cache · memoize the expensive node itself (opt-in)

The spectrum above makes *transitions* cheap. In *triage-shaped* production flows the dominant
cost is not routing at all; it is one **adjudication node** (an LLM classification, a slow judge)
whose inputs recur near-identically. `prismpath.prefilter.PrefilterCache` memoizes that node's
verdicts:

- Every adjudication is stored as (normalized embedding of the input document, verdict record
  `{action, confidence, key, description}`).
- Before the expensive call, `lookup(document)`: a **hit** requires *two* thresholds to pass;
  cosine similarity ≥ `threshold` (default 0.97: *is this the same situation?*) **and** the stored
  verdict's confidence ≥ `min_conf` (default 0.8: *was the prior verdict trustworthy?*). On a hit
  the prior verdict is reused and the expensive call is **skipped**; the reuse is logged with the
  matched key and similarity, so it is auditable.
- On a miss, make the call, then `learn()` the fresh verdict; the cache **compounds**: every
  escalation makes the next near identical input free.

Wiring it into a flow needs no engine support; it is a plain node plus deterministic edges (this
is the production SOC pattern of §6):

```markdown
## vector_prefilter
Match the alert against prior adjudications; reuse a near-identical high-confidence verdict.
-> stage_containment: when cached_action == "contain"
-> watchlist: when cached_action == "watch"
-> benign: when cached_action == "ignore"
-> classify: when always            # miss -> pay for the LLM, then learn()
```

**Measured (streaming replay over the author's own Wazuh instance, 400 real alerts oldest-first,
threshold 0.97): a 58.3% hit rate; 233 of 400 alerts auto-resolve by reusing a prior adjudication
before the LLM tier is touched (~2.4× capacity before the model is called).** This is a *streaming
replay over the author's own Wazuh*, not a live SOC deployment. The rate is distribution-dependent
(alert streams are highly repetitive; a novelty-heavy stream caches less), which is why the threshold
is per-cache and the measurement harnesses (`measure_prefilter.py`, `measure_reuse.py`) report the
rates. The embedder is pluggable (`embed_fn: list[str] -> unit vectors`); the default is a small
CPU/GPU sentence-transformer, and any modality encoder satisfying the contract can feed the same gate.

**Does reuse *compound* unsafely?** The natural objection to a compounding cache is that a stale reuse
propagates a wrong verdict. We measured it: for every one of the 233 hits we *also* ran the LLM fresh
(same prompt and model as production) and compared the reused action against that fresh verdict; an
**oracle**, not human ground truth (we say so). Result: **97% reuse agreement (226/233)** and **zero
unsafe downgrades**: the cache never reused a `watch`/`ignore` verdict where the fresh LLM would have
said `contain`, which is exactly the dangerous compounding failure. All **7 disagreements are
`contain → ignore`**: the cache *over*-blocking, the safe direction, and containment drafts are
human-reviewed anyway. The compounding risk we most feared did not occur in the replay; the residual
disagreement lands on the conservative side.

**This is a use-as-needed pattern, not an engine default**: the engine never invokes the cache;
an author wires it in per flow. It presumes three things: one node dominates cost; inputs recur
near-identically; and **the verdict is a function of the embedded document alone under a stable
policy**: everything the decision depends on must be in the document, or a reuse can silently
apply a verdict from a different context. (The SOC flow embeds only the *stable* alert fields,
not the volatile 24-hour enrichment; an explicit scoping choice trading context-sensitivity for
cache stability.) Generative, novelty-heavy, or context-dependent nodes should not be prefiltered.

**The cache polices itself (shadow sampling + policy-keyed invalidation).** The one-off oracle replay
above answers "was reuse safe *then*"; production needs the question answered *continuously*.
`lookup(doc, sample_rate=r)` flags a fraction of cache **hits** for shadowing: the adapter reuses the
verdict *and* runs the real adjudicator, then feeds the comparison to `record_shadow()`. The corpus
accumulates a live **reuse-error rate** reported alongside the hit rate (`python -m prismpath.prefilter
monitor <dir>`), and an entry whose disagreement crosses a bound (on the **cumulative** rate *or* a
bounded **recent window**, so an entry that was stable for months and then drifts is pulled within a
few samples rather than after its lifetime rate erodes) is **quarantined**: `_eligible()` drops it
from matching without deleting the evidence, and one situation goes back to the LLM tier (fail safe:
a false pull costs one call; a missed drift compounds). Invalidation is likewise structural, not TTL:
`learn(..., policy_hash=h)` stamps each verdict with the flow it was adjudicated under (the SOC
adapter passes the same content hash the checkpoint and lockfile layers use), and a lookup under a
different hash skips it; **editing the policy invalidates the stale verdicts automatically**, with
no manual purge. Entries otherwise never expire (re-seed to reset); wall clock TTL remains future
work, deliberately behind the structural invalidators above.

**Prior art, stated up front.** Semantic caching is not new; GPTCache and kin memoize LLM calls by
embedding similarity, and we cite them. The prefilter's novel parts are narrower and specific: the
**two-threshold gate** (similarity answers *is this the same situation?* while the stored confidence
answers *was the prior verdict trustworthy?*; a single similarity threshold has no second axis); the
**explicit scoping** (embed the stable fields, exclude the volatile context, so a reuse cannot
silently apply a verdict from a different context); and the **deployment finding** that in a
triage-shaped flow, memoizing the *worker* node dominates memoizing the *transition*; the expensive
adjudication is where the cost lives, not the routing.

---

## 5. Durable execution · checkpoints, resume, and the Flow-Ledger

The engine (`engine.py`) is **pure**: its `state` dict is ephemeral, thrown away when `run()` returns.
Durability is added *around* it, in two independent layers, and the invariant both preserve is that
**the flow `.md` is read only source and is never mutated**: durable state lives outside the
document (which is exactly why a checkpoint is a JSON sidecar, not a checkbox written back into the
prose).

### 5.1 The JSON checkpoint · one run, crash-resumable and suspendable

`run_durable(flow, agent, checkpoint_path)` (`checkpoint.py:118`) runs a flow while serializing the
live state to a JSON sidecar every step and at every suspension. Writes go through `_atomic_write`
(`checkpoint.py:49-58`): write to `{path}.tmp`, `flush` + `os.fsync`, then `os.replace`; atomic on
POSIX, so a crash mid-write leaves the previous valid checkpoint or the new one, never a torn file.
Checkpointing is **off the critical path**: if the state is not JSON-serializable, it disables itself
with a warning and the run continues (`checkpoint.py:118-136`).

The engine reports one of **five stop reasons** (three *terminal*, two *suspension* / resumable):

- `terminal`; reached a node with no edges (success).
- `stuck` (a deterministic-only node with nothing matching (an authoring bug) surfaced, not
  guessed around).
- `max_steps`; the runaway-loop bound.
- **`needs_human`**: the worker returned a truthy `needs_human`, *or* a semantic route scored below
  the `human_floor` (route to a person instead of guessing). `human_floor` is **opt-in, default
  `None`**, and is a **`run()` API parameter** (Appendix B). Its precedence is precise: **deterministic
  edges → the `HybridRouter` (which escalates to the LLM on a top-1−top-2 margin below δ) → then, only
  if the embedding score falls below `human_floor`, suspend as `needs_human`.** The floor is checked
  **only when the router did *not* escalate**: an escalated decision carries the LLM's answer, not an
  embedding score, so there is no score to compare. The checkpoint records a `pending` evidence packet:
  the node, the reason, the candidate edges, and (for the floor case) per-candidate scores and the edge
  it *would* have picked (`engine.py:143-148,172-184`).
- **`waiting`**: the worker asked to `wait` for an event (§4.5); `pending` lists the awaited events
  and any `timeout_s`.

**Resume** (`checkpoint.py:139`) re-parses the read only `.md`, restores `state`, and re-enters the
same pure `run()`. There are three re-entry paths: `resume(ckpt, agent, choose=<edge>)` applies a
human's decision for a `needs_human` suspension (validated against the pending node's actual edge
targets); `resume(ckpt, agent, event=<name>)` delivers an event for a `waiting` suspension; and a
bare `resume(ckpt, agent)` after a crash re-enters at the pending node and **re runs it**
(idempotent at node granularity for a deterministic engine). The CLI exposes
`prismpath resume <checkpoint> [--choose <edge>]`; `event=` resume is a library call.

**Flow-hash binding (the fix for resume-against-an-edited-flow).** Every checkpoint stores
`"sha256:" + sha256(flow bytes)` at write time (`_flow_hash`, `checkpoint.py:35`). On resume,
`_check_flow_unchanged` (`checkpoint.py:93-115`) recomputes and compares; on a mismatch,
`prismpath_RESUME_ON_FLOW_CHANGE` chooses `refuse` (default; raise, the audit-safe choice), `warn`, or
`allow`. This answers "which version of the flow governs a continuation?" *in code*: by default, the
one it was suspended against, or an explicit override is recorded. (A checkpoint predating
flow-hashing carries no hash and is not blocked; backward-compatible.)

**The human queue → Mission Control.** `list_queue()` (`checkpoint.py:241`) scans a queue directory
(`prismpath_QUEUE_DIR`, else `$XDG_STATE_HOME/prismpath/queue`) and projects one evidence packet per
`needs_human` checkpoint; node, reason, `would_pick`, candidates; newest-first. `record_decision()`
(`checkpoint.py:277`) atomically writes a validated `{choose, decided_by}` back into a checkpoint; a
later bare `resume()` picks it up. Mission Control's HTTP layer wires exactly these:
`GET /api/queue → list_queue()` and `POST /api/queue/decide → record_decision()`
(`mission_control.py:704,782`), giving a human a review surface for suspended runs. *(One honesty
note: the queue is a read/update surface; nothing in the repo automatically writes a fresh
`needs_human` checkpoint into the queue directory; enqueueing is the harness's job.)*

### 5.2 The git Flow-Ledger · commit-as-state, done-ness as a projection

Where the checkpoint makes a *run* resumable, the Flow-Ledger (`ledger.py`, opt-in) makes each
*completed unit* a durable, content addressed **proof-commit**. Ledgers live in a **separate bare
git repo** under `$XDG_STATE_HOME/prismpath/<flow>.git` (or `prismpath_LEDGER_DIR`); never inside the
project tree (`default_state_dir`, `ledger.py:50-57`; the `<flow>.git` repo path, `ledger.py:85`).
All writes go through git *plumbing* (`hash-object`, `write-tree`,
`commit-tree`, `update-ref`) with `GIT_DIR` pinned and no working tree, so the project's own repo,
index, and files are never touched; and a `SPRINT_FRESH` `rmtree` of the project **cannot delete the
ledger**, because it lives outside.

Each run gets one **orphan ref** `refs/prismpath/runs/<run-id>`; `commit_unit()` (`ledger.py:144`)
records one gate green unit as a commit whose tree is the *cumulative* content-hashed state the gate
blessed, carrying machine-parseable RFC-822 trailers (`PrismPath-Flow/-Run/-Unit/-Node/-Seq/-Gate/
-Output-Hash/…`). Git identity and dates are **pinned constants** so a commit's sha is a pure function
of `(content, parent, message)` (reproducible) with the consequence that the sha is *time-independent
by design* and cannot itself carry when the gate went green. Real green-time is therefore recorded
separately in an **`prismpath-Wallclock`** trailer, and the stable per-unit proof anchor is the
order-independent, content addressed **`prismpath-Output-Hash`** (`sha256_files`, `ledger.py:60`), not the
commit sha. The ref write is a **compare-and-swap** (`update-ref <ref> <new> <old>`) that, on a
concurrent ref move, **re-reads the tip and rebuilds on it** (retrying up to `_CAS_RETRIES`) rather
than dropping the proof; no lost commits under concurrency. One honest scoping note: "tamper evident"
here means **accident-evident** (a fat-fingered edit breaks the hash chain and is caught) but an
*adversary* with filesystem access can rewrite the whole chain and its pinned dates; the honest
adversarial upgrade is external anchoring (OpenTimestamps): **connected v1 is delivered**
(`ledger_ots.py`, Bitcoin/OTS) and the **air gap tier is delivered too** (`ledger_airgap.py`, an
internal **RFC-3161** trusted-timestamp path validated fully offline); trustless at the connected
tier, trust-a-TSA at the air gapped tier, and never presented as Bitcoin-strength on an air gapped site.

The thesis is `done_set()` (`ledger.py:221`): it folds the log into `{unit → latest green record}`,
**newest-wins**, so "which units are done" is a *derived projection over `git log`*, not a mutable
status field that can go stale or lie; this is event sourcing, and it is the ledger's replacement for
the `.kg.json` status pointer. Because the proof is an ordinary git object, a human can `git show`,
diff, and verify it by hand.

**Resume-from-ledger.** For **routing** flows, `ledger_runner.run_ledgered_loop` (`ledger_runner.py:63`)
drives a per-item loop: the flow marks one node `@checkpoint(unit=<state-key>, proof=<state-key>,
gate=<field>)` (§3), each pass seeds `state['_done_units']` from `done_set()` so already-proven items
are skipped, and a gate-red item is *skipped this pass* (added to `blocked`) so it can't head-of-line
block the queue. A stopped run restarts at the first item with no green commit; no separate
processed-list to keep in sync. For **build (sprint)** flows, the ledger is wired behind
`SPRINT_LEDGER=1` (`run_sprint.py:80`): a sprint whose `.kg.json` was wiped by `SPRINT_FRESH`
restarts at the first *unproven* node instead of rebuilding what git already attests, and
`SPRINT_LEDGER_RUN=<id>` points a fresh process at a prior run's ref. The commit hook is best-effort
and strictly off the critical path; any failure degrades to the existing `.lastgood/.kg.json` path;
the ledger records progress, it never drives or breaks a sprint.

### 5.3 Fan out & sub-flow composition · parallelism without impurity

The standard objection to a pure, single-threaded engine is "no parallelism." The answer keeps the
needle threaded: **fan-in semantics live in the document as event edges; concurrency mechanics live
in an out of band harness** (`composer.py`, CLI `prismpath compose`). A fan out node declares its
structure; `@spawn(child=review_one.md, over=files, item_id=path, join=all_done, gate=…)`; plus
ordinary event edges (`-> aggregate: on event all_done`, `-> escalate: on timeout`); its worker
supplies only the runtime item list (`spawn` implies `wait`). The engine's *entire* involvement is a
pure passthrough of the spawn spec into the checkpoint. The harness; the same restartable-scan
shape as the timeout scanner; spawns one **durable child run** per item (an ordinary checkpointed
run, seeded with its item), under a **deterministic, collision-free id**
(`parent.node.item_id`, no timestamp or randomness), so a crashed-and-restarted scan *re-attaches*
to existing children instead of double-spawning. When the join policy holds (`all_done`, `any`,
`quorum:k` or a fraction; `gate=<field>` distinguishes *succeeded* from merely *finished*), the
harness folds the children's terminal outcomes into the parent's state (`_spawned[node]`) and
delivers the join event through the ordinary `resume(event=…)` path. Stragglers are never cancelled.
**Sub-flow composition is the N=1 case**: a single child is a fan out over a one-item list,
the same code path; and nested composition (a child that itself fans out) is driven depth-first
by the same scan. The design was adversarially reviewed; the review found (and we fixed, with
regression tests) a lossy-id child collision, a nested-composition deadlock, an
annotation/runtime join drift, and a non-serializable-child re run loop; and *cleared* engine
purity, restart idempotency, and the timeout-vs-join race.

Two properties make composition more than a runtime feature. **Static analysis crosses the flow
boundary**: a `@spawn` node with no matching `on event` edge is a compile-time *deadlock error*; a
missing, unparseable, or terminal-less child flow is an error (its runs would never finish, so the
join could never fire); and a parent `@expect(fields)` is checked against the child's `@emits`
declarations; the composition contract, verified across two documents without running either. And
**the lockfile pins the tree**: `prismpath lock <parent>` recursively locks every child, recording
`{flow_hash, lock_hash}` pins, and `lock --check` fails if any child flow or lock drifted after the
parent was pinned; reproducible routing across the entire call tree. This is the stress test of the
data-not-code thesis, and it holds: the whole composition is inspectable as data.

---

## 6. Worked examples

**A minimal self-correcting loop** (deterministic loop cap + semantic give-up):
```markdown
## run_tests
Run the hidden test suite.
-> done: when tests_pass
-> give_up: when visits > 3
-> debug: when not tests_pass

## debug
Judge whether the fix is clear or the task is unsolvable.
-> write_code: the fix is clear, edit and try again
-> give_up: the problem is unsolvable
```

**Support triage** (pure intent; the semantic tier shines):
```markdown
## classify
Read the incoming message and decide what kind of request it is.
-> bug_report: the customer is reporting something broken or erroring
-> billing: the message is about payment, invoices, refunds, or charges
-> feature_request: the customer is asking for a new capability
-> general_question: it is a how-to or usage question
```

**Production SOC triage** (the tiers composed; the author's own Wazuh use case). A structured worker returns
`{threat_class, is_active_threat, confidence, recommended_action, rationale}` via schema-constrained
decoding, so routing is *deterministic on the model's own verdict*, with a severity override and a
safe fallback:
```markdown
## classify
Judge the alert in context and return a structured verdict.
-> stage_containment: when rule_level >= 12
-> stage_containment: when recommended_action == "contain"
-> watchlist: when recommended_action == "watch"
-> benign: when recommended_action == "ignore"
-> watchlist: when always
```
This is the pattern's sweet spot: the LLM does the *judgment* (produce a verdict) and the graph does
the *control flow* (route on it); deterministically, auditably, with zero routing ambiguity. In the
deployed pattern, a `vector_prefilter` node (§4.8) sits in front of `classify` and skips the LLM
entirely for **58.3%** of alerts by reusing prior adjudications (measured in a streaming replay over
the author's own Wazuh, §4.8).

---

## 7. Runtime

`run(graph, agent, router=None, max_steps=25)` starts at `graph.start` and loops: run the node's
agent, normalize the outcome to `(text, fields)`, handle a raise via the error tier (§4.4), then
evaluate deterministic edges (doc order, first-true), else route the semantic edges, advance. It
returns a `RunResult` with the `path`, a per-step log (which edge, chosen how; `deterministic` /
`embed` / `llm` / `single` / `error` / `event`), and a **stop reason**. `single` is the tier for a
**lone semantic edge**: with only one candidate there is nothing for the LLM to disambiguate, but the
router still **scores** it (absolute cosine, `used="single"`, `router.py:107-113`) so a `human_floor`
can suspend a barely-matching lone outcome instead of blindly taking the only edge. The base run
yields three stop reasons:

- `terminal`; reached a node with no edges (success).
- `stuck` (a node with only deterministic edges and none matched (an authoring bug) surfaced, not
  guessed around).
- `max_steps`; a safety bound against runaway loops.

Under durable execution (§5) two more are reachable; `needs_human` and `waiting`; the suspension
reasons that carry a `pending` evidence packet and resume via `choose=` / `event=`.

Routers are swappable: `EmbeddingRouter` (cheap, flow-dependent; ~0.52 to 0.81 per stratum, 0.69
overall on the N=301 suite), `LLMRouter` (accurate, a call per decision), `HybridRouter(LLMRouter(gen),
margin=δ)` (recommended), `LockedEmbeddingRouter` (reproducible, §4.6), and `RiskControlledHybridRouter`
(calibrated τ, §4.7; `ConformalHybridRouter` is a back-compat alias). The
CLI offers `validate` (static analysis; see §7.1), `lint` (validate + the semantic-ambiguity and
polarity-mirror checks), and `run` (with a mock agent, to trace the path).

### 7.1 Static analysis · "your flow compiles"

Because the flow *is* the graph; a declarative Markdown file, not control flow scattered across
Python functions; the entire structure is analyzable *before* execution. This is a guarantee a
code-first framework cannot make: LangGraph's graph only exists once its Python has run. PrismPath's
`analyze(graph)` runs a set of **decidable** checks (no model, no embeddings, no execution),
emitting `Finding(severity, code, node, message)`:

- **Errors** (the flow won't run correctly): undefined start / edge targets; an unsafe or
  unparseable `when` predicate; **no terminal node reachable from start** (the run could only ever
  end at `max_steps`). `validate` exits nonzero on any error.
- **Warnings** (a likely mistake that still runs): unreachable nodes; a **deterministic-only node
  whose conditions are not provably exhaustive** (can halt as `stuck`); an edge **shadowed** by an
  earlier `always`/`else` catch-all (dead, unreachable); a **shadowed error edge**: an
  `on error when …` edge placed *after* a bare `on error` catch-all, which always matches first (the
  same first-match hazard as a deterministic catch-all, applied to the error tier); an **unbounded
  cycle** with no `visits`-based cap (bounded only by `max_steps`); an **always-false** edge
  (`when visits < 4 and visits > 10`); duplicate semantic conditions (a guaranteed router near-tie).
  That was the original **11 decidable checks**; the suite has since grown to **16 in graph check codes** (adding `@emits` provenance and type cross checks, `@field_only` enforcement, and the `@spawn` deadlock checks) plus **4 cross-flow composition checks** (§5.3) and the portability tiering of §8.6; all still decidable, all still zero-false-positive on the shipping flows.

Every check is decidable because the language is tiny. Reachability and cycle detection are
ordinary graph algorithms (DFS, Tarjan SCCs); predicate reasoning is confined to the fragment the
`when` language actually permits (a variable compared to literals, joined by and/or/not) so
"stuck" analysis detects complementary `P` / `not P` coverage, and "always-false" reduces to
single-variable interval intersection. No SMT solver is needed, and anything outside the fragment
is left *un-analyzed* rather than guessed, which is what keeps false positives at **zero** on real
flows. The safety of the `when` sandbox (§4.1) is enforced at this same static layer. A
deliberately-broken corpus (one flow per check, `tests/fixtures/broken/`) is the regression spec, and
a coverage test asserts the corpus exercises *every* code the analyzer can emit; `--json` output
makes the pass a drop in CI / pre-commit gate. This is the concrete, shipped form of what a research
treatment would frame as flow reachability/termination analysis over the graph.

**`validate` vs `lint`; decidable vs model-backed.** `validate` runs *only* the decidable checks
above; no model, so its "no false positives on real flows" soundness can be honored. `lint` is the
superset: it appends two checks that genuinely need the embedder; `semantic_ambiguity` (two sibling
conditions that embed too similarly to route between, cosine ≥ 0.86) and `polarity_mirror`
(`lint.py:54`), the **negation failure class** from §4.3. `polarity_mirror` fires only when *both* a
topic-similarity gate (cosine ≥ 0.72) *and* a model free lexical polarity signal agree; an
asymmetric negation marker (`not`/`no`/`never`/`n't`/…) or a hardcoded antonym flip
(pass/fail, valid/invalid, ready/blocked, …). Because these two are heuristic (a learned embedder plus
a curated lexicon), they are honestly *not* decidable and are quarantined out of the compile gate into
the advisory linter; the design keeps the soundness guarantee where it can be honored, and bounds the
fuzzy signal behind two conjunctive gates (tuned against synonyms so "clear"/"obvious" does *not*
fire). On the only corpus measured to date (the N=99 polarity stratum), `polarity_mirror` fired on
**0/99**: a precise catch for *lexically-explicit* negation/antonym pairs, not a general polarity
detector, so its true-positive efficacy is unvalidated (loosening the topic gate to 0.65 buys ~16%
coverage at ~14% false-flag).

---

## 8. The data plane · what you can do to a flow because it is DATA

This section is the concrete payoff of the data-not-code thesis (§1): every tool below is an operation
on the flow *as data*; hashing it, embedding its conditions, walking its edges, replaying its scored
decisions, translating a foreign graph into it. None is well-defined against a Python routing
callback. The lockfile (§4.6) and risk controlled calibrator (§4.7) are two more members of this
family; here are the rest. The unifying primitive is that routing is a pure function
`(outcome_text, [(target, condition)], instruction) -> target`, shared verbatim by every tool via
`engine.first_deterministic` and the `router.route` interface; so the picture, the test, and the run
can never disagree on how a node routes.

### 8.1 Flow tests in Markdown · `prismpath test`

You normally cannot test a flow without running live agents. Here the **fixture is itself Markdown**;
a GFM table of `(node, outcome, fields, expect)` rows (default `<flow>.tests.md`) executed against
the *real* deterministic and embedding tiers, **never the LLM** (`flow_test.py`). The runner calls the
same `engine.first_deterministic` that `run()` uses (`engine.py:58`, deliberately shared "so the two
can never disagree"), and only lazily builds an embed-only router if a row actually needs an embedding
decision; and it **prefers a committed `<flow>.lock`** if one sits next to the flow, so tests are
bit for bit reproducible. A PM writes scenarios in prose; CI asserts the routing; every past mis-route
becomes a regression row. `--emit-labels` appends each case as a labeled routing record; the same
format `prismpath calibrate` (§4.7) consumes; so authoring tests produces calibration data for free.
CLI: `prismpath test <flow> [tests_md] [--json] [--emit-labels PATH]`.

### 8.2 `prismpath graph` · native Mermaid render

Because the flow *is* the graph, one command turns it into a picture that renders natively in a GitHub
README or PR. `to_mermaid` (`graph_export.py:18`) walks `graph.nodes`/`node.edges` and emits a
`flowchart` in which **the arrow style encodes the routing mechanism**: solid `-->` for deterministic
`when` edges, dashed `-.->` for semantic edges (classified by `predicates.is_deterministic`), with
pill-shaped terminals. `--fenced` wraps it in a ```` ```mermaid ```` fence for direct paste; pure
string output, no dependency. The deterministic-vs-semantic distinction can be *shown* only because
each edge carries its condition as inspectable data. CLI: `prismpath graph <flow> [--direction TD|LR]
[--fenced]`.

### 8.3 OpenTelemetry export

Each node execution and each *semantic routing decision* becomes an OTel span, with scores and margins
as attributes, so a flow shows up in Grafana / Jaeger / Datadog with no custom dashboard. This is a
**library API, not a CLI subcommand** (`otel.py`): `span_records(graph, agent, sink, …)` wraps the
agent to emit a `prismpath.node` span-record per execution and, via the engine's `on_decision` hook, a
`prismpath.route` span-record per semantic decision carrying `mechanism, margin, top1, top2, chosen,
escalated`. These are OTel-*shaped dicts*, fully testable with no OpenTelemetry installed;
`to_otel_sink(tracer)` adapts them to real spans when the SDK is present. The `margin`/`escalated`
attributes exist *because* routing is a scored decision over embedded condition data; a branch inside
a Python callback produces no such attribute.

### 8.4 The LangGraph importer · `prismpath import`

Migration tooling as the adoption wedge, and the asymmetry demonstrated as a one-way street:
`import_langgraph` (`langgraph_import.py:46`) walks a LangGraph `StateGraph` **Python AST** (no
langgraph install needed); `add_node` → a `## node` with a TODO, `add_edge` → `-> b: when always`,
`START`/`set_entry_point` → the `start:`, `add_conditional_edges` → an edge per branch carrying a
`TODO write the condition (router returned '<key>')`. Fidelity is deliberately ~70%: the routing
*functions can't be translated*, which is the whole point; the import mechanically converts
everything already structural (nodes, edges, entry/exit) and marks the one thing that was
code-not-data (the routing callback) as the human's job to write in prose. The 70/30 split *is* the
code-vs-data boundary made visible. CLI: `prismpath import <py_file> [--name NAME] [--out PATH]`.

### 8.5 `prismpath label` · the routelog labeling workbench

Every semantic-tier decision a run makes can be appended to a JSONL log via the engine's
`on_decision` hook; outcome, candidate edges with scores, margin, chosen target, whether it escalated
(`routelog.run_logged`/`jsonl_sink`, `routelog.py:25,38`). `prismpath label <log.jsonl>` is the workbench
that turns those raw records into ground-truth training data: it prints each unlabeled decision's
outcome and numbered candidates (marking the router's own choice) and prompts for the correct edge.
The label format is deliberately identical to `prismpath test --emit-labels`, so tests and real runs feed
one calibration corpus (§4.7). You can only "label" a routing decision because it is a *record* with a
candidate set and a score; there is nothing to adjudicate about the execution of a Python `if`.

### 8.6 The portable subset · the auditable subset runs anywhere

A flow whose reachable edges are all decidable; `when` predicates, error edges, event edges; needs
**no ML runtime for its routing**. That boundary is now enforceable and demonstrated. `prismpath
portable <flow>` decides membership, listing the exact semantic edges that violate it and recursing
through `@spawn` children (a portable parent spawning a non-portable child is not portable). The
subset itself ships as **`prismpath/portable/prismpath.mjs`**: the parser, the predicate sandbox (a
hand rolled recursive-descent evaluator; no `eval`, the same allowed grammar as the Python AST
sandbox), and the engine loop (deterministic + error + event tiers, every suspension shape,
re-entry), in **one dependency free ES module** that runs unmodified in Node, a browser
`<script type="module">`, an edge function, or a network appliance; places a Python ML stack does
not go. `run()` *refuses* a non-portable flow rather than guess at a semantic edge. Two further
kernels have since been written against the same frozen vectors; **`prismpath-rs/`** (Rust; native
binaries and WASM) and **`prismpath-go/`** (Go; services and network appliances); each
dependency free in its own ecosystem, so the portable claim is now carried by three independent
implementations rather than one.

The load bearing engineering is fidelity, and it is **verified, not asserted**: a cross language
conformance suite replays identical flows and scripted worker outcomes through both engines and
requires identical paths, stop reasons, and pending nodes; deliberately torturing the sharp edges
of Python's predicate semantics that a naive port would miss (`True`/`False`/`None` are constants
while lowercase `true` is a *field name*; booleans compare numerically, so `flag == 1` matches
`flag: true`; a comparison against a missing field is *unsatisfied*, never a crash, except `not in`,
whose failure is *satisfied*; chained comparisons; substring `in`; `[]` and `{}` are falsy). A
differential fuzzer over both evaluators backs the suite.

The scope note this section used to carry; that locked *semantic* routing could not live in the
port, because the outcome side of a semantic decision still needs a runtime embedder; has since
been closed rather than argued away. The ports now implement the **P1 tier**: pass a parsed lockfile
and a caller-supplied `embed(text)` callback and the kernel routes against the committed condition
vectors itself, with `human_floor` escalation, staying dependency free because the *embedder is the
caller's*; an ONNX/transformers.js encoder in a browser, a native model in a Rust host, nothing at
all in a P0 deployment. A separate frozen fixture set (`locked_flows.json`) certifies that tier
independently. What remains genuinely outside the ports is *unlocked* semantic routing, which needs
live condition embedding and the LLM escalation path. The flow that motivates the feature was
already inside the boundary: the production SOC triage flow's routing is fully decidable;
the LLM lives in the *workers*, which the host supplies in any language.

**The fragment is now machine-recognized; and machine checked.** SPEC §4.3's match action
fragment stopped being a prose definition: `prismpath verify --level-m` classifies every
deterministic edge as in fragment or out (with a stable reason code; field-vs-field, substring
membership, string ordering, float constant; chained comparisons are normalized into the fragment,
not reported out), and `portability_tier()` reports Level-M
membership for the whole flow alongside P0/P1/P2. The same recognizer powers **bounded model
checking**: `prismpath verify --reach NODE --forbid NODE --assume "<expr>"` searches the reachable
state space under the engine's real first-match semantics, returning a concrete witness outcome for
a reachable node and a *proof for all bounds* for an unreachable one (per node `visits` counters are
modeled with saturation, so the search terminates on a finite state space rather than a depth cut).
Satisfiability is decided by enumerating candidate outcomes against the **actual predicate
evaluator**, so the checker cannot drift from the engine the way a re-implemented decision procedure
would. Outside the fragment it over-approximates deliberately; semantic, error, and event hops are
*may*-takeable; which keeps UNREACHABLE sound while labeling optimistic witnesses honestly.

**The deterministic tier is synthesizable; and now synthesized (delivered, measured).** A
predicate in that same match action
fragment (field-vs-constant comparisons, constant-set membership, boolean combinators, the
`visits`/`error_count` counters) is not *like* hardware; it is the abstract description of one: each atom is a `(field-selector, operator, constant)` row, a node's ordered
deterministic edges are a priority encoder, and the counters are registers. As of August 2026
that argument is an artifact ([`prismpath-hw/`](../../prismpath-hw/README.md),
evidence rows #72 to #76): a Level M flow compiles to a binary table image; the production SOC flow
`wazuh_triage`, unmodified, is **302 bytes**; `incident_severity` is **136**: interpreted by
**one fixed circuit** on a Zynq-7020, never re-synthesized per flow. The promised certification
pattern held exactly: the same frozen conformance vectors that certify the software kernels became
the hardware test bench, **on a declared subset, stated plainly**: the C target passes 124/1,079
predicate + 6/27 engine vectors and the RTL 114/1,067 (its re-sweep to 124/1,079 for the negative integer
literals, #89, is pending a hardware retest), each with zero divergence and a
machine readable reason for every exclusion (this is the portability-tier pattern one level down, *not* full SPEC §8
conformance), and the RTL reproduced 7,436 live sensor samples bit for bit against the C target.
The promised hash-chain attestation is **partially delivered**: the table-image and bitstream
hashes are published and OpenTimestamps-anchored in `prismpath-hw/evidence/`; chaining the
routing-lockfile hash into that same attestation remains open, as does the P4 emitter; the XDP/eBPF
emitter, open when this was written, shipped in August 2026 as a verifier accepted in kernel program
certified on the same declared subset (ledger rows #77 to #80; re certified at 124/1,079,
both architectures; #90). The substrate ladder has since reached its floor: the same signed table
images are decided by an **8-bit ATmega328P** (Arduino Uno R3, 16 MHz, 2 KB RAM), a 1,720-byte
evaluator matching the reference **124/124** byte for byte (predicate/single-hop, #92); and the kernel
swap is now **double buffered**: a single word atomic bank flip proven torn-free under a concurrent
swap storm on both architectures (#93). Three further MCU instruction sets then joined the floor tier:
**ARM Cortex-M33 and RISC-V Hazard3**, both cores of one RP2350 die built from one source file (124/124
each, #97), and **Xtensa LX6** on an ESP32 (124/124, #98). Four MCU ISAs now decide the same signed
policy identically, on top of the language kernels, the in kernel eBPF target, and the FPGA fabric: the
portability claim is no longer "the table runs everywhere we ported it" but "one signed table, byte
identical decisions across every instruction set we can put it on." Two demonstrators ride that
substrate and earn one sentence each: an RP2350 reads a real VL53L0X time of flight sensor over I2C and
routes a signed proximity policy on device, the band flipping exactly at the authored thresholds (#99);
and three ESP32s perform a coordinated fleet policy swap over ESP-NOW, each node re verifying the
received table before staging it, committed in two phases, the whole fleet flipping within 0.7 ms
(#100). The fleet then grew a decision of its own: three nodes each sensing one channel converge on
one fused Level M posture, stay fail operational under node loss and a 99% interference blackout
(never silent; a stale sensor reads a sentinel band the same signed table escalates or degrades on),
and hot swap the fusion rule itself with the scene held physically constant, the fleet moving
CRITICAL to WARN because the rule changed and the world did not (#101); and the fleet swap is now
gated on device by an Ed25519 signature with a persisted anti rollback version floor that survived a
true power cycle and refused a replay (#102).
The routing spectrum's **physical latency hierarchy** is no longer a projection but a
measurement: the fabric answers a deterministic routing decision in **5 to 21 cycles; a provable
100 to 420 ns worst case** at the shipped 50 MHz clock, in 1,064 LUTs (2.0% of the part); the CPU
beside it (Linux, Python, and a network hop included) turned live sensor fields into fabric
decisions at 89/96/202 µs min/median/max on the bench; LLM escalation and the human queue live
upstream in seconds; the margin and floor thresholds stop being software parameters and become
decisions about *where computation physically happens*. Confidence routes the work itself. None
of this required new authoring machinery; the fragment was pinned in the spec and vectors
precisely so the compile chain could be built against a frozen target, and it was.

Several further capabilities have since landed on the same decidable base. **The decision fusion plane**
(`adapters/fusion/`, August 2026) joins any N decision sources into one Level M table; its v1 worked
example tessellates a cyber triage verdict and a live IMU's physical posture, and measures the fused
decision wire on the whole real triage backlog; ~1.5
bytes per alert with its integrity apparatus (Merkle roots, epoch chaining, ACK channel) counted, run
end to end on the live rig; where the high value coincident bands stay honestly empty. That decision
wire is now a named, normatively specified protocol: **Facet** (`Facet/1`), carrying **Figueroa
quantized** symbols whose codebook is agreed from the shared signed policy rather than transmitted; the
specification is [`PROTOCOL.md`](../../PROTOCOL.md) and the companion paper is
[`paper-facet-figueroa-quantization.md`](paper-facet-figueroa-quantization.md), which measures the wire
against OTLP, the industry standard telemetry protocol: 1.516 bytes per decision with the integrity
apparatus counted, 66.9× under OTLP protobuf and 4.7× under zstd compressed batched OTLP (#95's
originally recorded 67.6×/4.8× divided by the payload only O1; the bench now emits exact ratios). The
wire now ships beyond the reference: the `prismpath-rs` and `prismpath-telemetry-rs` crates are on
crates.io, a Facet codec compiled into Vector round trips routed decisions byte identical to the
reference over the frozen corpus at a measured 2.000 bytes per event (#103), and the adoption path is
tooled end to end (a preflight that reports what the codec will do on a user's own events, in Python
and as the `facet-preflight` crate; a drafter that transcribes an existing Vector config into a
policy flow, the tool drafting and the author signing; and a canary recipe whose verifier proved
route parity on live traffic before cutover). **Secure signed
policy hot swap** (`prismpath/policy_pack.py` + `policy_host.py`, published as prior art in
`docs/design/spec-secure-hotswap.md`, August 2026) replaces a running Level M policy only when the pack is
Ed25519 authorized, inside a signed envelope, monotonically versioned, atomically applied, and audited to
a Merkle rooted ledger; the same gate fronting the kernel eBPF `netupdate` as a host-side pre loader.
**Context attestation** (`prismpath/context_ledger.py`, mirrored in the Rust kernel, August 2026) makes
what a frozen model was conditioned on checkable: an append only, hash chained, Merkle rooted ledger of
context segments (salted for low entropy text, content never stored) bound into the standard provenance
manifest; the context is the only mutable state a frozen model has, so it is the governance surface.
**Provable crypto-agility** (`prismpath/crypto_agility.py` + `crypto_host.py`, prior art in
`docs/design/spec-crypto-agility.md`, August 2026) applies the same governor to the choice of
*cryptographic suite*: a suite-selection policy is a Level M flow whose terminals are the approved
suites, and five machine checked proofs establish that no reachable state selects an unapproved or
below-floor suite and none downgrades past a migration phase (algorithm-level anti-rollback, proven
statically); the runtime refuses a swap whose declared suite's provider is unavailable rather than
weakening it, delegating every cryptographic operation to a vetted provider; a control plane, not a
cipher.
Ledger rows #82 to #103.

---

## 9. The control plane · sprints, and gates as the definition of done

Above the kernel, prismpath drives **spec driven feature sprints** against a local agent swarm. The
control plane is a **fixed loop**, and its contribution is that loop; the gate as the definition of
done, the durable state (the Flow-Ledger of §5, the last-good snapshot), and the human in the loop
escalation; all of which are **agent- and strategy-agnostic**: the engine is independent of who runs
the work (`engine.py`), and none of the durable machinery knows *which* strategy chose the unit:

```
human intent → spec → sprint loop:
   a next-step strategy picks one unit of work → executor diff-edits the REAL tree →
   GATE (compiles? types? builds? tests? WIRED? reachable?) → green: next / red ×3: escalate
         ▲ the strategy is pluggable (kg | spec); the rest of the loop is fixed
```

- **Gates are the machine enforced definition of done; the key discovery.** A build is not green
  until it compiles, type-checks, builds, passes tests, *and is wired into a composition root and
  reachable by the user.* The rule that falls out: **"never write a completeness claim a gate doesn't
  enforce."** Dead code, an unbuilt UI, an unreachable feature, a stale contract; each becomes a
  gate, not a thing you remember to check. Gates are pluggable per target (the built-in browser gate: syntax →
  imports resolve → DOM element exists → headless click changes the DOM; any other target loads a
  gate plugin behind the same `validate(proj)` interface).
- **Two next-step strategies plug into the one loop, determinism-first** (the loop, gate, and
  escalation are identical across both; only the choice of *what to build next* differs, a strategy
  dispatch in `run_sprint.py`):
  1. `kg` (**the default, and what prismpath was built for**): **one structured spec** whose `##` are
     requirements, `### Contract` the binding interface, `### Definition of done` the gate-checkable
     target. The agent seeds a **knowledge graph from the spec itself** (authored, so deterministic),
     builds exactly one node per pass (the first `pending` whose `depends_on` are all `done`), and
     records each node's `produces`/`exports` so later steps *read* the graph instead of re-deriving
     context, which is what stops a step from re-inventing a module an earlier step already built.
  2. `spec`; build a flat ordered list of modules, each from its embedded spec: the same determinism
     without the dependency graph.

  (A former `council` expansion strategy, game-dev in origin, once let the swarm propose and vote on
  net-new subsystems; it has since been removed, and because it was load bearing for none of the
  control-plane guarantees above, removing it left them intact.)
- **The auditor (advisory):** an idle-time small-model judge that checks each build against a
  canonical `GLOSSARY.md` for contract drift. Nearly free (runs on the otherwise-idle coder model);
  advisory by default because an LLM judge is fuzzy; it surfaces drift a human or a deterministic
  grep confirms.

**The loop is now itself a flow (dogfood).** The fixed Python loop above has a document twin:
`flows/sprint_loop.md` expresses the same control structure as edges; the gate routes on a
deterministic field (`when gate_green`), the **3×-same-error rule is an edge**
(`-> fix: on error when error_count < 3`, then `-> escalate: on error`), escalation is an ordinary
`needs_human` suspension carrying the evidence for a supervisor, a `visits` cap bounds the fix loop,
and every gate green unit is a `@checkpoint` **proof-commit** in the Flow-Ledger, so a restarted
sprint resumes at the first unproven unit. The concrete work (pick/build/gate/fix/escalate) plugs in
as a seam bundle (`sprint_flow.py`); `run_sprint.py` wires its own machinery behind `SPRINT_FLOW=1`,
keeping only the harness concerns (wall clock, pause, heartbeat) in the driver; where harness
concerns belong. The control plane that builds PrismPath is driven by a PrismPath flow: `prismpath validate`
compiles the sprint loop itself, which is the credibility argument in its most literal form.

---

## 10. Operational lessons (hard-won, and the most useful part for practitioners)

These come from running prismpath against a real local-model swarm on a workstation:

- **Lean the decision-step context** (a general lesson, first surfaced in an earlier multi-agent
  strategy). A 14 KB prompt across several sequential agent dispatches makes an ~80 s round that
  *looks hung*. Pass only what the decision needs, for ~5 s dispatches. Long context is not free and not
  neutral; this holds for any fan out of agent calls per unit of work.
- **Cap retries to the build's cost, or a fixable RED becomes an infinite spin.** `max-reflections 5`
  × a slow large-context build = a ~20-min timeout *per iteration*; if the RED is one the model can't
  self-fix, every iteration burns the full budget → times out → restarts → spins for hours. Fail
  *fast* (reflections ≈ 3) and let a **3×-same-error detector escalate to a human** who hand-fixes
  the one hard edit. Retry budget must be **< timeout ÷ per-attempt cost**, with margin.
- **Diagnose before you restart the model server.** Hours of load *can* clog a server (orphaned long
  generations starve throughput on unified memory); but a fresh 16-token probe returning in ~2 s
  means the server is FINE and the slowness is elsewhere (build size, retry count). Don't cargo-cult
  the restart.
- **Parallel spec authors DRIFT; author a shared glossary first.** Fanning out one agent per module
  spec is fast, but each independently invents names for *cross-references* (`ValueKey` vs `ValueId`,
  `EnemyDef` vs `EnemyDefinition`, scalar-vs-array `damageMultiplier`). 10 specs → ~15 hard mismatches,
  each a build failure. **Fix:** author a `GLOSSARY.md` of canonical shared types/signatures first,
  pass it to every spec agent as ground truth, reconcile with a consistency pass. Drift is then caught
  at the **Markdown layer (≈ free)** instead of as broken code (a stuck swarm). The glossary is
  authored in *passes*, and the last mile is the human's; LLM conformance passes asymptote (4
  residuals → 3 → …); close with a **deterministic grep sweep** for known anti-patterns.
- **Embed the spec, don't name it.** "Implement per specs/Elements.md" fails; a coder model handed a
  filename misfires a `read_file` tool call and *wings it*. Paste the full spec + glossary text into
  the build instruction.
- **Tasking a small (7B) model as a judge takes four specific moves:** (1) kill the tool instinct
  explicitly ("you have NO tools; the content is pasted below"); (2) scope to contract-surface
  (audit only exported types / glossary calls / glossary fields; ignore local names); (3) few-shot
  with **both** a flag and an ignore; (4) a deterministic post-filter to strip the model's nonsense
  self-flags. Short persona beats a wall of rules; long rule-piles degrade small-model adherence.
- **Oversized auto-refactor is a footgun.** Inlining a whole file into one dispatch to "split" it
  hangs and corrupts mid-feature. Make size a *soft, advisory* signal; do structure work deliberately
  on a green build.

The meta-lesson: **push correctness to the cheapest layer that can enforce it**: a `when` predicate
over an LLM route, a glossary over vigilance, a deterministic grep over a third fuzzy LLM pass, a
gate over a prose claim.

---

## 11. When to use it · and when not

**Use prismpath when:** the *process* is owned by non-engineers or must be reviewable/auditable; many
transitions are cheap logic that shouldn't cost an LLM call; you want determinism where you can get
it and graceful semantic routing where you can't; you're extending a base rather than generating from
blank slate.

**Reach for something else when:** the control flow is trivial (one prompt, no branching; just call
the model); you need hard real time guarantees per step; or the "graph" is really a data pipeline
better served by a durable-workflow engine with typed gateways only (no semantic tier needed).

**Known gaps / threats (named honestly).** Objections we name here rather than paper over. The
first two arrived open and are now delivered/closed; the last two are standing objections with
partial answers:

- **Field-only routing mode; DELIVERED** (kept here because it originated as this list's
  highest-value open item). The concern: semantic and predicate routing can be influenced by raw
  upstream worker *prose*, which in an adversarial setting may be attacker-influenced
  (prompt-injection through content flowing between nodes). The delivered machinery: a node
  *declares* its emitted fields (`@emits(...)`, optionally typed) and may be marked `@field_only`;
  the static analyzer (§7.1) enforces the provenance boundary decidably; a `when` edge reading an
  undeclared field is flagged (`undeclared-field`), a typed declaration contradicting the
  predicates is flagged (`emits-type-mismatch`), and a `@field_only` node carrying a *semantic*
  edge (which routes on raw text by definition) is a compile-time **error**
  (`field-only-violation`). Exactly as predicted, the data-not-code design made it a static check
  rather than a runtime hope. Honest residual: enforcement is opt-in per node; unannotated nodes
  retain the old exposure; and the transcript itself still flows to *workers* (the boundary
  governs routing, not worker inputs).
- **Unbounded state growth; CLOSED (`@state_bound`).** The run state used to accumulate without
  bound: `state["transcript"]` appends per step, and a resume re-seeds the full path/step history,
  all serialized into every checkpoint (§5). A flow may now declare `@state_bound(transcript=N)`
  (flow-scoped, any node): the engine sliding-windows the transcript on append and the re-seeded
  history on resume, so the checkpoint payload stays **flat across unlimited resumes**: the test
  suite pins both arms (strictly-growing without the bound, constant with it). Drops are counted
  deterministically in `_state_dropped` (the engine stays pure; no model-summarized tail), and the
  window cannot change a routing decision by construction: predicates read fields plus the per node
  `visits`/`error_count` counters, which are never trimmed; `_outcomes` is last-write-per-node and
  bounded by node count already. Residual caveats: opt-in per flow (default remains unbounded), and
  a malformed bound fails loudly at run start rather than silently not binding.

- **"Structured output obsoletes the semantic tier"; partially conceded, and the concession is
  the design.** Where a worker can emit a clean enum, `@emits` + `when` is strictly better than
  semantic routing, and the tooling pushes authors there (the polarity lint's prescription; the
  production SOC flow is P0). The standing rebuttal is twofold. First, schema-classification
  *relocates* the semantic judgment inside the model; the enum-mapping is the same fuzzy decision,
  made where nothing measures it; and deletes the confidence signal: there is no margin to
  threshold, so risk controlled abstention (§4.7) is not constructible over structured outputs;
  self-reported `"confidence"` fields are not calibrated quantities. Second, the semantic tier
  serves workers that are not promptable LLMs at all; the CLI-worker contract routes on stdout,
  and a human's or legacy script's output carries no schema. Honest residual: for
  LLM-worker-only flows with enumerable outcomes, the semantic tier is legitimately optional, and
  the head to head should grow a fourth arm (idiomatic structured-output LangGraph) to measure
  exactly this; a result we commit to publishing whichever way it lands.
- **"The innocent diff": a one-word semantic edit hides its behavioral shift in embedding
  geometry.** True, and worth stating at full strength: the most dangerous class of change
  produces the most innocent-looking `git diff`. Two responses. This is every semantic system's
  problem (the same one-word drift in a routing prompt has no tripwire anywhere) and here it has
  three: `prismpath lock --check` fails CI until the moved condition vectors are deliberately
  re-locked (the wording change cannot merge alone), the flow's fixture table re runs modelless
  and names any flipped routing case, and `--emit-labels` re-scores the edit against labeled
  history before merge. Review therefore targets pinned consequences, not geometry. Honest
  residual: the tripwires bound *detection*, not *legibility*; no tool renders what a wording
  change means in embedding space, and a fixture table only guards the cases it contains.

**Novelty caveats (stated before a reviewer states them).** Two ideas here have clear prior art, and
we scope the actual contribution narrowly:

- **The error and event tiers are individually old.** BPMN has had deterministic gateways, error
  boundary events, *and* timer events for years. What is new is not any one tier but the
  **composition**: a **semantic tier over a probabilistic worker's natural language outcome**,
  sitting beside the deterministic/error/event tiers, in **one plaintext line a non-engineer can
  author**, with the condition string as the *sole* tier selector.
- **Semantic caching is old** (GPTCache and kin): cited in §4.8. The prefilter's novel parts are the
  **two-threshold gate** (similarity = same-situation, stored confidence = was-the-prior-verdict-
  trustworthy), the **explicit scoping** (embed stable fields, exclude volatile context), and the
  deployment **finding** that memoizing the *worker* dominates memoizing the *transition*.

**Status (honest).** The flow kernel (parser, four-tier router, safe predicates, engine) is solid
with a passing test suite; durable checkpoints/resume, the Flow-Ledger, the lockfile, the static
analyzer + broken-flow corpus, `prismpath test`/`graph`/`import`/`label`/`calibrate`/`verify`/`lsp`,
the sprint loop, the browser gate, the safety guard with its pre registered bypass measurement, the
Connector SDK behind which both reference adapters run, and Mission Control observability (the
human-queue view and the live fan out composition trees) all work. The portable subset is carried by
three independently written kernels (JavaScript, Rust, Go), each passing every conformance vector.
It's an active research control plane extracted from a real build, not a packaged release; several
root scripts are experiments, and the supported entry points are `cli.py`, `run_sprint.py`,
`engine.py`, `mission_control.py`.

> **Note.** Design review and adversarial critique of this work were conducted with an AI assistant
> (Claude), consistent with venue AI-disclosure policy.

---

## Appendix A · API & CLI quick reference

> **Convention.** `pip install prismpath` provides the `prismpath` console command used throughout this
> paper (from a source checkout, `pip install -e .`); it is the `console_scripts` entry point
> `prismpath = prismpath.cli:main` declared in `pyproject.toml`, dispatching `cli.py`'s argparse subcommands
> (`run`, `lint`, `validate`, `verify`, `lsp`, `resume`, `lock`, `import`, `calibrate`, `graph`,
> `label`, `test`, `portable`, `compose`, `plugins`, `ci-report`, `init`, `ledger`).
> Without installing, every command runs equivalently as `python -m prismpath.cli <cmd>`.

```python
from prismpath.parser import parse_file
from prismpath.engine import run
from prismpath.router import HybridRouter, LLMRouter
from prismpath.prefilter import PrefilterCache

graph = parse_file("flows/bugfix.md")
router = HybridRouter(LLMRouter(generate_fn), margin=0.05)   # embed-first, LLM-on-doubt
result = run(graph, agent, router=router, human_floor=None)  # agent: (node, instr, state) -> str|dict
                                                             # human_floor (opt-in, default None): suspend
                                                             # as needs_human below this score (§5.1)
print(result.path, result.stopped)                            # e.g. ['triage','implement','review','done'] 'terminal'

cache = PrefilterCache("corpus/", threshold=0.97, min_conf=0.8)   # verdict memoization (§4.8)
res = cache.lookup(document)                                  # res.hit -> reuse res.record["action"]
cache.learn(res.vector, action, confidence, key=..., description=...)   # miss -> adjudicate, learn

# Durable execution (§5)
from prismpath import checkpoint
checkpoint.run_durable("flows/bugfix.md", agent, "run.ckpt", router=router)  # checkpoint every step
checkpoint.resume("run.ckpt", agent, choose="implement")     # apply a human's edge (needs_human)
checkpoint.resume("run.ckpt", agent, event="approved")       # deliver an event (waiting)

# Reproducible / calibrated routing (§4.6 / §4.7)
from prismpath.lockfile import locked_router
from prismpath.calibrate import RiskControlledHybridRouter   # HybridRouter at a calibrated τ
                                                          # (ConformalHybridRouter = back-compat alias)

# The Flow-Ledger (§5.2)
from prismpath.ledger import Ledger
Ledger(flow, run_id).commit_unit(unit, gate="green", files={f"{unit}.proof": b"..."})  # proof-commit
```

```bash
prismpath validate  flows/bugfix.md          # static analysis: does the flow compile? (--json for CI)
prismpath lint      flows/bugfix.md          # validate + semantic-ambiguity + polarity-mirror (--json)
prismpath run       flows/bugfix.md          # trace the path with a mock agent
prismpath test      flows/bugfix.md [--json] [--emit-labels labels.jsonl]  # fixtures-as-data (no LLM)
prismpath lock      flows/bugfix.md [--check] # write/verify the routing lockfile (§4.6)
prismpath calibrate labels.jsonl [--alpha 0.05] [--out cal.json]           # derive τ (§4.7)
prismpath graph     flows/bugfix.md [--direction TD|LR] [--fenced]         # Mermaid render (§8.2)
prismpath import    graph.py [--name NAME] [--out flow.md]                 # LangGraph → skeleton (§8.4)
prismpath label     labels.jsonl             # hand-label routing decisions (§8.5)
prismpath resume    run.ckpt [--choose <edge>]   # resume a suspended/crashed run (§5.1)
```
*(OTel export is a library API only; `prismpath.otel.span_records` / `to_otel_sink`; no CLI subcommand.
`resume --choose` is the only resume flag in the CLI; `event=`-resume and `run_durable` are library
calls.)*

## Appendix B · Key environment knobs
- `EMBED_MODEL` (default `BAAI/bge-base-en-v1.5`), `EMBED_DEVICE` (default `cpu`).
- `HybridRouter(margin=δ)`; the accuracy/LLM-rate dial (default 0.05; the re-derived frontier is smooth, so prefer a calibrated τ); the
  risk controlled τ of §4.7 is the calibrated alternative (`RiskControlledHybridRouter`).
- `run(..., human_floor=None)`; an **opt-in** absolute-confidence floor (a `run()` parameter, default
  `None`): a semantic/`single` route scoring below it suspends as `needs_human` instead of guessing.
  Checked **only when the router did not escalate** (§5.1).
- `PREFILTER_THRESHOLD` (default 0.97), `PREFILTER_MIN_CONF` (default 0.8),
  `PREFILTER_EMBED_MODEL` (default `BAAI/bge-small-en-v1.5`), `PREFILTER_EMBED_DEVICE`
  (default `cuda`, CPU fallback); the prefilter cache (§4.8).
- `run(..., max_steps=25)`; runaway-loop bound.
- **Durable execution / lockfile (§5, §4.6):**
  - `prismpath_RESUME_ON_FLOW_CHANGE=refuse|warn|allow` (default **refuse**); resume-against-edited-flow
    policy (`checkpoint.py:104`).
  - `prismpath_QUEUE_DIR`; where `needs_human` checkpoints wait for a human (default
    `$XDG_STATE_HOME/prismpath/queue`).
  - `prismpath_LEDGER_DIR`; where the git Flow-Ledger bare repos live (default `$XDG_STATE_HOME/prismpath`).
  - `prismpath_LOCK_POLICY=refuse|warn|allow` (default **refuse**); embedder-drift policy for the
    lockfile (`lockfile.py:127`); note the `LOCK_COSINE_MIN = 0.9999` false-refuse caveat of §4.6
    (use `warn` on a mixed torch/ONNX/CPU to GPU fleet).
- Sprint modes (§9): `SPRINT_SPEC_DIR`+`SPRINT_SPEC_ORDER` (flat `spec` mode), `SPRINT_SPEC_FILE`
  (structured `kg` mode), `SPRINT_AGENT=swarm` (multi-agent swarm backend), `SPRINT_LEDGER=1`
  (opt-in git Flow-Ledger of gate green proofs; `SPRINT_LEDGER_RUN=<id>` resumes a prior run's ref),
  `SPRINT_GATE=<target>`, `SPRINT_AUDIT=1` (auditor), `SPRINT_AGY=1` (frontier auto-unblock).
