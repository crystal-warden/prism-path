# Decoder Ring

**Every borrowed term in this project, in plain language, with a pointer to where it lives.**

The papers use vocabulary borrowed from statistics, formal methods, and distributed systems. Most of
it names an idea that is simpler than the term suggests; the term exists so specialists can be
precise with each other, not because the idea is hard. This file is the translation layer, and
doubles as a map of the repo: if you want to know where something *is*, [Part 3](#part-3--the-map)
lists it.

Three parts:

- **[Part 1 · The ideas that unlock the rest](#part-1--the-ideas-that-unlock-the-rest)**: eleven
  concepts, explained properly. Read these and the papers stop being opaque.
- **[Part 2 · Glossary](#part-2--glossary)**: A to Z, one or two sentences each.
- **[Part 3 · The map](#part-3--the-map)**: where every document, module, kernel, and command lives.
- **[Part 4 · Reading paths](#part-4--reading-paths)**: "I want to understand X" → read these, in
  this order.

---

## Part 1 · The ideas that unlock the rest

### 1. Embeddings, cosine similarity, and the margin

An **embedding** turns a piece of text into a list of numbers (a vector); roughly 768 of them, for
the model this project uses. Texts that mean similar things get similar vectors. **Cosine
similarity** measures how similar two vectors are on a scale where 1.0 means "pointing the same
direction" and 0.0 means "unrelated."

Semantic routing is just this: embed the worker's outcome, embed each edge's condition, pick the
edge with the highest cosine. The score is a similarity, not a probability; 0.65 does not mean 65%
confident.

The **margin** is the gap between the best and second-best score. If the top edge scores 0.61 and
the runner-up scores 0.59, the margin is 0.02 and the router is effectively guessing between two
options. If the top scores 0.71 and the next 0.44, the margin is 0.27 and the decision is clear.
The margin (not the raw score) is what the system uses to decide whether it needs help.

**Why it matters here:** the margin is the cheap confidence signal that makes everything else
possible. Where it lives: [`embedder.py`](../prismpath/embedder.py), [`router.py`](../prismpath/router.py).

### 2. The routing spectrum, and the four tiers

The central claim. A workflow's "which way do I go next?" decisions are not all the same kind of
question, so they should not all be answered by the same machinery.

| tier | written as | resolved by | cost |
|---|---|---|---|
| **deterministic** | `-> review: when tests_passed` | evaluating an expression | free, exact |
| **semantic** | `-> triage: the change is risky` | embedding similarity | ~free, approximate |
| **error** | `-> retry: on error when timeout` | the worker raised | free, exact |
| **event** | `-> escalate: on timeout` | an outside signal arrived | free, exact |

You do not pick the tier. The engine picks it from the *shape of the condition string*; `when …`
is deterministic, `on error …` is an error edge, `on event …`/`on timeout` is an event edge, and
anything else is semantic. That is why all four fit in one plaintext file a non-engineer can read.

**The empirical argument for having a spectrum at all** is the polarity result (§4.2 of the research
paper): embeddings score 0.81 where the distinction is one of *topic*, but 0.52 (near coin flip)
where it is one of *logic* ("all tests pass" vs "three tests fail" are topically almost identical).
Logic is exactly what a `when` predicate does perfectly and for free. Neither tier is sufficient
alone; the finding is the argument for composing them.

Where it lives: [`parser.py`](../prismpath/parser.py) (tier classification),
[`engine.py`](../prismpath/engine.py) (routing), [SPEC.md](../SPEC.md) (normative rules),
[authoring guide](guides/authoring.md).

### 3. Escalation, abstention, and "selective classification"

**Selective classification** is a classifier that is allowed to say "I don't know" instead of
guessing. Declining to answer is called **abstention**. There is a whole literature on it, because
a model that abstains on its worst 10% and is right on the rest is often more useful than one that
guesses everywhere.

This project's version: when the embedding margin is below a threshold, the router *abstains* and
hands the decision to an LLM. That is all "LLM-on-doubt escalation" means. Abstaining costs money
and latency instead of accuracy, which is why the threshold matters.

Two symbols get used for that threshold and they are **not** the same thing:

- **δ (delta)**: a threshold you *chose by hand*. "Escalate when the margin is under 0.05."
- **τ (tau)**: a threshold that was *derived from labeled data with a guarantee attached* (see
  idea 5). Same mechanism at runtime; the difference is entirely in where the number came from.

Where it lives: [`router.py`](../prismpath/router.py) (`HybridRouter`; the δ version),
[`calibrate.py`](../prismpath/calibrate.py) (`RiskControlledHybridRouter`; the τ version, which
subclasses it; the two differ only in where the threshold came from).

### 4. The Wilson score interval · why a lower bound, not an average

You test 40 routing decisions and 38 are correct. Is your accuracy 95%?

No. 95% is what you *observed*; the truth could easily be 85% and you got a good sample. A
**confidence interval** is the honest range. The **Wilson score interval** is a specific formula for
that range when you are measuring a proportion (successes out of trials). It is used instead of the
textbook normal approximation because the textbook version breaks down exactly where this project
operates; small samples, and proportions close to 0 or 1 (it will happily tell you accuracy is
104%).

The important habit is which *end* of the interval you use, and this project uses both, in opposite
directions, on purpose:

- **Lower bound** when a *high* number is the good news. Calibration certifies "accuracy is at
  least X"; so it takes the pessimistic end. Claiming less than you saw is what makes the claim
  survive contact with new data.
- **Upper bound** when a *low* number is the good news. Cache-reuse tuning certifies "error rate is
  at most Y"; so again it takes the pessimistic end, which is now the top of the range.

Both are the same discipline: state the worst case the data can't rule out.

Where it lives: [`calibrate.py`](../prismpath/calibrate.py) (`_wilson_lower`),
[`prefilter.py`](../prismpath/prefilter.py) (`_wilson_upper`).

### 5. Risk controlled calibration · and why it is *not* conformal prediction

The setup: you have a pile of labeled routing decisions, each with a margin and whether it was
right. You want to pick the threshold τ such that everything the router handles *without* escalating
is correct at least 95% of the time; and you want that to hold on future data, not just this pile.

The procedure: sort by margin, and for each candidate τ compute the Wilson **lower** bound on
accuracy among decisions above it. Take the smallest τ whose lower bound clears 95%. Smallest,
because a bigger τ escalates more and costs more; you want the cheapest threshold that still
earns the guarantee.

This is a single-knob instance of **Learn-Then-Test** / **Risk-Controlling Prediction Sets**
(Angelopoulos, Bates, et al.); a family of methods for tuning a parameter so a risk stays bounded
with high probability.

**It is not conformal prediction**, and the papers say so deliberately. Conformal prediction is a
sibling method that outputs a *set* of answers ("it's one of these three") calibrated so the true
answer is in the set 95% of the time, built from quantiles of a nonconformity score. This project
outputs one answer or abstains. The names get used interchangeably in casual writing, and a reviewer
who knows the difference would notice; hence the explicit disclaimer. The class
`ConformalHybridRouter` survives only as a back-compat alias for a name chosen before the
distinction was pinned down.

**The fail safe worth knowing:** if no threshold can meet the bound, calibration returns τ=None and
warns loudly; the router escalates *everything*, degrading to LLM-router cost rather than silently
shipping an uncertified threshold.

Where it lives: [`calibrate.py`](../prismpath/calibrate.py), `prismpath calibrate --alpha 0.05`.

### 6. Centroids, prototypes, and shrinkage

The zero shot semantic router compares an outcome against the *authored wording* of a condition. But
the author's phrasing may be a poor stand-in for what real outcomes on that edge actually look like.

A **centroid** is the average of a group of vectors; here, the average embedding of outcomes that
correctly routed down a given edge. Comparing against that average ("what do cases like this
actually look like?") beats comparing against the author's guess. In ML this is called
**prototype-based classification**.

The catch: with three examples, the average is noise. The fix is **shrinkage**: blend the observed
average toward a prior, weighted by how much evidence you have. Lots of history → trust the
centroid. No history → fall back entirely to the authored condition vector, i.e. the original
zero shot behavior. The **James-Stein** name attached to this comes from a famous 1961 result
showing that a shrunk estimator can beat the raw average, which is one of the more counterintuitive
facts in statistics.

Measured effect: overall routing 0.69 → 0.83, and on the polarity stratum 0.52 → 0.75. That second
number is the point; centroids repair the *confidently wrong* cases that a margin threshold can
never catch, because the router isn't hesitating on those.

Where it lives: [`centroid.py`](../prismpath/centroid.py), `prismpath centroids`.

### 7. Cohen's κ · agreement that isn't just luck

If two people label 100 items yes/no and agree on 80, that sounds good; until you notice that two
people answering "yes" at random would agree about half the time anyway. **Cohen's kappa (κ)**
subtracts out that chance agreement. 1.0 is perfect, 0.0 is no better than coincidence.

The conventional reading (Landis & Koch): >0.80 "almost perfect", 0.61 to 0.80 "substantial",
0.41 to 0.60 "moderate".

In the benchmark: a human blind-relabeled all 301 cases and hit **κ = 0.961** against the gold
labels. An independent model from a different family hit **κ = 0.682**.

**Read the caveat, because it's the load bearing part.** The 0.961 is one human (the author)
agreeing with labels produced by a process the author designed. That is a useful *sanity check* and
it is not **inter-annotator reliability**, which requires two independent people. The papers state
this in §4.1 and §6 rather than letting the number pass for more than it is. If you ever quote the
0.961, quote the caveat with it.

Where it lives: [`kappa.py`](../prismpath/kappa.py), [`annotate.py`](../prismpath/annotate.py),
`prismpath kappa`.

### 8. Cross-validation, leakage, and ablation

Three habits that turn "it worked" into "it will work."

**Five-fold cross-validation.** Split the data into five parts. Train on four, test on the held out
one, rotate five times, average. It stops you from reporting a score that just means the model
memorized the answers.

**Leakage** is when the test set is contaminated by the training set; the classic case being
near-duplicate items on both sides, so the model recognizes rather than generalizes. Since this
benchmark contains deliberately similar phrasings, a leakage audit was mandatory: the reported
max train to test cosine is 0.887, i.e. nothing is a near-copy.

**Ablation** is removing one ingredient to see whether it was doing the work. The centroid result
has one: swapping the embedding space alone (without learned prototypes) *hurts* by 0.03, which
establishes that the gain came from the prototypes and not from an incidental change.

Where it lives: [`prismpath/benchmark/`](../prismpath/benchmark/README.md).

### 9. Decidable, bounded model checking, and the match-action fragment

**Decidable** means an algorithm can always answer the question correctly in finite time. Many
questions about programs are *undecidable*; no algorithm can answer them for all inputs, ever
(Turing, 1936). "Will this loop terminate?" is the famous one.

"Can node X ever be reached?" is undecidable in general. But it becomes decidable if you restrict
the language enough; and this project restricts it deliberately.

The **match action fragment** (called **Level M** here) is that restriction, and the term is
borrowed from networking, where a switch is a table of *match on these fields → take this action*.
A predicate is in the fragment if it is a boolean combination of `field OP constant`, `field in
[literals]`, and bare field checks. No arbitrary computation. The state space of such a flow is
finite, so a checker can enumerate it exhaustively; that is **bounded model checking**: search all
reachable states and report what you find.

**The one-sided guarantee is the subtle part, and it is deliberate.** Semantic edges can't be
decided statically (they depend on an embedder and possibly an LLM) so the checker treats them as
*possibly* takeable. This is a **sound over-approximation**: it considers more paths than can really
happen. The consequence is an asymmetry you should internalize:

- **UNREACHABLE is trustworthy.** If the checker explored a superset of reality and never got there,
  you really can't get there. This is the direction a safety reviewer relies on.
- **A reported path might be fake.** It may cross an over-approximated hop, so it's labeled `may`
  rather than `certain`.

Which is itself an argument for writing safety-critical branches as `when` predicates: the more of
your flow lives in the fragment, the stronger an answer the tool can give you.

Where it lives: [`model_check.py`](../prismpath/model_check.py), `prismpath verify`, SPEC §4.3;
and, since August 2026, in FPGA fabric:
[`prismpath-hw/`](../prismpath-hw/README.md), the fragment's first hardware
target (declared-subset certified).

### 10. Hexagonal architecture (ports and adapters)

A way of organizing code so the core doesn't know what it's plugged into. The core defines
**ports**: interfaces it needs, written in its own vocabulary. The outside world provides
**adapters** that implement them. All dependencies point *inward*: the core never imports the
adapter.

The payoff is testability and reuse. The core is exercised with fake adapters and no network, and a
second use case is a new adapter rather than a fork.

Six ports here: Ingestion, Retrieval, Adjudicator, Action/Sink, Attestation, Deferral. Two adapters
prove the shape: [SOC alert triage](../adapters/soc/) and [compliance](../adapters/compliance/).

**How it's enforced rather than merely intended:** [`tools/arch_guard.py`](../tools/arch_guard.py)
scans the core for domain vocabulary. A word like `alert`, `SIEM`, or `learner` appearing in core
code is **Signal-1**, a hard failure; the tripwire for domain knowledge leaking inward. (This is
not theoretical: a docstring in `connector.py` once used "FPGA" and tripped it.)

Where it lives: [`connector.py`](../prismpath/connector.py) (the SDK),
[architecture](design/architecture.md), [adapter guide](../adapters/ADAPTER_GUIDE.md).

### 11. Content addressing, Merkle batching, and timestamping

**Content addressed** means a thing's name *is* the hash of its contents. Change one byte and the
name changes, so you cannot alter something while keeping its identity. Git works this way.

A **Merkle tree** hashes many items into pairs, then hashes the pairs, up to a single **root** hash
that commits to every item beneath it. The practical value is **batching**: timestamp the root
alone, and you have timestamped all thousand items under it.

**OpenTimestamps (OTS)** publishes such a root into the Bitcoin blockchain. Because rewriting
Bitcoin history is prohibitively expensive, this proves the data existed before that block,
without trusting anyone. **RFC-3161** is the older, offline-friendly alternative: a **Timestamp
Authority** signs "I saw this hash at this time." Cheap and air-gap-friendly, but only as
trustworthy as the authority.

Both ship here, at different strengths, and the docs never present the second as equal to the first.

Two more terms that show up around the ledger:

- **Compare-and-swap**: "update this only if it currently equals what I last read." Detects a
  concurrent writer instead of silently overwriting them.
- **Orphan ref**: a git branch with no shared history, a separate DAG in the same repository. The
  ledger lives on one so proof commits never touch your source history.

Where it lives: [`ledger.py`](../prismpath/ledger.py), [`ledger_ots.py`](../prismpath/ledger_ots.py),
[`ledger_airgap.py`](../prismpath/ledger_airgap.py),
[ledger spec](design/spec-ledger-opentimestamps.md).

---

## Part 2 · Glossary

**Ablation**: removing one component to prove it was responsible for the gain. See idea 8.

**Abstention**: a classifier declining to answer. Here: escalating to the LLM. See idea 3.

**Adapter**: an implementation of a port, holding all the domain-specific knowledge.
[SOC](../adapters/soc/) · [compliance](../adapters/compliance/) · [guide](../adapters/ADAPTER_GUIDE.md)

**Air-gapped**: a machine deliberately kept off any network. Drives the RFC-3161 ledger tier.
[`ledger_airgap.py`](../prismpath/ledger_airgap.py)

**Annotation**: a directive on a node: `@emits` (declares output fields), `@field_only` (routes
only on declared fields, never raw text), `@state_bound` (caps persisted state), `@spawn` (fan out).
[authoring guide](guides/authoring.md)

**Bounded model checking**: exhaustively searching a finite state space to answer a reachability
question. See idea 9. `prismpath verify`

**Centroid**: the average embedding of outcomes that correctly took an edge. See idea 6.

**Checkpoint**: an atomic JSON snapshot of a run, letting it resume after a crash or a human pause.
Resume is bound to a hash of the flow, so an edited flow can't silently resume into the wrong graph.
[`checkpoint.py`](../prismpath/checkpoint.py)

**Cohen's κ**: agreement between two labelers, corrected for chance. See idea 7.

**Compare-and-swap (CAS)**: conditional update that detects concurrent writers. See idea 11.

**Conformal prediction**: a method this project explicitly does **not** use. See idea 5.

**Conformance vectors**: 1,079 predicate cases + 27 engine flows that define correct behavior. Any
kernel claiming compatibility must pass all of them.
[vectors](../prismpath/portable/conformance/README.md)

**Content addressed**: named by the hash of its contents. See idea 11.

**Control plane / data plane**: borrowed from networking. The data plane does the work (running a
flow); the control plane decides what work happens and whether it's done (gates, sprints, ledger).
[architecture](design/architecture.md)

**Cosine similarity**: how aligned two vectors are, 0.0 to 1.0. See idea 1.

**Cross-validation**: rotating train/test splits. See idea 8.

**δ (delta)**: a hand-chosen escalation margin threshold. Contrast **τ**. See idea 3.

**Decidable**: always answerable by algorithm in finite time. See idea 9.

**Determinism**: same input, same output, every time. The deterministic tier is deterministic by
construction; the semantic tier is deterministic *given a lockfile*.

**Diagnostic codes**: what static analysis emits: `undefined-target`, `unreachable-node`,
`shadowed-edge`, `always-false-edge`, `unbounded-cycle`, `duplicate-condition`, `no-terminal`,
`unsafe-predicate`, `field-only-violation`, `undeclared-field`, `emits-type-mismatch`,
`not-portable-edge`, `spawn-no-join-edge`, and others.
[`analysis.py`](../prismpath/analysis.py) · `prismpath validate`

**Edge tier**: which mechanism resolves a transition. See idea 2.

**Embedding**: text as a vector of numbers. See idea 1.

**Escalation**: handing a low confidence decision to an LLM. See idea 3.

**Fan out**: one node spawning parallel children that rejoin. `@spawn`.
[`composer.py`](../prismpath/composer.py)

**Fingerprint**: a probe-cosine signature that detects whether the embedder changed under you. A
lockfile can *detect* embedder drift; it cannot repair it. See **lockfile**.

**Gates**: machine checks that define "done": compiles, type-checks, builds, tests pass, and the
code is reachable from a composition root. The operating rule is *never write a completeness claim a
gate doesn't enforce*. [`gates.py`](../prismpath/gates.py) · [framework](design/framework.md)

**Guard onion**: the layered safety floor: a deterministic policy layer inherited by every adapter.
Its grammar has **no verb for permitting**: a policy can only restrict, so layering cannot
accidentally widen permission. [spec](design/spec-guard-onion.md) ·
[`guard.py`](../prismpath/guard.py)

**Hexagonal architecture**: ports and adapters. See idea 10.

**Hybrid router**: embeddings first, LLM on low margin. See idea 3.
[`router.py`](../prismpath/router.py)

**Idempotent**: running it twice has the same effect as running it once. Required of sinks, so a
resumed run can't double-send.

**Inter-annotator agreement**: how much two independent labelers agree; the standard evidence that
labels mean something. See idea 7 and its caveat.

**James-Stein shrinkage**: blending a noisy estimate toward a prior. See idea 6.

**Kernel**: the minimal parse-and-route core. Four exist: Python (reference),
[JavaScript](../prismpath/portable/README.md), [Rust](../prismpath-rs/CONFORMANCE.md),
[Go](../prismpath-go/README.md). All four pass all vectors.

**Leakage**: test data contaminated by training data. See idea 8.

**Learn-Then-Test (LTT)**: the framework behind risk controlled calibration. See idea 5.

**Level M**: the match action fragment; the decidable heart of the predicate language. See
idea 9. Now has a first hardware target; a fixed FPGA interpreter circuit, certified on a
declared subset of the frozen vectors
([`prismpath-hw/`](../prismpath-hw/README.md)).

**Lockfile**: committed embeddings for every semantic condition, so semantic routing is
reproducible bit for bit across machines. Promotes a flow from P2 to P1.
[`lockfile.py`](../prismpath/lockfile.py) · `prismpath lock`

**Margin**: gap between the top-1 and top-2 similarity; the confidence signal. See idea 1.

**Match-action**: see **Level M** and idea 9.

**Merkle tree / root**: hash tree enabling batched timestamping. See idea 11.

**Monotonic**: only ever moves one direction. The guard's policy grammar is monotonic in the
restrictive direction.

**Nudges**: prompt assets read at runtime by the control plane. Program data, not documentation.
[`prismpath/nudges/`](../prismpath/nudges/)

**Orphan ref**: a git ref with no shared history. See idea 11.

**OpenTelemetry (OTel)**: the vendor-neutral standard for traces. Routing decisions are emitted as
spans into whatever observability stack you already run. [`otel.py`](../prismpath/otel.py)

**OpenTimestamps (OTS)**: trustless timestamping via Bitcoin. See idea 11.

**P0 / P1 / P2**: portability levels. **P0**: every reachable edge is decidable, zero ML, runs
anywhere. **P1**: semantic edges exist but all are pinned in a lockfile. **P2**: needs the full
Python engine (live embedding and/or LLM escalation). `prismpath lock` promotes P2→P1; rewriting
edges as predicates promotes to P0. [portable kernel](../prismpath/portable/README.md)

**Polarity**: logical opposites that are topically near identical ("all tests pass" / "three tests
fail"). The stratum where embeddings collapse to 0.52. See idea 2.

**Polarity lint**: an authoring time warning for sibling semantic conditions that look like a
polarity trap, advising you demote them to `when` predicates. [`lint.py`](../prismpath/lint.py)

**Port**: an interface the core owns. Six of them. See idea 10.

**Prefilter cache**: reuse a prior LLM verdict when a new input is embedding-near a past one *and*
that verdict was confident. Two thresholds, because similarity asks "same situation?" and stored
confidence asks "was the old answer any good?". [`prefilter.py`](../prismpath/prefilter.py)

**Projection over a log**: deriving current state by replaying an append only history rather than
storing a status field. "Which units are done" is a projection over `git log`.

**Prototype classification**: classifying by nearest prototype. See idea 6.

**RFC-3161**: timestamps signed by a trusted authority; air gap friendly, weaker than Bitcoin. See
idea 11.

**Risk controlled**: a parameter tuned so a risk is provably bounded. See idea 5.

**Routing spectrum**: the core thesis. See idea 2.

**Selective classification**: a classifier permitted to abstain. See idea 3.

**Signal-1**: arch_guard's hard failure: domain vocabulary found in core code. See idea 10.

**Sound over-approximation**: considering more possibilities than can really occur, so that
"impossible" verdicts are trustworthy. See idea 9.

**Static analysis**: checking a flow without running it. `prismpath validate`

**Stratum**: a labeled slice of the benchmark (intent / abstraction / polarity). Reporting per
stratum is what surfaced the polarity collapse that an overall average would have hidden.

**τ (tau)**: a *derived*, risk controlled escalation threshold. Contrast **δ**. See ideas 3 and 5.

**Wilson score interval**: a confidence interval for a proportion that behaves under small samples.
See idea 4.

**Worker**: whatever executes a node's instruction: a mock, a CLI process, a local model, an API.
[`cli_worker.py`](../prismpath/cli_worker.py) · [`llm_local.py`](../prismpath/llm_local.py)

**Zero shot**: working with no task-specific training examples. The default router is zero shot;
centroids make it few-shot.

---

## Part 3 · The map

### Documents

| where | what |
|---|---|
| [README.md](../README.md) | the front door |
| [SPEC.md](../SPEC.md) | the normative format spec: grammar, tiers, predicate semantics, conformance |
| [GETTING_STARTED.md](../GETTING_STARTED.md) | from zero to a running flow |
| [ROADMAP.md](../ROADMAP.md) | what's built, what's next |
| [CHANGELOG.md](../CHANGELOG.md) · [CONTRIBUTING.md](../CONTRIBUTING.md) · [SECURITY.md](../SECURITY.md) · [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) | project conventions |
| [docs/README.md](README.md) | index of the docs tree |
| [guides/authoring.md](guides/authoring.md) | the flow authoring reference |
| [guides/frontier-agent-integration.md](guides/frontier-agent-integration.md) | pairing with frontier agents |
| [design/architecture.md](design/architecture.md) | how the pieces fit |
| [design/framework.md](design/framework.md) | the operating methodology |
| [design/spec-guard-onion.md](design/spec-guard-onion.md) | the safety floor's design spec |
| [design/spec-ledger-opentimestamps.md](design/spec-ledger-opentimestamps.md) | the anchoring design spec |
| [research/primer-students-guide.md](research/primer-students-guide.md) | the ideas without the vocabulary |
| [research/paper-routing-spectrum.md](research/paper-routing-spectrum.md) | the research paper |
| [research/whitepaper-engineering.md](research/whitepaper-engineering.md) | the engineering white paper |
| [research/supporting-evidence.md](research/supporting-evidence.md) | every claim → its measured result |
| [research/bypass-measurement.md](research/bypass-measurement.md) | the pre registered safety protocol |
| [research/soc-triage-case-study.md](research/soc-triage-case-study.md) | a measured deployment |

### The four kernels

| kernel | where | role |
|---|---|---|
| Python | [`prismpath/engine.py`](../prismpath/engine.py) | reference implementation; the full engine |
| JavaScript | [`prismpath/portable/`](../prismpath/portable/README.md) | browser/edge; powers the playground |
| Rust | [`prismpath-rs/`](../prismpath-rs/CONFORMANCE.md) | native/embedded |
| Go | [`prismpath-go/`](../prismpath-go/README.md) | services |

All four pass [the same frozen vectors](../prismpath/portable/conformance/README.md); 1,079
predicates, 27 flows. Conformance refereed by re-implementation rather than asserted.

### The CLI

```bash
prismpath init        # scaffold a flow from a template
prismpath run         # execute a flow
prismpath validate    # static analysis: does it compile? (fast, no model)
prismpath lint        # validate + semantic ambiguity + polarity traps (needs embedder)
prismpath verify      # bounded model checking: can this node be reached?
prismpath capability  # which targets does this flow compile to? (python / portable / Level M hw)
prismpath test        # run the flow's Markdown fixtures (no model)
prismpath lock        # pin semantic routing into a lockfile
prismpath calibrate   # derive the risk-controlled threshold τ
prismpath centroids   # learn prototype routing from labeled history
prismpath label       # hand-label routing decisions
prismpath annotate    # blind-relabel for agreement measurement
prismpath kappa       # compute Cohen's κ between two label sets
prismpath graph       # render the flow as Mermaid
prismpath import      # LangGraph StateGraph → skeleton flow
prismpath resume      # resume a suspended or crashed run
prismpath compose     # fan-out composition
prismpath portable    # portability level report (P0/P1/P2)
prismpath compile     # compile to a portable artifact
prismpath contract    # the agent contract
prismpath plugins     # list gate plugins
prismpath ci-report   # CI-shaped output
prismpath ledger      # the Flow-Ledger (incl. anchoring)
prismpath lsp         # language server for editors
```

### Python modules by subsystem

**Kernel**: [`parser.py`](../prismpath/parser.py) · [`engine.py`](../prismpath/engine.py) ·
[`predicates.py`](../prismpath/predicates.py) · [`analysis.py`](../prismpath/analysis.py) ·
[`contract.py`](../prismpath/contract.py)

**Routing**: [`router.py`](../prismpath/router.py) · [`embedder.py`](../prismpath/embedder.py) ·
[`centroid.py`](../prismpath/centroid.py) · [`lockfile.py`](../prismpath/lockfile.py) ·
[`calibrate.py`](../prismpath/calibrate.py) · [`routelog.py`](../prismpath/routelog.py)

**Verification**: [`model_check.py`](../prismpath/model_check.py) ·
[`lint.py`](../prismpath/lint.py) · [`flow_test.py`](../prismpath/flow_test.py) ·
[`fuzz_predicates.py`](../prismpath/fuzz_predicates.py)

**Durability**: [`checkpoint.py`](../prismpath/checkpoint.py) ·
[`ledger.py`](../prismpath/ledger.py) · [`ledger_ots.py`](../prismpath/ledger_ots.py) ·
[`ledger_airgap.py`](../prismpath/ledger_airgap.py) · [`scheduler.py`](../prismpath/scheduler.py)

**Safety**: [`guard.py`](../prismpath/guard.py) ·
[`guard_semantic.py`](../prismpath/guard_semantic.py) ·
[`guard_ledger.py`](../prismpath/guard_ledger.py) ·
[`bypass_corpus.py`](../prismpath/bypass_corpus.py) ·
[`bypass_report.py`](../prismpath/bypass_report.py)

**Integration**: [`connector.py`](../prismpath/connector.py) (the SDK) ·
[`prefilter.py`](../prismpath/prefilter.py) · [`retriever.py`](../prismpath/retriever.py) ·
[`deferral.py`](../prismpath/deferral.py) · [`cli_worker.py`](../prismpath/cli_worker.py) ·
[`llm_local.py`](../prismpath/llm_local.py) · [`otel.py`](../prismpath/otel.py)

**Control plane**: [`run_sprint.py`](../prismpath/run_sprint.py) ·
[`gates.py`](../prismpath/gates.py) · [`orchestrator.py`](../prismpath/orchestrator.py) ·
[`mission_control/`](../prismpath/mission_control/) ·
[`composer.py`](../prismpath/composer.py)

**Interop**: [`langgraph_import.py`](../prismpath/langgraph_import.py) ·
[`graph_export.py`](../prismpath/graph_export.py) · [`lsp.py`](../prismpath/lsp.py)

**Measurement**: [`eval_routing.py`](../prismpath/eval_routing.py) ·
[`eval_hybrid.py`](../prismpath/eval_hybrid.py) · [`kappa.py`](../prismpath/kappa.py) ·
[`annotate.py`](../prismpath/annotate.py) · [`measure_p1.py`](../prismpath/measure_p1.py)

### Everything else

| where | what |
|---|---|
| [`prismpath/examples/`](../prismpath/examples/README.md) | curated example flows |
| [`prismpath/gallery/`](../prismpath/gallery/README.md) | templates for `prismpath init` |
| [`prismpath/benchmark/`](../prismpath/benchmark/README.md) | the N=301 routing suite + reproducer |
| [`prismpath/comparisons/`](../prismpath/comparisons/README.md) | the LangGraph/CrewAI head to head |
| [`prismpath/editor/`](../prismpath/editor/README.md) | editor integrations |
| [`prismpath/flows/`](../prismpath/flows/) | reference flows (program data) |
| [`prismpath/policies/`](../prismpath/policies/) | the statutory floor + the P1 lockfile |
| [`adapters/soc/`](../adapters/soc/) | SIEM alert triage |
| [`adapters/compliance/`](../adapters/compliance/) | compliance adjudication |
| [`tools/arch_guard.py`](../tools/arch_guard.py) | boundary enforcement (Signal-1) |
| [`tools/docs_health.py`](../tools/docs_health.py) | doc/claim coverage checks |
| [`research/`](../research/) | exploratory scripts behind the evidence ledger |

---

## Part 4 · Reading paths

**"I just want to write a flow."**
[GETTING_STARTED.md](../GETTING_STARTED.md) → [authoring guide](guides/authoring.md) →
[examples](../prismpath/examples/README.md). Skip the papers entirely.

**"I want the ideas, not the math."**
[research/primer-students-guide.md](research/primer-students-guide.md) → ideas 1 to 3 above. That's it.

**"I need to defend a claim someone challenged."**
[supporting-evidence.md](research/supporting-evidence.md) first; it maps each claim to the result
and the script that produced it; then the relevant paper section.

**"I'm evaluating this for production."**
[architecture](design/architecture.md) → [SPEC.md](../SPEC.md) →
[portability levels](../prismpath/portable/README.md) (P0 flows have no ML dependency at all) →
[SECURITY.md](../SECURITY.md) → [the SOC case study](research/soc-triage-case-study.md).

**"I want to understand the safety story, including its limits."**
[guard onion spec](design/spec-guard-onion.md) →
[bypass-measurement.md](research/bypass-measurement.md). The second reports the attacks that
*succeed*; read it before making any claim about resistance.

**"I'm implementing a kernel in another language."**
[SPEC.md](../SPEC.md) → [conformance vectors](../prismpath/portable/conformance/README.md) →
[the Go kernel](../prismpath-go/README.md) as the most recent worked example.

**"I want to know what's actually measured vs. asserted."**
[supporting-evidence.md](research/supporting-evidence.md), then §6 of
[the research paper](research/paper-routing-spectrum.md); the limitations section is where the
open questions are stated plainly.
