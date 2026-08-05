# PrismPath — authoring guide & the rules that govern the framework

A workflow is **one markdown file**. The kernel (~700 LOC across parser/predicates/router/
engine; hard dep: numpy — the embedder is the optional `[embeddings]` extra, transformers only
for the LLM-fallback router) reads it and drives any agent through it. No code defines the
graph; no framework state objects. This doc is the authoring contract — the normative format
definition lives in [SPEC.md](SPEC.md); read both before extending.

---

## 1. File anatomy

```markdown
---
name: bugfix          # optional label
start: triage         # optional; defaults to the first node
---

## triage                                   # a NODE (heading -> node name, lowercased,
Read the bug report and decide what to do.  # spaces->underscores). Prose = the node's
-> implement: the root cause is clear       # INSTRUCTION handed to the agent.
-> gather_info: more information is needed   # EDGES: `-> target: condition`
-> close: it is a duplicate or invalid

## done                # a node with NO edges is TERMINAL (the run ends here)
Summarize and finish.
```

- **Node** = `## Heading`. Name is normalized (`Write Code` → `write_code`). Body until the next
  heading (minus edge lines) is the instruction.
- **Edge** = a line `-> target: condition`. `target` must be a defined node.
- **Terminal node** = a node with zero edges. Reaching one stops the run (`stopped="terminal"`).

---

## 2. The routing spectrum (the core idea)

Each edge's `condition` is one of four kinds; the **engine** decides how to route, not the author:

| kind | syntax | how it routes | cost | use it for |
|---|---|---|---|---|
| **deterministic** | `-> t: when <expr>` (also `always`/`else`/`false`) | evaluate `<expr>` against the outcome fields | free, exact | logic: pass/fail, counts, flags, negation |
| **semantic** | `-> t: <natural language>` | embed the outcome text vs the condition; escalate to an LLM only if low-confidence | ~free + rare LLM | judgment/intent that isn't a clean predicate |
| **error** | `-> t: on error [when <expr>]` | fires when the worker *raises*; `<expr>` sees `error_count`, `error_type`, `error_message` | free | retries, escalation, dead-letters (see §6d) |
| **event** | `-> t: on event <name>` / `-> t: on timeout` | fires when the run is *resumed* with that external signal/timer | free | wait-for-webhook / timer (see §6b) |

**Precedence (the rule):** at a node, deterministic edges are evaluated **first, in document
order — first true wins**. If none match, the **semantic** edges are routed by the router. If
there are no semantic edges and no deterministic edge matched → `stopped="stuck"`. Error and event
edges are inert during normal routing — they only fire on a raise (error) or on resume (event).

> Rule of thumb: *logic where logic exists, intent where it doesn't.* If you can express a
> transition as a predicate, write `when …` — it's free and never misroutes (this is how
> negation like `when not tests_pass` is handled reliably; embeddings alone can't).

---

## 3. The agent contract

The engine is agent-agnostic. You pass `run(graph, agent, ...)` where:

```python
agent(node_name: str, instruction: str, state: dict) -> outcome
```

`outcome` is either:
- a **string** — becomes the text used for semantic routing; or
- a **dict** — `{"text": "...", <field>: <value>, ...}`. `text` feeds semantic routing; the
  other fields are the variables deterministic `when` predicates see.

Example: a `run_tests` node returns `{"tests_pass": True, "text": "all tests passed"}`, so the
edge `-> done: when tests_pass` fires deterministically while `-> debug: tests look wrong` stays
semantic.

The agent owns its own working memory via `state` (persists across the whole run) — e.g. it
stashes `state["code"]`, `state["last_error"]`. The engine never inspects those; only the
fields you *return* are exposed to predicates.


### Any CLI as a worker (`prismpath.cli_worker`)

The most stable worker interface is a process: `cli_agent(["claude", "-p"])` runs a CLI per node
(prompt on stdin), a `{node: argv}` map runs a **different engine per node**, and the contract is
data all the way down — JSON on stdout becomes the dict outcome (`when` predicates read its
fields), plain stdout is the outcome text, **nonzero exit and timeouts raise onto the error
tier** (`-> retry: on error when error_count < 3` gives any CLI a retry budget as edges).
`{node}`/`{instruction}` template into argv for file-based runners; `pass_state=[...]` forwards
chosen state keys as a JSON context block. Trust boundary, bluntly: a CLI worker is arbitrary
code execution *by design* — PrismPath's sandbox claim covers the ROUTING layer (predicates never
execute worker-influenced strings), not the workers you choose to run.

---

## 4. State, the visits counter, and loop control

- `state` is a dict shared across the run; the engine seeds `state["transcript"]` (list of
  `{node, outcome}`) and `state["visits"]` (per-node entry counts).
- Inside predicates you get `visits` = how many times the **current** node has been entered.
  Use it to bound cycles: `-> give_up: when visits > 3`.
- Cycles are allowed and normal (`-> implement: when not tests_pass` loops back). `max_steps`
  (default 25) is the hard stop → `stopped="max_steps"`.

---

## 5. Predicate grammar (deterministic edges)

Safe AST evaluation — **no function calls, attribute access, or subscripts** (no code exec;
fuzz-tested). Allowed: names (outcome fields + `visits`; unknown name → `None`), constants,
`and`/`or`/`not`, and comparisons `== != < <= > >= in not in`.

```
when tests_pass
when not tests_pass
when visits > 3
when status == "done"
when score >= 0.9 and not blocked
always   |   else   |   false      # bare catch-alls
```

**Fail-safe semantics (so a predicate never crashes a run):**
- A **missing or type-mismatched field in a comparison is *unsatisfied*** — `when score >= 0.9`
  is simply `False` when the agent didn't emit `score`, not an error. (`==`/`!=` are exact:
  a missing field compares unequal to a value, equal to another missing field.)
- An **unsafe or unparseable predicate is caught by `validate`/`lint`** before the flow ever
  runs (see §9) — `when foo.bar`, `when score >=`, `when open(x)` are compile-time errors, not
  runtime surprises. Run `python -m prismpath.cli validate flow.md` and fix what it reports.

---

## 6. Run outcome

`run(...)` returns `RunResult(path, steps, stopped, state, pending)`:
- `path` — list of visited node names (a readable audit trail).
- `steps` — per-transition `StepLog(node, outcome, target, info)`; `info["used"]` ∈
  `{deterministic, embed, llm, single, error, event, human}` (how each hop was decided).
- `stopped` ∈ `{terminal, stuck, needs_human, waiting, max_steps, contract_violation}` (the last only with the opt-in `type_gate`, §6a).
- `pending` — set when `stopped` is `needs_human` (the decision awaiting a person: node, candidate
  edges, router scores, reason — the evidence packet a human queue shows) or `waiting` (the events
  the run is blocked on, from its `on event`/`on timeout` edges, plus an optional `timeout_s`).

---

## 6b. Durable execution — suspend, checkpoint, resume (`prismpath.checkpoint`)

The engine is pure and its `state` is ephemeral. To make a run **durable and resumable** without
ever writing the read-only `.md`, the checkpoint layer serializes the run to a JSON sidecar
(atomic `os.replace`) and resumes by re-parsing the `.md` and re-entering the engine:

```python
from prismpath import checkpoint
# run, persisting a checkpoint at every step:
res = checkpoint.run_durable("flows/soc.md", agent, "run.ckpt.json")
# after a crash, continue from the pending node (deterministic — re-runs only the unfinished node):
res = checkpoint.resume("run.ckpt.json", agent)
# after a needs_human suspension, apply the human's chosen edge:
res = checkpoint.resume("run.ckpt.json", agent, choose="stage_containment")
```

**Two ways a run suspends as `needs_human`** (a dedicated stop reason — the run is *suspended*, not
failed):

1. **Worker-requested.** A node's handler returns a dict with a truthy `needs_human` field
   (`{"text": "...", "needs_human": True, "reason": "policy sign-off"}`). `needs_human` and
   `reason` are **reserved** outcome fields, checked before routing.
2. **Low-confidence route.** Call `run(..., human_floor=τ)`: when a semantic route's top absolute
   score falls below `τ`, the engine suspends instead of guessing and records the candidate edges
   *with their scores*. This turns the absolute-score floor into a compliance feature — every
   uncertain decision lands in a human queue with the scores that explain why.

Guarantees: the `.md` is never written (durable state lives only in the sidecar — this is *why*
we checkpoint to JSON rather than a checkbox back in the doc); resume is deterministic (same
checkpoint + same choice ⇒ identical continuation); and checkpointing is off the critical path
(non-serializable state disables it with a warning rather than breaking the run). The human
decision is logged in the transcript with `decided_by: "human"`.

**Flow-hash binding.** The checkpoint records a content hash of the flow `.md`. If the flow is
edited while a run is suspended, `resume` **refuses** by default rather than silently governing by
the new version (a real correctness trap for long-lived suspensions). Override with
`prismpath_RESUME_ON_FLOW_CHANGE=warn` (proceed + warn) or `=allow` (proceed silently).

CLI: `python -m prismpath.cli resume <checkpoint> [--choose <edge>]`.

### Wait-for-event (durable pauses on external signals)

A worker that returns `{"wait": True, "timeout_s": 3600}` suspends the run with `stopped="waiting"`
(its own stop reason). The node's **event edges** say where each resume goes:

```markdown
## await_payment
Wait for the payment webhook (or a timeout).
-> fulfilled: on event payment_confirmed
-> cancelled: on timeout
```

Deliver the signal to continue: `checkpoint.resume(ckpt, agent, event="payment_confirmed")` (or
`event="__timeout__"`). This generalizes suspension to timers and webhooks — Temporal-lite, but the
waiting logic is readable in the flow. Combined with the checkpoint, a run can pause for days and
resume deterministically.

### Plugins & tool binding (`@worker`, `prismpath plugins`)

The plugin ecosystem extends the **harness**, never the engine: routing, predicates, and purity are
not extensible on purpose. A plugin (bundled under `plugins/`, or any pip-installed package
registering the ``prismpath.plugins`` entry-point group) provides **workers** (named tools),
**gates** (build targets — the browser gate in `gates.py` is the built-in), and/or **CLI** subcommands.

Bind a node to a tool *in the document*, where a reviewer can see it:

```markdown
## steer
Roll the expansion mandate for this round.
@worker(council.roll)
-> propose: always
```

```python
from prismpath.plugins import registry
agent = registry.worker_agent(graph, default=my_agent)   # bound nodes -> plugin; rest -> yours
```

Three auditability guarantees back the binding: `worker_agent` resolves every binding at
**construction** (a missing tool fails before the run, not at hop 40); `PrismPath plugins --check
flow.md` is the same verification as a CI gate; and every dispatched outcome carries a `_worker`
provenance field, so the transcript records which installed tool produced each hop. `PrismPath plugins
[--json]` lists everything discovered — name, version, source (bundled vs entry-point), and what it
provides. The bundled `council` plugin (seeded dice + weighted vote tally) is the showcase
*expansion*: an optional deliberation pattern for decisions that benefit from deliberate diversity —
the exception, not the default (see `plugins/council/README.md`).

### Bounding persisted state (`@state_bound`)

A long-lived, resumable run appends one transcript entry per hop and re-seeds its full path/step
history on every resume — unbounded by default. Declare a bound in the flow (any node may carry it;
it is flow-scoped, first in document order wins):

```markdown
## work
Poll the feed, forever.
@state_bound(transcript=200)
-> work: on event tick
```

The engine then sliding-windows the growing lists to the last N entries — the transcript on every
append, and the re-seeded `path`/`steps` at each resume — so the **checkpoint payload stays flat**
across unlimited resumes. What was dropped is counted deterministically in
`state["_state_dropped"]` (`{"transcript": …, "path": …, "steps": …}`) rather than summarized by a
model — the engine stays pure. **The window can never change a routing decision**: predicates read
worker fields plus the per-node `visits`/`error_count` counters, which are separate ints and never
trimmed; `_outcomes` is last-write-per-node and already bounded by the node count. A malformed value
(`transcript=lots`, `transcript=0`) raises at run start — a declared bound that silently didn't bind
would be worse than none. Programmatic callers can override with `run(..., max_transcript=N)`.

### Fan-out & sub-flow composition (`@spawn`, `prismpath.composer`)

Parallelism without impurity: a **fan-out node** spawns one durable child run per item and waits for
them to finish. Fan-in *semantics* live in the document (event edges); concurrency *mechanics* live in
an out-of-band harness. The engine is unchanged except that it passes a worker's `spawn` payload
through into the checkpoint — it spawns nothing itself.

```markdown
## dispatch
Fan out one review per changed file, then wait for them all.
@spawn(child=review_one.md, over=files, item_id=path, join=all_done)
@expect(verdict)
-> aggregate: on event all_done
-> escalate: on timeout
```

The node's worker supplies only the runtime **item list** — either
`{"spawn": {"items": [...]}}` in its outcome (spawn implies wait; `"wait": True` is optional), or by
writing the list into state under the key named by `over=` and returning `{"spawn": {}}`. The
**annotation is authoritative for structure** (child flow, join policy, `item_id`, `gate`): what
`validate` checked and the lockfile pinned is exactly what the harness executes — a worker-supplied
`join` that diverges from the declared one is ignored, so runtime drift can't deadlock a fan-out that
compiled clean.

- **Join policies** (the event the join fires): `all_done` → every child terminal; `any` → first child
  done; `quorum:k` / `quorum:0.6` → a count/fraction done. Each fires the matching event
  (`on event all_done` / `on event any` / `on event quorum`); stragglers are left running, never
  cancelled. `join=…, gate=<field>` counts a child "done" only if its terminal outcome sets `<field>`
  truthy (a *successful*, not merely finished, child). A **fan-out timeout** is just the node's
  `timeout_s` — the ordinary scheduler delivers `on timeout` if the join never completes.
- **Sub-flow composition is the N=1 case** — a single child is a fan-out over a one-item list; identical
  code path.
- **The harness** `prismpath.composer.advance_fanouts(agent)` (CLI: `prismpath compose`) is a restartable
  scan, exactly like the timeout scanner: it spawns each child under a **deterministic** id
  (`parent.node.item_id`, no timestamp/randomness), so a re-scan re-attaches to existing children and
  **never double-spawns**; when the join is ready it aggregates the children into
  `state["_spawned"][node]` and resumes the parent. Children are ordinary checkpointed runs (durable,
  resumable, ledgerable); the git ledger dedups child **units** across every parent that spawns them.
- **Static analysis crosses the flow boundary**: `validate` errors on a `@spawn` node with no matching
  `on event` edge (a fan-out deadlock), a missing/unparseable child flow, or a child with no reachable
  terminal (its runs never finish → the join never fires); and warns when `@expect(fields)` names fields
  the child never `@emits`. The whole composition tree compiles without running.
- **The lockfile pins the tree**: `prismpath lock <parent>` recursively locks every child and records each
  child's `{flow_hash, lock_hash}`; `prismpath lock --check` (`verify_tree`) fails if any child flow or its
  lock drifted after the parent was pinned. Reproducible routing across the entire call tree.

**Learned routing pins:** `prismpath lock <flow> --centroids <labeled.jsonl>` builds per-condition
centroids from labeled decisions (`prismpath test --emit-labels` / `prismpath label`) and commits the
SHRUNK vectors in the lock — the measured centroid gain (+0.14 overall, +0.23 polarity) becomes
bit-for-bit reproducible; `locked_router` prefers pinned centroids automatically. A typed
`@emits(x=bool)` declaration is also cross-checked against the type the node's own `when` edges
infer for `x` (`emits-type-mismatch` warning) — the declaration and the predicates can't drift.

### The portable subset (`prismpath portable`, `portable/prismpath.mjs`)

A flow whose reachable edges are all decidable — `when` predicates, `on error`, `on event`/`on
timeout` — is **portable**: its routing needs no embedder and no LLM, so it runs on the reference
port `portable/prismpath.mjs` (one dependency-free ES module: parser + predicate sandbox + engine
loop) in a browser, at the edge, or in an appliance. `prismpath portable <flow>` reports the flow's
**tier** — P0 (all decidable), P1 (semantic edges all pinned in the lockfile: only an outcome-side
embedder needed at runtime), P2 (unlocked semantic edges: full engine) — with the exact
violating/unlocked edges, recursing through `@spawn` children (the tree's tier is its worst
member's). Authoring rule of thumb: emit structured fields (`@emits`) and
route on them with `when` — every semantic edge you convert both hardens routing *and* keeps the
flow in the subset. Parity with the Python engine is enforced by the cross-language conformance
suite (`tests/test_portable_conformance.py`), not asserted.

### The human queue (Mission Control)

A suspended run's checkpoint, written into the **queue dir** (`prismpath_QUEUE_DIR`, else
`$XDG_STATE_HOME/prismpath/queue`), surfaces in Mission Control's **Queue** tab: each waiting run shows
its evidence packet — flow, node, the reason it escalated, and the candidate edges *with the router
scores that asked for a human*. An operator picks an edge; `checkpoint.record_decision(path, choose)`
writes the choice into the checkpoint (`decided_by`), and the owning run's next `resume(...)` (no
explicit `choose`) applies it. So the UI decision and the execution are decoupled — the console never
needs the flow's agent. Backing calls: `checkpoint.list_queue()` and `record_decision()`; every
decision is logged to the Mission Control audit.

### The git Flow-Ledger (`prismpath.ledger`) — proof-commits, opt-in

Where the checkpoint makes a run *resumable*, the **Flow-Ledger** makes each gate-green unit a
durable, content-addressed **proof**. Behind `SPRINT_LEDGER=1`, every unit the sprint marks done
becomes exactly one commit whose git tree is the content-hashed state the gate blessed and whose
trailers correlate it to the flow node:

```
prismpath: auth green  (browser-integration run 20260710T…)

prismpath-Unit: auth   prismpath-Node: auth   prismpath-Seq: 1   prismpath-Gate: green
prismpath-Gate-Name: browser   prismpath-Output-Hash: sha256:…   prismpath-Depends: …
```

Design points that matter:
- **Never in-tree.** The ledger is a *separate bare repo* under `$XDG_STATE_HOME/prismpath/<flow>.git`,
  written via git plumbing with `GIT_DIR` pinned — a project's own repo (refs, index, working tree)
  is never touched, and `SPRINT_FRESH`'s wipe can't delete it. One orphan ref per run
  (`refs/prismpath/runs/<run-id>`); commits are append-only.
- **Progress is a projection.** `Ledger.done_set()` folds the log into `{unit → latest green
  record}` (newest-wins per unit) — the resume state, derived from git rather than a mutable
  sidecar. `prismpath-Output-Hash` is the per-unit "done for *which* input" key a checkbox can't be.
- **Off the critical path.** Every ledger call is wrapped so a git failure degrades to the existing
  `.lastgood`/`.kg.json` path — the ledger records progress, it never drives or breaks a sprint.
  Anchor provenance on the tree / `Output-Hash` (content-addressed), never the commit sha.
- **Resume from git.** A build sprint whose `.kg.json` was wiped (`SPRINT_FRESH`) resumes by pointing
  at its prior run: `SPRINT_LEDGER=1 SPRINT_LEDGER_RUN=<id>` re-marks every ledger-proven node done
  from `done_set()` before the loop, so the sprint restarts at the first *unproven* node instead of
  rebuilding what git already attests.

This is the *public* durable-proof tier; a multi-party tamper-evident audit is a separate premium layer. Full design: `docs/design/commit-as-state.md`.

### Ledgering a routing flow — `@checkpoint` + `run_ledgered_loop`

A *routing* flow (SOC triage, a ticket queue) processes one item per `engine.run` and edits no code,
so it has no gate-green seam. Give it one anyway by marking the node whose success means "this item
is fully handled" with a **`@checkpoint`** annotation, and drive it with `run_ledgered_loop`:

```markdown
## report
@checkpoint(unit=alert.id, proof=verdict)
Write the triage report and mark the alert processed.
-> end: when always
```

- **`unit`** (required) — a dotted `state` path to the ITEM id (e.g. `alert.id`), *not* the node
  name (which repeats across items). This is the resume key and the `prismpath-Unit` trailer.
- **`proof`** (optional) — a `state` path to the produced artifact (the verdict); its content hash
  is `prismpath-Output-Hash`. Defaults to the checkpoint node's outcome text.
- **`gate`** (optional) — an outcome field of the checkpoint node that must be truthy to commit.

`run_ledgered_loop(flow, agent, ledger)` runs the flow once per item, writes one proof-commit when
the checkpoint is reached, and **resumes from the ledger**: each pass seeds `state['_done_units']`
from `done_set()`, so the flow's `observe`/`fetch` node skips items already proven in git — a run
stopped mid-stream restarts at the first item with no green commit, with no processed-list to keep
in sync. Make side effects idempotent with `upsert_jsonl(path, record, key=...)` so a replayed item
never double-appends. Reference: `flows/wazuh_triage.md` + `wazuh_triage_agent.py` (`SPRINT_LEDGER=1`).

---

## 6a. What `validate` / `lint` guarantee — "your flow compiles"

Because the flow *is* the graph (a Markdown file, not code), the whole control structure can be
checked statically. `prismpath.analysis.analyze(graph)` runs every **decidable** check (no model, no
embeddings, no execution) and returns `Finding(severity, code, node, message)`:

| code | severity | catches |
|---|---|---|
| `undefined-start` / `undefined-target` | error | an edge/start pointing at a node that isn't defined |
| `unsafe-predicate` | error | a `when` that isn't sandbox-safe & parseable |
| `no-terminal` | error | no terminal node reachable from `start` (can only end at `max_steps`) |
| `unreachable-node` | warning | a node nothing routes to |
| `possible-stuck` | warning | a deterministic-only node whose conditions aren't provably exhaustive |
| `shadowed-edge` | warning | an `always`/`else` catch-all makes later or semantic edges dead |
| `unbounded-cycle` | warning | a loop with no `visits`-based cap (only `max_steps` protects it) |
| `always-false-edge` | warning | a dead condition, e.g. `when visits < 4 and visits > 10` |
| `duplicate-condition` | warning | two identical semantic edges — a guaranteed router near-tie |

- `python -m prismpath.cli validate flow.md` — errors + warnings; **exits non-zero only on errors**
  (warnings are advisory). `--json` for CI/pre-commit.
- `python -m prismpath.cli lint flow.md` — the above **plus** the one non-decidable check
  (`ambiguous-conditions`: semantic edges that embed too similarly to route between; needs the
  embedder).

The predicate reasoning is confined to the decidable `when` fragment (a variable compared to
literals, joined by and/or/not) — including complementary-pair detection so `when tests_pass` /
`when not tests_pass` is recognized as exhaustive. Anything outside that fragment is left
un-analyzed rather than guessed, which is why real flows get **zero false positives**. The
broken-flow corpus in `tests/fixtures/broken/` is one deliberately-broken flow per check.

---

## 6c. Testing a flow's routing (`prismpath test`)

`validate` checks the flow *compiles*; `prismpath test` checks it *routes the way you meant* — from a
Markdown fixture, no agents or LLM required. The fixture (a sibling `<flow>.tests.md`) is a GFM
table of `(node, outcome, fields, expect)`:

```markdown
| node      | outcome                          | fields          | expect     |
|-----------|----------------------------------|-----------------|------------|
| run_tests | all tests passed                 | tests_pass=true | done       |
| run_tests | three tests still fail           | tests_pass=false| debug      |
| debug     | the fix is obvious, a one-line typo |              | write_code |
```

```bash
python -m prismpath.cli test prismpath/flows/coding.md        # runs <flow>.tests.md; ✓/✗ per row
python -m prismpath.cli test prismpath/flows/coding.md --emit-labels labels.jsonl   # + calibration data
```

Each row is run against the **real router's deterministic and embedding tiers** (the LLM tier is
never invoked) and its chosen edge is asserted against `expect`. `fields` are `k=v` pairs (`;`/`,`
separated; `true`/`false`/`int`/`float` coerced) the `when` predicates see; deterministic rows need
no model at all. If a `<flow>.lock` exists, tests route against the committed vectors — so they are
bit-for-bit reproducible. The PM writes the scenarios; CI asserts the routing (non-zero exit on any
miss); every past mis-route becomes a regression row; and `--emit-labels` drops each case as a
labeled routing record — free calibration data. (`.tests.md` files are fixtures, not flows — `lint`
and `validate` ignore them.)

---

## 6d. Error edges — failure handling in the document

When a node's worker **raises**, the engine routes the node's **error edges** instead of guessing —
so retries and escalation live in the readable flow, not in retry conventions:

```markdown
## implement
Write the fix and run the tests.
-> review: when tests_pass
-> implement: on error when error_count < 3      # transient failure — retry up to 3×
-> escalate_human: on error                       # then hand it to a person
```

`on error` matches any raise; `on error when <expr>` conditions on the error context
(`error_count` — per node, `error_type`, `error_message`), evaluated by the same safe predicate
evaluator. Edges are tried in document order; the first match wins. **If no error edge matches, the
exception propagates** (unchanged behavior). Error edges are inert on a normal (non-raising)
outcome. `lint` can require every node to carry an error path if you want failure handling enforced.

---

## 7. Routers (pluggable; `run(graph, agent, router=...)`)

- `EmbeddingRouter()` — cosine only (cheap, weakest; ~0.82 on the bench).
- `LLMRouter(generate_fn)` — a 1-shot LLM picks the edge (accurate, costs a call).
- `HybridRouter(LLMRouter(...), margin=0.05)` — embed first; escalate to the LLM only when the
  top-1↔top-2 margin < `margin` (**recommended**, stacked over `CentroidRouter` once labeled
  history exists: 95.3% at 360 calls/1k on the N=300 suite — `benchmark/hybrid_sweep.py`; derive
  the margin with `prismpath calibrate` rather than hand-picking a constant).

### The routing lockfile — reproducible semantic routing (`prismpath.lockfile`)

Semantic routing is a function of the embedder's exact numerics — a model update, a different ONNX
build, even hardware float differences can shift a margin across δ and change routing with **no diff
anywhere**. The lockfile closes that hole (it's `package-lock.json` for control flow):

```bash
python -m prismpath.cli lock prismpath/flows/triage_support.md   # writes triage_support.lock
python -m prismpath.cli lock --check prismpath/flows/triage_support.md   # verify the embedder still matches
```

`<flow>.lock` commits every semantic condition's embedding vector (base64 float32, bit-exact), the
embedder's identity + a **fingerprint** (a fixed probe sentence's embedding), δ, and a hash of the
flow. At runtime, `lockfile.locked_router(lock, llm_router)` routes conditions against the committed
vectors — so the condition side of every decision is bit-for-bit reproducible — and `verify_lock`
checks the local embedder still reproduces the fingerprint, turning silent drift into a loud,
policy-controlled signal (`prismpath_LOCK_POLICY=refuse|warn|allow`, refuse by default). This makes
semantic routing reproducible across machines, installs, and years — a compliance *feature* rather
than a liability. Commit the `.lock` next to the flow.

### The prefilter cache (memoizing expensive verdicts)

Routing is cheap; the expensive step in a real flow is usually one adjudication node. If that
node's inputs recur near-identically, put a **prefilter node** in front of it backed by
`prismpath.prefilter.PrefilterCache`:

1. The prefilter node's handler calls `cache.lookup(document)` and returns
   `{"cached_action": <action>|None, "prefilter_hit": bool, ...}`.
2. Deterministic edges route on the cached action; the miss path falls through to the expensive
   node: `-> classify: when always` (last, so a hit never reaches it).
3. The expensive node's handler calls `cache.learn(vec, action, confidence, ...)` after
   adjudicating (reuse `res.vector` from the lookup — no re-embed), so the cache compounds.

A **hit requires two thresholds**: similarity ≥ `threshold` (default 0.97 — same situation?) and
the stored verdict's confidence ≥ `min_conf` (default 0.8 — was the prior verdict trustworthy?).
The reuse is logged with the matched key + similarity, so auto-resolutions stay auditable.
Reference implementation: `flows/wazuh_triage.md` (`vector_prefilter`) + `wazuh_triage_agent.py`
(measured live: ~59% auto-resolve → ~2.4× capacity).

**Use as needed — this is a pattern, not a default.** The engine never invokes it; you wire it
in per flow, and only when **all three** hold:

1. **One node dominates run cost** (an LLM adjudication, a slow judge). If routing or I/O is
   your cost, the cache buys nothing.
2. **Inputs recur near-identically** (alert streams, ticket queues, moderation). Generative or
   novelty-heavy nodes never hit — the corpus is just risk with no payoff.
3. **The verdict is a function of the embedded document alone, under a stable policy.**
   Everything the decision depends on must be *in* the document you embed — otherwise a reuse
   can silently apply a verdict from a different context. (The SOC flow deliberately embeds
   only the *stable* alert fields, not the volatile 24-hour context: a scoping choice that
   trades context-sensitivity for cache stability. Make that choice explicitly.)

Operational caveats: entries never expire and the corpus grows without bound — re-seed to reset
(TTL/invalidation is future work). Before enabling, replay your real stream
(`measure_prefilter.py` is the template) and look at both cold-start and steady-state hit
rates; if they're low, don't ship it.

---

## 8. Authoring rules of thumb

1. **Prefer `when` for anything logical.** Free, exact, and it's how you beat the embedding
   weakness (negation, counts, thresholds).
2. **Make semantic conditions mutually distinct.** Run `python prismpath/lint.py flow.md` — it flags
   conditions too similar to route between.
3. **Phrase a semantic condition at the abstraction level of the agent's likely outcome** (the
   bench misroutes came from concrete outcomes vs abstractly-worded conditions).
4. **Always give a node an exit** — a terminal target, a catch-all `-> x: else`, or a
   `when visits > N` escape — or a cycle can only end at `max_steps`.
5. **Return structured outcomes** (`{text, ...fields}`) wherever a downstream edge is logical.
6. **If one node is an expensive adjudication over recurring inputs — and the verdict depends
   only on what you embed — prefilter it** (§7): a `PrefilterCache`-backed node in front of it
   turns repeat inputs into free, auditable auto-resolutions. Skip it everywhere else.

---

## 9. Invariants to preserve when extending (don't break these)

- **The MD file stays the single source of the workflow** — no control flow in code.
- **Deterministic-before-semantic precedence** (Section 2) — keep it; it's what makes flows
  predictable.
- **The agent contract** (Section 3) — `(node, instruction, state) -> str | {text, ...}`. New
  features should not require changing agent signatures.
- **Predicate safety** (Section 5) — never add `eval`/attribute/call access to the evaluator.
  The allowlist (`predicates._ALLOWED_NODES`) is the security boundary; if you extend the grammar,
  extend `check_predicate` and re-run `python -m prismpath.fuzz_predicates` (must stay 0 crashes, 0
  executions) and the `tests/test_predicates.py` hardening cases.
- **Routing is the engine's choice, not the author's** — authors write conditions, not routing
  modes (beyond the `when` vs natural-language distinction).

## 10. Natural extension points (where new complexity slots in cleanly)
- **New edge kinds**: add a classifier alongside `predicates.is_deterministic` + a handler in
  `engine.run` (e.g. `-> t: include subflow.md` for subgraphs; `-> t: parallel a,b,c` for fan-out).
- **Node annotations**: a `@human`, `@parallel`, or `@retry(n)` marker on a heading, parsed in
  `parser.py`, handled in `engine.run`.
- **Typed state**: declare variables in front-matter; expose them in the predicate context.
- **New routers**: implement `.route(outcome, edges, instruction) -> RouteDecision` and pass via
  `run(router=...)` — no engine change.
- **Observability**: `RunResult.steps` already carries everything for a trace/visualizer.
