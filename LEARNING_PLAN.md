# The learning plan — three roads into the same document

This plan takes three people through PrismPath, each on their own road, all arriving at the same
place: a team whose **process changes are pull requests**. The three personas exist because the
system is used by people who don't share a vocabulary — so this plan standardizes one. Every stage
ends with a **checkable outcome** (a command whose output tells you that you passed), because
"read about it" is not a definition of done here or anywhere else in this project.

| persona | who this is | what they'll own at the end |
|---|---|---|
| **The analyst** (business analyst, PM, process owner) | owns a real-world process; doesn't write code, doesn't want to | authors and reviews flows + fixture tables; approves process changes in PRs |
| **The developer** | writes application code daily | wires workers (models, CLIs, tools), builds worker packs, ships flows |
| **The engineer** (platform / SRE) | runs systems in production | the guarantees: reproducibility, calibration, CI gates, observability |
| **The SecOps analyst** (SOC / detection engineering) | triages alerts for a living | flows as playbooks: containment behind human gates, verdict reuse with a safety monitor, air-gap deployment |
| **The auditor** (compliance, GRC, customer diligence) | verifies controls after the fact; runs nothing | reconstructing any decision from artifacts alone; evidencing that routing changed only by reviewed diff |
| **The decision-maker** (CTO, director) | approves the bet, not the syntax | the five questions — lock-in, verifiability, team cost, security posture, longevity — answered defensibly |

Pick your row. Or read several — the fastest way to learn the *language* is to see the same
concept land more than one way. (Two readers deliberately have no track: the researcher — the
papers in `prismpath/docs/papers/` *are* their plan — and the OSS contributor, whose road is
`CONTRIBUTING.md`. A plan for everyone is a plan for no one.)

---

## The shared vocabulary (learn this first — it's the whole trick)

One concept, three dialects, one word we all use. When you talk across roles, use the **term**
column; the plan and every doc in this repo do.

| term | the analyst hears | the developer hears | the engineer hears |
|---|---|---|---|
| **flow** | the process document — the thing you'd have written in Confluence, except it runs | a state machine defined in Markdown | a policy artifact: versioned, diffable, hash-addressable |
| **node** | one step of the process, described in plain prose | a unit of work handed to a worker | an execution stage with a derived I/O contract |
| **edge** | "if this, then go there" — one line you can read | a guarded transition | a routing rule with a tier and a cost |
| **worker** | whoever/whatever does the step (a model, a tool, a person) | the callable: `(node, instruction, state) → outcome` | an untrusted component outside the verified boundary |
| **outcome** | what came back from the step | the return value: text and/or fields | the evidence a routing decision is made on |
| **tier** | how a decision is made: exact rule, judgment call, failure, or waiting | deterministic / semantic / error / event dispatch | the cost-and-certainty class of a decision |
| **escalate** | "this one needs a smarter look" | fall through to the LLM (or a person) on low margin | move the decision to a costlier, more capable stage |
| **fixture** | a table of examples: "when the step says X, it must go to Y" | a test case in Markdown | a regression gate; CI fails if routing drifts |
| **lockfile** | the routing is frozen — it can't quietly change | pinned embeddings; reproducible routing | bit-for-bit reproducibility + drift refusal |
| **validate** | "does my process even make sense?" — the spell-checker | static analysis; "your flow compiles" | decidable checks, zero false positives, CI-safe |
| **escalation queue** | the pile that needs a human decision | a suspended run awaiting `choose=` | a durable checkpoint with an evidence packet |

Words we deliberately avoid: "DAG" (flows have cycles, on purpose), "prompt chain" (routing is
not prompting), "agent" for the whole system (the *worker* may be an agent; the flow is a document).

---

## Stage 0 — everyone, together (15 minutes, nothing installed)

Same three steps regardless of persona. The playground runs entirely in your browser.

1. Open the playground (`prismpath/portable/playground.html` — or click a shared flow link; the whole flow
   lives in the URL).
2. Pick a preset. Press **▶ Run**. Watch the path light up.
3. Break it: edit an edge's target to a node that doesn't exist. Watch the compile panel catch it
   *as you type*. Fix it. Then change a `when` condition and re-run.

**✓ Done when:** you can say out loud what an edge is, and you've used 🔗 Share to send someone a
flow you edited. That link is the "oh" moment this whole system is built around: the document you
just read *is* the program that just ran.

---

## The analyst's road (no code, ever)

**Stage A1 — read a real flow (30 min).** Have anyone on the team run
`prismpath init --template support_triage`, or open the gallery in the playground. Read
`support_triage.md` top to bottom. Notice the two kinds of edges: judgment calls in plain English
(`-> escalate: a manager approval or exception is required`) and hard policy in one line
(`-> escalate: when amount > 500`).
**✓ Done when:** you can point at one edge that encodes *policy* and one that encodes *judgment*,
and say why they're different lines.

**Stage A2 — own the fixture table (45 min).** Open `support_triage.tests.md`. It is just a
table: *when the step's outcome says this, routing must go there*. Add three rows from your own
memory of the real process — including one past mis-route (the ticket that went to the wrong
queue that one time). Ask a teammate to run `prismpath test support_triage.md`, or run it yourself —
it's one command, and it's model-free.
**✓ Done when:** your rows pass — or better, one *fails* and the fix is a one-line edge edit you
can read. Every past mistake your process ever made can become a row in this table.

**Stage A3 — the PR is the process change (45 min).** Propose a real rule change ("refunds over
$500 need a manager") as a pull request: edit one edge line, add one fixture row. Watch the
**flow report comment** appear on the PR: your process's map, before → after, with the test
verdicts. That comment is written for you, not for the developers.
**✓ Done when:** you have approved (or rejected!) a process change by reading a PR — no meeting,
no stale wiki page. **Capstone:** write a brand-new flow for a process you own, with a fixture
table, and get it merged. The gallery's entries were written by people like you; yours can join
them (`prismpath/gallery/README.md`).

---

## The developer's road

**Stage D1 — the toolchain loop (30 min).** `pip install -e .`, then: `prismpath init` →
`prismpath validate flow.md` → `prismpath test flow.md` → `prismpath graph flow.md`. Read
`GETTING_STARTED.md` Paths 2–3 as you go. Then deliberately write a broken flow (unreachable node,
a `when` edge shadowed by `always`) and watch `validate` name each mistake.
**✓ Done when:** `init → validate → test` is green and you've seen validate catch two bugs you
planted.

**Stage D2 — wire a real worker (1 hr).** Three rungs, cheapest first: (1)
`prismpath run flow.md --agent ollama:llama3.2` — a local model, one flag; (2) `cli_agent(["claude",
"-p"])` — any CLI as the worker (`PrismPath/cli_worker.py`); (3) a plain Python callable. Learn the one
contract they all share: return text (routes semantically) or JSON fields (routes exactly), raise
on failure (routes the **error tier** — add `-> retry: on error when error_count < 3` and see a
retry budget you can *read*).
**✓ Done when:** one flow routes off a real model's JSON on a `when` edge, and a forced worker
crash lands on your `on error` edge instead of a stack trace.

**Stage D3 — durability, fan-out, and packs (2 hrs).** `checkpoint.run_durable` a flow that
waits (`-> resume: on event approved`); kill the process; resume it. Fan out with `@spawn` (the
`fanout_review` template ships the parent AND child). Then build a **worker pack**:
`prismpath plugins --new mytools`, `pip install -e .`, bind it in a document with
`@worker(mytools.hello)`, and verify with `prismpath plugins --check flow.md`.
**✓ Done when:** a killed run resumes correctly, and `prismpath plugins` lists your pack as
`[entry-point]` with its outcome carrying `_worker` provenance in the transcript. **Capstone:**
a flow + worker pack pair where `prismpath ci-report` comes back green.

---

## The engineer's road

**Stage E1 — the guarantees (1 hr).** Read `SPEC.md` §4 (the predicate sandbox and tiers) and run
`prismpath validate` / `prismpath lint` on the gallery. Internalize the two load-bearing facts: the
engine is **pure** (no I/O, no clock — everything operational lives in the harness), and `when`
predicates **never execute worker-influenced strings** (the fuzz-gated sandbox). Workers are
arbitrary code *you chose* — the trust boundary is routing, not execution.
**✓ Done when:** you can state what the sandbox does and does not protect, in two sentences,
accurately.

**Stage E2 — reproducibility and the dial (1.5 hrs).** `prismpath lock` a flow with semantic edges
and read the lockfile: committed vectors + an embedder fingerprint; set
`prismpath_LOCK_POLICY=refuse` and watch drift become a loud failure instead of a quiet regression.
Then the dial: read `prismpath/comparisons/README.md` — accuracy per LLM-call is a **knob** (δ, or the
calibrated τ with its finite-sample bound), measured across a whole frontier (90.0% @ 160
calls/1k → 98.0% @ 507). Decide where *your* workload sits on it.
**✓ Done when:** you can explain to your team why 83.7% at 383 calls and 99% at 1000 calls are
the same system at two settings — and which setting your SLA wants.

**Stage E3 — operations (2 hrs).** Wire the GitHub Action (validate + fixtures as the gate, the
sticky PR comment as the review surface). Point the OTel decision-spans at the Grafana/Jaeger/
Datadog you already run — margin, top-1/top-2, escalated-or-not arrive as span attributes, not as
a new pane of glass. Check `prismpath portable` on your flows: a P0 flow runs on the dependency-free
JS kernel (browser, edge, appliance) certified by the frozen conformance vectors. For long-lived
runs, set `@state_bound(transcript=N)` and confirm the checkpoint payload stays flat.
**✓ Done when:** a PR that breaks a fixture fails CI with the comment explaining why, and your
tracing backend shows a routing decision with its margin. **Capstone:** the escalation queue in
production — a flow that suspends to a human with an evidence packet, resumed with `choose=`,
every decision in the audit trail.

---

## The SecOps road (the beachhead: alerts, playbooks, containment)

*How the vocabulary lands for you:* a **flow** is a playbook that actually executes; a **worker**
is an enrichment step or tool; **escalate** is tier-up; the **prefilter** is verdict reuse with a
safety monitor; **@field_only** is the prompt-injection boundary.

**Stage S1 — the severity playbook (30 min).** `prismpath init --template incident_severity`. Read
it: hard severity policy as `when` edges (`data_at_risk`, `error_rate`), judgment as semantic
edges. Run the fixture table. Then read the [SOC triage case study](PrismPath/PRISMPATH_USECASE_blue_team_soc_triage.md)
— a real Wazuh deployment, including the measured verdict-reuse result (58% hit rate, **zero
unsafe downgrades**: the cache never reused a benign verdict where the fresh decision would have
been more severe).
**✓ Done when:** `prismpath test incident_severity.md` is green and you can say which edges are
policy and which are judgment — the same split your escalation matrix already makes.

**Stage S2 — containment behind a human gate (1 hr).** Author a response flow where the
destructive action (isolate host, disable account) sits behind a gate: the worker sets
`needs_human`, the run **suspends with the evidence packet**, and only `choose=` resumes it. Add
the adversarial edge case: alert text is *attacker-influenced* input — mark triage nodes
`@field_only` so routing consumes only declared structured fields, never raw prose, and run
`prismpath lint` to see the polarity check flag negation-mirror edges ("is not malicious" vs "is
malicious" — the failure class embeddings are worst at).
**✓ Done when:** your containment flow cannot reach the destructive node without a recorded human
decision, and `validate` proves it (the only inbound edges go through the gate).

**Stage S3 — the deployment shapes (1 hr).** `prismpath portable your_flow.md`: a P0 (fields-only)
triage flow runs on the dependency-free JS kernel — air-gapped, no Python, no model. For the
connected shape: `prismpath lock` the semantic edges and set `prismpath_LOCK_POLICY=refuse`, so routing
in the SOC can never drift from what was reviewed.
**✓ Done when:** you know which of your playbooks are P0 (edge-deployable) and which need the
full stack — and why that boundary is exactly the policy/judgment split from S1.

---

## The auditor's road (verify everything, run nothing)

*How the vocabulary lands for you:* the **flow** is the control description — and, uniquely, the
control *implementation* is the same document; the **lockfile** is change control with evidence;
the **transcript** is the record; the **escalation queue** is a segregation-of-duties point.

**Stage V1 — the control description (30 min).** Read any gallery flow. Everything that governs
routing is on the page: the edges are the control logic, the fixture table is the control's test
evidence, `prismpath validate` is the automated review. There is no second place to look — no code
path that overrides the document.
**✓ Done when:** you can state the control ("billing disputes over $500 route to a manager") by
quoting a line of the artifact, not a policy PDF that may or may not match production.

**Stage V2 — reconstruct one decision (45 min).** Take a finished run's checkpoint (a JSON file).
For any hop, answer *who decided and on what evidence*: the `steps` record names the tier that
routed it (`used`: deterministic / embed / llm / human / error), the transcript holds the
outcome it routed on, `_outcomes` carries `_worker` provenance (which installed tool produced
it), and a human decision appears as its own transcript entry (`decided_by: human`). The
checkpoint also binds the **flow hash** — a run cannot be resumed against a silently edited
document; it refuses.
**✓ Done when:** you reconstruct a full decision trail from artifacts alone, without asking an
engineer a single question. That sentence is the audit pitch.

**Stage V3 — change control (45 min).** Review one merged process-change PR: the diff is prose
(readable), the fixture row asserts the new behavior, the flow-report comment shows topology
before → after, and the lockfile diff proves the routing change is *exactly* the reviewed change
and nothing else. Where the ledger is in use, each gate-passing unit is a **proof-commit** — an
append-only git history where done-ness is a fold over the log, not a status field someone can
edit.
**✓ Done when:** you can evidence "routing changes only by reviewed diff" for a sampled change,
end to end. **Capstone:** write the one-page control narrative for your compliance framework
mapping each claim to its artifact — you will find you never needed a screenshot.

---

## The decision-maker's hour (no exercises — five questions, defensibly answered)

Read: the README first screen (10 min) · `prismpath/comparisons/README.md` including *where PrismPath loses*
(15) · the `GETTING_STARTED.md` scoreboard (5) · `SPEC.md` §1–2 (10) · `SECURITY.md` (10) · this
plan's budget table (5). Then confirm you can answer:

1. **What's the lock-in?** Approaching zero: the artifact is Markdown in *your* git; the format is
   an open spec with frozen conformance vectors (any runtime that passes them is conformant, by
   definition); a dependency-free kernel already exists in a second language. If the project
   vanished tomorrow, your flows remain readable process documentation.
2. **Is it better, or just different?** Measured, including the losses: ~2.6–6× fewer model calls
   at an accuracy you *choose* on a smooth dial; the external arms win on out-of-box accuracy and
   parallel execution, and the comparison doc says so in its own table.
3. **What does adoption cost the team?** The budget table below — and the cheapest on-ramp needs
   zero runtime commitment: teams adopt the linter and CI gate months before the engine.
4. **What's the security posture?** A pure engine (no I/O, no clock), a fuzz-gated predicate
   sandbox (routing never executes worker-influenced strings), local-model support (nothing has
   to leave your network), and workers that are code *you chose* — the same trust decision as a
   dependency.
5. **What happens at scale and over time?** Locked routing is bit-reproducible across installs;
   escalation thresholds carry finite-sample statistical bounds instead of vibes; long-lived runs
   bound their own state; and the conformance suite makes additional runtimes a refereed sport
   rather than a fork risk.

**✓ Done when:** you can defend the bet — and its exit cost — to a board or a security review
without scheduling a vendor call.

---

## Sidebar — the seventh person: the human in the queue (10 minutes)

Someone on your team will meet this system only as *the person an escalation goes to*. Their
entire required knowledge: a suspended run hands you an **evidence packet** (the node, the
outcome it stalled on, the candidate routes); you pick one; your choice resumes the run and is
recorded in the transcript as a first-class decision (`decided_by: human`). You are not a
fallback — you are a tier, and the audit trail treats you as one.

---

## Stage Ω — the convergence exercise (the core three, 1 hour, the point of everything)

Run the loop once, live, with all three personas on one real (or realistic) process:

1. **The analyst** edits one edge in the flow — a genuine rule change — and adds the fixture row
   that asserts it. Opens the PR.
2. **The developer** confirms the worker emits the field the new edge reads (or adds it —
   `@emits` declares it).
3. **The engineer** watches the gate: validate clean, fixtures green, the before→after topology
   in the PR comment; merge changes production routing, and the lockfile guarantees the change is
   *exactly* the diff and nothing else.

**✓ Done when:** the merge happens and each persona can honestly say which part of the artifact
is theirs. The analyst owns the edges. The developer owns the workers. The engineer owns the
guarantees. **Nobody owns a translation layer between them — that's the part you deleted.**
(If you have an auditor, invite them to observe and then sample this very change afterward using
their Stage V3 — the freshest possible evidence that the loop works.)

---

## Budgets and the map

| | Stage 0 | Stage 1 | Stage 2 | Stage 3 | Ω |
|---|---|---|---|---|---|
| analyst | 15 min | 30 min | 45 min | 45 min | 1 hr |
| developer | 15 min | 30 min | 1 hr | 2 hrs | 1 hr |
| engineer | 15 min | 1 hr | 1.5 hrs | 2 hrs | 1 hr |
| SecOps | 15 min | 30 min | 1 hr | 1 hr | 1 hr |
| auditor | 15 min | 30 min | 45 min | 45 min | (observer) |
| decision-maker | — | — one hour total, reading only — | | | — |
| the human in the queue | — | — ten minutes, the sidebar — | | | — |

Artifact map: playground (`prismpath/portable/`) · `GETTING_STARTED.md` (install paths, honestly counted) ·
`prismpath/AUTHORING.md` (the full authoring reference) · gallery (`prismpath/gallery/` — every entry is a starter:
`prismpath init --template list`) · `SPEC.md` (the format, normative) · `prismpath/comparisons/README.md` (the
measured trade-offs, including where this system loses) · editor surface (`prismpath/editor/vscode/`) ·
plugins (`prismpath plugins`, `prismpath/AUTHORING.md`'s `@worker` section) · papers (`prismpath/docs/papers/`, when you
want the full argument).

A note on depth: this plan makes you *fluent*, not exhaustive. The system will still route
correctly if the analyst never learns what an embedding is, the developer never reads the κ
statistics, and the engineer never writes a flow from scratch. That asymmetry — everyone
productive without everyone knowing everything — is what "the document is the interface" buys.
