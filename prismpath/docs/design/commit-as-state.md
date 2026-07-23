<!-- Provenance: synthesized 2026-07-10 by a multi-agent design workflow (commit-as-state-design, 16 agents: understand → 5 designs → 3 judges → 4 adversarial critics → synthesis). Winner: Flow-Ledger (2/3 first-place votes). Kept as the roadmap design record; not part of the public export. -->

# Design Brief: Commits-as-State for prismpath — a git ledger of gate-green proofs

**Author:** Lead architect · **Date:** 2026-07-10 · **Status:** recommendation, GO with a de-scoped first slice

---

## 1. The reframing — why commits-as-state beats checkboxes here

The checkbox idea died on a hard invariant: prismpath's parser is one-way and lossy. `flush()` (parser.py:74) folds every non-heading, non-edge line — including a `- [ ]` — into `node.instruction`, and edge lines are hoisted out of position; writing "done" back into the `.md` corrupts the flow on its next parse and violates the AUTHORING §9 rule that "the MD file stays the single read-only source." Commits-as-state doesn't fight this invariant, it *defends* it: durable state moves entirely out of the human-authored artifact and into git's own append-only Merkle DAG. A commit is created only when the machine definition-of-done — a gate-green validation (run_sprint.py:1269) — fires, so the commit's *existence* is a content-hashed, tamper-evident, durable proof that the unit passed, and `git log` alone reconstructs where the agent left off. That is exactly what a checkbox tried and failed to be (a mutable mark inside the read-only file), delivered for free by a tool already on the box (git 2.43.0), against a read-only `.md` that is never touched.

---

## 2. RECOMMENDED design — the Flow-Ledger, refined

The recommended design is the **Flow-Ledger**: one commit per gate-green unit on a **dedicated per-run orphan ref**, correlated to the flow node by git trailers, with resume defined as a projection over `git log`. It won the judging (2 of 3 first-place votes, top aggregate) because it lands all three discriminators at once — the *gate-green* unit boundary, a *state ref that survives the `FRESH` wipe and isolates concurrent runs*, and *zero engine changes*. Below it is refined by grafting the runner-up ideas the judges called out and by answering the adversarial critiques (which were substantiated against source and are real).

### Where state lives, and why

**A dedicated orphan ref in a separate git dir — not code commits, not git notes.**

- **Not code commits on a working branch.** SPRINT_FRESH=1 (the default) `shutil.rmtree(PROJ)` at run_sprint.py:1207-1208 would delete any `.git` placed inside SPRINT_PROJ; a working-tree repo also collides with cecli (which is deliberately run with `--no-git`, run_sprint.py:289) and with any user/CI/swarm git the tree is shared with. **Decision (grafted from the interleaving critique):** the ledger is **always** a separate bare repo — `$XDG_STATE_HOME/prismpath/<flow-or-run>.git` — for build flows too, written via plumbing against a scratch index (`GIT_DIR=<state>.git GIT_INDEX_FILE=<tmp> git write-tree`), never `git add` in a live tree. If provenance-in-the-artifact is wanted, `git bundle` the run ref into the delivered zip at the end. This neutralizes the single biggest correctness hazard.
- **Not git notes / not tags.** Notes are decoupled from the DAG, need a separate refspec, and re-introduce the mutable-sidecar smell; tags are singletons that can't be re-created on a re-run without `--force`, breaking idempotency. Trailers live *inside* the content-addressed commit object and inherit git's Merkle tamper-evidence for free.
- **Orphan ref, one per run:** `refs/prismpath/runs/<run-id>`. It never needs a working-tree checkout (works identically for build flows that edit a source tree and routing flows that edit nothing), lives only in `refs/prismpath/*` (invisible to `git log`/`blame`/`bisect`/merge on `refs/heads` — no code-history pollution), and deleting a ref GCs a run atomically.

### The commit shape

One commit per gate-green **unit**. The unit is the gate-green edge — the one boundary every durable side-effect already keys off (`snapshot_green`, `kg_mark_done` both fire inside `if v["valid"]:`). Trailers are RFC-822, first-class in `git log --format=%(trailers)`:

```
prismpath: <unit-id> green  (<flow-name> run <run-id-short>)

<optional gate summary, e.g. "browser gate: 0 errs, biggest 812 tok">

Prismpath-Flow:        <flow-name>
Prismpath-Run:         <run-id>          # ULID, minted once per run
Prismpath-Unit:        <unit-id>         # THE resume key (see §2 correlation) — NOT the node name
Prismpath-Node:        <graph-node-name> # trace/human aid only
Prismpath-Seq:         <n>               # monotonic; disambiguates loop iterations & repeats
Prismpath-Gate:        green
Prismpath-Gate-Name:   browser|roblox|verify_staged|...
Prismpath-Output-Hash: sha256:<produced artifact only>   # in-toto/SLSA subject-hash (grafted from Proof-Trailer)
Prismpath-Input-Hash:  sha256:<node instruction + upstream done-set>  # DVC-style invalidation (build flows only)
Prismpath-Edge:        <chosen-target>   # REQUIRED for semantic edges: read on resume, never recomputed
Prismpath-Depends:     <id>,<id>         # build/KG flows only
```

**What each hash proves (grafted dual-hash distinction from Proof-Trailer Commits):**
- The **git tree hash** (implicit) is the *cumulative state-of-record* at that green transition — the correct thing to `git checkout` on resume, replacing `.lastgood`. In cecli build mode a later node edits files an earlier node produced, so the tree spans multiple nodes' bytes; it is a state snapshot, **not** per-node proof.
- **`Prismpath-Output-Hash`** is computed over *only this unit's produced artifact* (the KG node's `produces` subtree, or the single emitted draft/verdict blob). This is the genuine "node N produced exactly this output" attestation and the correct dedupe/invalidation key — it does not change when an unrelated file changes.
- **`Prismpath-Input-Hash`** expresses "done for *which* input" — a boolean checkbox can't. **Scoped to build/KG flows only** (routing flows have no `depends_on` DAG; per the critique, keep this trailer off routing units).

### The node ↔ commit correlation mechanism

The resume key is **`Prismpath-Unit`**, an explicit unit-of-work identity the *control-plane adapter* supplies — **not** the engine node name. This is the fix for a real blocker: for SOC/support flows every alert traverses the *same* node names (`observe`, `classify`, `report`), and the domain unit (the alert id) lives in runtime `state['alert']['id']`, which appears in **no** `StepLog` field. Keying on the node name would collide across every alert and every loop iteration. So:
- **Build/KG mode:** `Prismpath-Unit` = the KG node id (author-minted in the spec's seeded `json` block, already the `depends_on` key).
- **Routing mode:** `Prismpath-Unit` = the alert/ticket id from runtime state, passed by the adapter.
- **Loops** (a node revisited N times, engine.py:61 tracks `visits`): fold on the composite **`(Prismpath-Unit, Prismpath-Seq)`**, never `Prismpath-Node` alone. A static-analysis lint **fails closed** on a flow with a cycle but no per-iteration unit key.

`Prismpath-Node`/`Prismpath-Edge` come straight from `StepLog(node, target, ...)` (engine.py:89) — the payload §10 already advertises for a trace.

### Resume semantics — idempotent by construction

Resume is a pure left-fold over `git log <ref>`, mirroring `kg_next` (run_sprint.py:1123-1150) with the done-set sourced from git instead of `.kg.json`:

1. `done = { Prismpath-Unit : (Output-Hash, Edge) for each commit with Prismpath-Gate: green }`, newest-wins per `(Unit, Seq)`.
2. `next` = first pending unit whose `depends_on ⊆ done` (build) or first alert with no green commit (routing).
3. **Re-run the gate at the top of the loop (run_sprint.py:1260) — always.** A commit is never a skip-token; resume re-validates, so a partially-applied or corrupted unit self-heals.

Idempotency rests on two facts already true in prismpath: deterministic-first routing is reproducible (predicates safe-AST allowlist, engine.py:66-80), so re-deriving `next` yields the identical node; and the gate is re-run every iteration. **For semantic (non-deterministic) edges, resume READS `Prismpath-Edge` and never recomputes the route** — the Temporal non-determinism guard. Because a routing-flow resume must re-enter *mid-graph*, the engine gets one purity-preserving addition: an optional `start_node` + injected `state` on `run()` (still no I/O, agent still injected) so the control plane can re-enter at the node after the last committed unit and force the recorded edge. This is the one honest deviation from "zero engine changes" and it is scoped to routing-flow resume; build flows resume via the outer run_sprint loop and need no engine change.

### Worked example

**Flow (KG-mode, read-only spec, seeded nodes):**
```
auth  (depends_on: [],           produces: [auth.luau])
store (depends_on: [auth],       produces: [store.luau])
ui    (depends_on: [auth,store], produces: [ui.luau])
```
**The git log it produces** (bare repo `~/.local/state/prismpath/roblox-integration.git`, ref `refs/prismpath/runs/01HTX`):
```
$ git log refs/prismpath/runs/01HTX --format='%h %s'
c3a1  prismpath: ui green    (roblox-integration run 01HTX)   [Unit: ui    Gate: green  Output-Hash: 9f2c… Depends: auth,store]
b2f0  prismpath: store green (roblox-integration run 01HTX)   [Unit: store Gate: green  Output-Hash: 1a90… Depends: auth]
a19d  prismpath: auth green  (roblox-integration run 01HTX)   [Unit: auth  Gate: green  Output-Hash: 04ee…]
```
**Resume after a crash with `ui` half-built (gate red):**
```
done = {auth, store}      # folded from the two green commits
next = ui                 # first pending whose depends_on ⊆ done
→ git checkout store's tree, re-run ui's gate over it, rebuild ui, commit c3a1.
```
The `.md` was never read for state; no pointer was consulted; `git log` alone said where to restart.

---

## 3. The non-code-flow answer (no papering over it)

**Verdict: it works for SOC/support flows — but not "for free," and the design's own claim that it reuses the existing seam is false to the code. Here is the honest version.**

The SOC flow *is* stateful — the premise "triage edits no repo so has nothing to commit" is refuted by wazuh_triage_agent.py: it writes a processed-alerts `STATE_FILE` (:68,185), containment drafts (:321), reports (:383), and `verify_staged` (:333) is a real on-disk gate. Any flow with a gate produces content-bearing output, which is exactly what a commit content-hashes. So the *discriminator is "does the flow have a gate?"*, not "does it edit code?"

**But three things must be built honestly, not hand-waved:**

1. **The SOC path does not run through run_sprint.py's loop.** It runs `wazuh_triage_agent.main → engine.run → return`, once per alert. There is no `if v["valid"]` edge, no `snapshot_green` seam. Committing for routing flows requires a **new** `prismpath.ledger_runner` that wraps `engine.run`, drives a per-alert loop, and interposes a commit after the gate node. This is genuine new code, not the "already the shape of run()" claim. Budget it as such.
2. **The engine has no gate concept.** `StepLog.info` carries routing metadata, not a gate verdict, so the runner cannot infer which node is a gate. Make it explicit: an `@checkpoint(proof=<state-key>, gate=<state-key>)` node annotation (the §10-sanctioned slot) names *which* artifact is the proof and *which* field is the pass signal — `verify_staged`'s `staged_ok` and `draft_path` become a contract, not a guess.
3. **Routing handlers are not idempotent.** `watchlist`/`benign` *append* to JSONL (wazuh_triage_agent.py:345,355); `report` writes a fresh timestamped file. The "gate is re-run so it self-heals" guarantee covers the *ledger*, not these side effects — a crash between the append and the commit, then resume, double-appends. Fix: either key each append (upsert on `(alert_id, rule_id)`) so a replayed unit is a no-op, or gate the side effect on the done-set *before* it runs. `@checkpoint`-eligibility requires an idempotent effect, and lint for it.

With those, a stopped triage run resumes cleanly: `git log` yields the processed alert ids (subsuming `STATE_FILE.processed`), the committed verdict/draft is the tamper-evident proof-of-verdict, and the flow re-enters at the first alert with no green commit. **Honest caveat:** for a single-blob verdict, git's tree-hash advantage over a plain `sha256` field largely evaporates — the routing class gets *tamper-evidence and audit*, not a new resume capability the existing `STATE_FILE` didn't already provide. That is a real reason to keep routing-flow ledgering *optional* (see §5).

---

## 4. What it unlocks (ranked, tied to the roadmap)

1. **Gates-as-DoD becomes a durable, content-addressed record.** Today a green gate is a transient event in an ephemeral run (state discarded at engine.py:96) — the proof evaporates when `run()` returns. A gate-green commit makes "was this unit done, or did an agent just claim it?" answerable from `git log` forever, hardening the framework thesis ("never write a completeness claim a gate doesn't enforce"). **Honest scope:** the commit is a *tamper-evident record of the state the control plane blessed*, not cryptographic proof the gate re-executes to green — the design itself re-runs the gate on resume rather than trusting the commit. Call it what it is.
2. **Area 6 durable/resume + ask-a-human, with zero `.md` mutation.** This is the highest *roadmap* value: resume derives from `git log` while the flow file stays read-only, sidestepping the parser-lossiness blocker that has no other clean answer. `needs_human` becomes a stop reason; the run suspends by committing an evidence packet, and `resume --choose <edge>` re-enters from that commit's recorded edge (grafted from Checkpoint-Engine).
3. **Sub-flows / composition & content-addressed invalidation.** `Prismpath-Input-Hash` expresses "done for which input," so a changed upstream correctly re-opens its dependents — the substrate a boolean checkbox can't support and the foundation for composing/caching sub-flows (build flows only).
4. **The SOC control plane.** One mechanism, one commit shape, spans build and triage; each alert gets a per-run tamper-evident audit trail with no code branch touched.
5. **Audit/provenance story — the tiering.** Git is the **PUBLIC durable-proof tier** (content-addressed state, reproducible, diffable, no extra dependency). The **MMR stays the CWM premium multi-party tier** — it already exists (mmr_audit.py, excised from the public repo as a moat), gives compact O(log n) inclusion proofs, and represents non-repo control actions git cannot. They *compose*: an MMR leaf carries the ledger's tree/output hash (see §5 for why not the commit sha) so the two Merkle layers cross-certify rather than duplicate. **Honest note:** git's Merkle chain is strictly *weaker* than the MMR for audit (no compact inclusion proof without walking history) — so git's justification is content-of-output + tooling, *not* out-auditing the MMR.

---

## 5. Risks & mitigations (from the stress phase) — including the real blockers

| Risk (severity) | Real? | Mitigation |
|---|---|---|
| **SOC path has no gate-green seam; needs a NEW runner** (blocker) | Yes — verified: `main → engine.run → return`, no loop | Build `ledger_runner` as explicit new code; re-scope effort (§6). Do not claim reuse of the run_sprint seam. |
| **Node-name correlation collides across alerts & loops** (blocker) | Yes — alert id is in runtime state, not `StepLog` | Fold on `Prismpath-Unit` (adapter-supplied) + `Prismpath-Seq`, never node name. Static-analysis lint fails closed on a cycle without a per-iteration key. |
| **`FRESH=1` rmtree wipes an in-tree `.git`; shared-repo GC/mirror interleaving** (major) | Yes — run_sprint.py:1207 | Ledger is **always** a separate bare repo under `$XDG_STATE_HOME`; scrub `GIT_DIR/GIT_WORK_TREE`; never `git add` in a live tree. |
| **Semantic-edge resume divergence** (major) | Yes — engine re-routes from scratch | Record `Prismpath-Edge`; on resume READ it, never recompute. Add `start_node`+`state` to `run()` (purity-preserving) so mid-graph re-entry can force it. |
| **Non-idempotent routing handlers double-apply on replay** (major) | Yes — JSONL appends at :345/:355 | Key/upsert the appends, or gate the side effect on the done-set before running it; `@checkpoint`-eligibility requires an idempotent effect. |
| **Concurrent/relaunch writers lose commits (non-atomic update-ref)** (major) | Yes | CAS on every ref write (`update-ref <new> <expected-old>`), retry-with-re-fold on mismatch; per-run flock; reap orphan PID before resuming a run-id. |
| **git as a new hard dependency; "unusable" ≠ "absent"** (major) | Yes — today zero git in control plane | `SPRINT_LEDGER=1` flag; wrap every git op in try/except that falls back to `.lastgood`/`.kg.json`/`STATE_FILE` on *any* failure (missing, dubious-ownership, lock). Ledger stays strictly off the critical path. |
| **Commit SHA is non-reproducible (dates/committer)** (minor) | Yes | Pin `GIT_*_DATE` + a constant `prismpath`/`prismpath@local` identity (already the repo's config); cross-reference the **tree/Output-Hash** (content-deterministic), never the commit sha, for MMR anchoring. Never leak a commit hash into a `when` predicate (guards AUTHORING.md:232). |
| **"Squash to compact" breaks trailers & anchors** (minor) | Yes — squash drops intermediate trailers | Ledger is append-only; remove the squash suggestion. Compaction, if ever needed, writes one new checkpoint commit enumerating every collapsed unit — never a git squash. |
| **Multi-node commit tree ≠ per-node proof** (major, framing) | Yes — cecli edits shared tree | Tree = cumulative state snapshot; `Output-Hash` over the node's `produces` subtree only. Drop "tree hash = per-node proof." |

**Where a plain JSON checkpoint is simpler — stated honestly.** For the *only* thing Area 6 actually names — deterministic durable resume + ask-a-human — a plain JSON checkpoint is strictly cheaper (~20-30 LOC, the atomic `os.replace` pattern already at run_sprint.py:1082), ships today, adds no git dependency, and satisfies the plan's success criterion verbatim ("serialize state to JSON on suspension … deliberately minimal durable execution"). The ledger's genuine deltas over that — Merkle-chained order, content-addressed output bytes, input-hash invalidation — are (a) partly already covered by the MMR the project chose to excise, and (b) solutions to problems (multi-party audit, upstream invalidation) no shipped requirement asks for yet. **The intellectually honest position: the JSON checkpoint is the resume mechanism; the git ledger is an *optional provenance layer* that must earn its keep against un-excising the MMR when a concrete buyer needs cross-party tamper-evidence.**

---

## 6. Phased plan

Interaction with existing gates, up front: the **pytest suite** must gain ledger unit tests and — critically — a *repo-isolation* test (run under a dir that *is* a git repo; assert its `refs/heads`, index, and reflog are byte-identical before/after a ledger commit). The **static-analysis/fuzz gates** get one new rule: reject a flow with a cycle but no per-iteration unit key (fail closed), and assert no ledger data reaches a `when`-predicate context. The **git identity already in the repo** (`prismpath dev` / `prismpath@local`) is what we pin for reproducible commit identity — pass it explicitly (`-c user.name=… -c user.email=…`) so nothing is inherited or missing headless.

**Slice 0 — FIRST valuable slice (small, ~0.5 day): the Area-6 JSON checkpoint, shipped as planned.** Serialize `(state, transcript, visits, pending node, candidate edges+scores, chosen edge)` to a JSON sidecar (atomic `os.replace`) at suspension; `resume` re-parses the read-only `.md`, loads the JSON, re-enters. **DoD:** same checkpoint + same choice ⇒ identical continuation; `.md` untouched; a crash-and-resume test passes. This delivers durable resume *now*, dependency-free, and de-risks everything downstream. **Do this before the ledger** — it is the load-bearing path and the ledger's safe fallback.

**Slice 1 — `prismpath/ledger.py` + build-flow wiring (medium, ~1 day; delegatable).** Git-plumbing wrapper (`init_ledger`, `commit_unit`, `done_set`) writing only to `refs/prismpath/*` in a bare `$XDG_STATE_HOME` repo via `hash-object`/`write-tree`/`commit-tree` + CAS `update-ref`; wire into the green transition behind `SPRINT_LEDGER=1`, replacing `kg_next`'s done-set source (the depends_on selection is unchanged). **DoD:** `done_set(commit_unit(...)) == expected` round-trips a known KG done-set; a KG resume path diffs identically vs the `.kg.json` sidecar; the repo-isolation pytest passes. This is a clean, checkable unit to hand to agy (verify its claims by re-running the projection yourself).

**Slice 2 — the routing runner + SOC adapter (medium, ~1 day).** New `ledger_runner` wrapping `engine.run` in a per-alert loop; `@checkpoint(proof=, gate=)` annotation parsed in parser.py and read by the runner; SOC handlers made idempotent (keyed appends); `Prismpath-Unit` = alert id; `STATE_FILE.processed` subsumed by `done_set`. **DoD:** a triage run stopped mid-alert resumes at the first alert with no green commit; no duplicate watchlist lines on replay; verdict blob hash matches `Prismpath-Output-Hash`.

**Slice 3 — resume `--choose <edge>` + semantic-edge replay + MMR anchor (small, ~0.5 day).** `start_node`+`state` on `run()`; recorded-edge-read-not-recomputed enforced; an MMR leaf carries the tree/Output-Hash. **DoD:** a semantic-routed run resumes on the *recorded* edge (not a re-route); MMR leaf cross-verifies against the ledger tree hash.

---

## 7. GO / NO-GO

**GO — conditional and de-scoped.** The mechanism is sound, preserves every §9 invariant (the ledger is the read-only-`.md` invariant's *best defender*, not a threat to it), and the adversarial critiques surfaced real gaps that are all fixable, none fatal. But the design as originally framed (ledger *replaces* `.lastgood` + `.kg.json` + `STATE_FILE` as the primary resume path) is over-engineered for its stated Area-6 goal, and its "one mechanism, both classes, for free" claim is false to the code.

**The recommendation is therefore a split:**
- **Ship durable resume as a plain JSON checkpoint first (Slice 0).** It is the honest, cheap, dependency-free answer to Area 6 and the ledger's fallback.
- **Ship the git Flow-Ledger as an *optional* provenance/proof layer behind `SPRINT_LEDGER=1`**, justified by content-addressed output proof + audit tiering (public git / premium MMR), *not* by being the resume mechanism.

**The exact first slice: Slice 0 — the Area-6 JSON checkpoint** (`(state, transcript, visits, pending node, candidate edges+scores, chosen edge)` serialized via atomic `os.replace` at suspension; `resume` re-parses the untouched `.md` + loads the JSON + re-enters; DoD = deterministic resume, `.md` byte-identical, crash-and-resume test green). It delivers the roadmap's actual requirement immediately, touches no engine internals, adds no dependency, and is the foundation the ledger (Slices 1-3) layers on only where content-addressed proof genuinely earns its coupling cost.