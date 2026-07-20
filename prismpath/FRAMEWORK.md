# PrismPath FRAMEWORK — the operating methodology

How PrismPath's control plane directs an AI-swarm project, distilled from a real spec-driven build. The
thesis: a human holds the VISION, that vision is compiled into **one spec per script**, and a local-LLM
swarm builds each spec as a **feature sprint** against deterministic **gates**, steered by
**oblique-strategy dice**.

> The concrete examples below (a `GAME_DESIGN.md` umbrella, `.luau` modules, an `EnemyDef` drift, a
> Roblox client) come from the **reference project** — a game built via the optional `plugins/roblox`
> gate. The methodology and every lesson are target-agnostic; only the examples are Roblox-flavored.

## The pipeline
```
VISION (human, in conversation)
   → UMBRELLA design doc (GAME_DESIGN.md) — the cohering whole; lore, loops, pillars, the ONE ironclad contract
   → SPEC-PER-SCRIPT (specs/<Module>.md) — purpose, types/contract, behavior, deps, ACCEPTANCE CRITERIA
   → FEATURE SPRINTS (prismpath swarm) — council picks the next spec; cecli diff-edits the real tree to green
   → GATES dispose; DICE direct; human supervises the hard parts
   → playable, then iterate
```

## Why spec-per-script (not one mega-doc, not blank-slate)
- A swarm builds a **module** well when it has a tight, self-contained contract. One file = one spec = one
  sprint keeps the prompt small and the acceptance criteria checkable.
- This is a **FEATURE-sprint** engine, not a blank-slate generator. It excels at *extending a base* (we have
  ~30 systems + a playable hub). Blank-slate produces breadth without a spine; specs-against-a-base produce
  depth that integrates. Establish a thin playable base FIRST, then spec-driven feature sprints.

## The components and their jobs
- **Council (2-model, dice-driven):** decides WHAT to build next. Lean context (goal + coverage + file list),
  not the whole architecture. 3 gemma4 engineering voices + 2 qwen25 product voices for real vote diversity.
- **Dice (oblique strategy):** decide the DIRECTION. A *system* die (direction × provocation × scope,
  coverage- and balance-weighted) and a separate **World Lens** die (the physical/visual world) on a cadence
  knob (`SPRINT_WORLD : SPRINT_EXPAND : SPRINT_REFINE`). Dice widen the proposal distribution; gates dispose.
- **cecli (executor):** diff-edits the REAL tree to green (no whole-file regen → no require-scrambling).
- **Gates = the DEFINITION OF DONE, machine-enforced** (the key discovery): a build is not green until it
  *compiles + types + builds + tests + is wired + has a world + is reachable by the player*. Declare an
  invariant in the spec → confirm it with a gate, never with prose alone (`wiring_check`, `world_check`,
  `presentation_check`). "Never write a completeness claim a gate doesn't enforce."
- **Auditor (qwen, idle-time judge):** a consistency reviewer that, after each build, checks the changed file
  against a canonical `GLOSSARY.md` and flags contract drift (a type/field/signature named differently than
  the glossary mandates). It runs on the otherwise-idle qwen25 coder in its window between gemma4 builds, so
  it's nearly free. ADVISORY, not a gate (an LLM judge is fuzzy) — it surfaces drift candidates a human or a
  follow-up deterministic check confirms. The glossary is what makes a small model reliable here: focused
  conformance-to-an-explicit-contract is a 7B's sweet spot. Opt-in via `SPRINT_AUDIT=1`.
- **Human as supervisor:** answers HELP escalations, and HAND-BUILDS the parts the swarm genuinely can't
  (Roblox client/UI, composition-root wiring, the playable storefront) — "agents propose, gates dispose,
  Claude unblocks the hard parts."

## Hard-won operating lessons (so far)
- **Lean the council context.** A 14KB prompt × 5 sequential dispatches = an 80s round that looks hung. Pass
  what the decision needs, nothing more (→ ~5s dispatches).
- **Oversized auto-refactor is a footgun.** Inlining a whole file into one LLM dispatch to "split" it hangs
  and corrupts mid-feature. Make size a *soft, advisory* signal; do structure work deliberately on green.
- **The model server clogs under hours of load** (orphaned long generations starve throughput on unified
  memory); restart to clear, and keep `gpu-memory-utilization` modest on a workstation you're using. But
  DIAGNOSE before restarting the server: a fresh 16-token probe returning in ~2s means the server is FINE and
  the slowness is elsewhere (build size / retry count), not a clog.
- **Cap retries to the build's COST, or a fixable RED becomes an infinite spin.** cecli `--max-reflections 5`
  × a slow large-context build = a ~20-min `CECLI_TIMEOUT` *per iteration*. If the RED is one the model can't
  self-fix (here: a `WorldAdapter` missing a `setupPlot` field the linter had added to the `World` port type),
  every iteration burns all 5 reflections → times out → restarts → spins forever, surfacing to the human as
  "cecli timeouts." Fail FAST (reflections=3 ≈ 10 min) and let the **3×-same-error auto-stuck detector ESCALATE
  to the human**, who hand-fixes the one hard edit and the swarm flows again. Retry budget must be < timeout ÷
  per-attempt cost, with margin.
- **World rounds edit the WIRING, so their builds are big and brittle.** Touching `main.server` + adapters +
  the port `Types` per round pulls a large focus into one cecli call (slow) and is where port/adapter type
  mismatches surface (the World-port spin above). Worth scoping the world-round focus tighter, or accepting
  that these are the rounds most likely to need a human unblock.
- **Drift is preventable with gates, not vigilance.** Dead modules, an unbuilt world, an unreachable surface,
  a stale blueprint — each becomes a gate or an auto-refresh, not a thing you remember to check.
- **The blueprint is a CONTRACT, not a status doc** — structural + behavioral expectations only; priorities
  and current-state are derived live (a red gate IS the priority), never authored into the contract.
- **Parallel spec authors DRIFT — author a SHARED GLOSSARY first.** Fanning out one agent per module spec is
  fast, but each independently invents names for the *cross-references* (Elements exported `ValueKey`; PetGems
  & Towers wrote `ValueId`/`EffectKey`; `damageMultiplier` scalar-vs-array; `EnemyDef` vs `EnemyDefinition`;
  `element` vs `elements`; chimera union SUM-vs-MAX). 10 specs → ~15 hard mismatches that would each be a build
  failure. THE FIX: author a `GLOSSARY.md` of canonical shared types + signatures FIRST, pass it to every spec
  agent as ground truth, and run a consistency agent after. This is the whole value of spec-driven — drift is
  caught + reconciled at the CHEAP (markdown) layer, never as expensive broken code. (Cost ~$0 to fix a name in
  a spec; a wrong type name discovered mid-sprint costs a stuck swarm.)
- **The GLOSSARY is authored in PASSES, and the last mile is the HUMAN's.** You can guess the shared NAMES up
  front, but you only DISCOVER the missing cross-module STRUCTS by normalizing against the glossary. Budget two
  passes + a hand-finish: pass 1 (conform to the names you guessed) surfaces the structural holes → GROW the
  glossary (e.g. chimera tool `colors`, the vein `NodeDef`, the full `PlotManager` API) → pass 2 (conform to the
  now-complete contract) converges to a handful of residuals → HAND-FIX the last mile, because LLM passes
  ASYMPTOTE (4 residuals → 3 → …) and looping just burns tokens on diminishing returns. Close with a
  DETERMINISTIC grep sweep for the known anti-patterns (`EnemyDefinition`, `element = nil`, `assignPlot`) — a
  spec-layer gate that's cheaper and surer than a third fuzzy LLM verify.

- **Tasking a small (7B) model as a JUDGE takes four specific moves** (learned wiring the qwen auditor):
  (1) **Kill the tool instinct explicitly** — an agentic coder model, handed a filename, will emit a
  `read_file` tool call instead of reasoning over the inline content; the persona must say "you have NO tools,
  the full content is pasted below, never emit JSON/a tool call." (2) **Scope to contract-surface** — it will
  flag local variable/parameter/helper names as "drift"; tell it to audit ONLY exported types, glossary-
  function calls, and glossary-type fields, and to IGNORE local names. (3) **Few-shot with BOTH a flag and an
  ignore** — one worked example showing what to flag AND what to leave alone; bias toward flagging (advisory,
  human reviews). (4) **Deterministic post-filter** — strip the model's nonsense `DRIFT X -> X` self-flags in
  code, not prose. Net: tight, scoped persona + a code-level safety net beats a wall of prose rules (which a 7B
  ignores). Keep the system prompt SHORT — long rule-piles degrade small-model adherence.

- **Spec-driven builds must EMBED the spec, not NAME it — and the auditor must DISPOSE, not just advise.**
  Pointing a cecli build at "implement per specs/Elements.md" fails: gemma4-in-cecli can't reliably read files
  (the tool-call misfire), so it WINGS the module — it invented a FIRE/WATER/VOID stateful `Elements` instead
  of the gem schema. Embed the full `<Module>.md` + `GLOSSARY.md` text directly in the build instruction.
  Second half: the qwen auditor CORRECTLY flagged the drift (strongAgainst→strongVs, tint→color, …) — but
  it was ADVISORY, so the non-conformant leaf sailed through the gate (a leaf core compiles regardless of its
  internal names; only its CONSUMER or the auditor catches the drift), and the next module broke against it.
  Lesson: in spec mode the auditor's drift flags should trigger a corrective rebuild, not just a log line —
  "agents propose, gates dispose" applies to CONFORMANCE too. Also strip the playable-app build clauses
  ("WIRE IT into AppService", "SURFACE IT") for pure cores — they're built in isolation and integrated later.

- **Three execution modes — and DETERMINISM is the default, council is the exception.** (1) `council` (dice-
  driven, free expansion) — for open-ended "what should this game grow into" exploration. (2) `spec` mode
  (`SPRINT_SPEC_ORDER`) — build a flat list of module-files, each from its embedded `specs/<M>.md`, in order.
  (3) `kg` mode (`SPRINT_SPEC_FILE` + `SPRINT_KG`) — the most deterministic, and the one PrismPath was made for:
  ONE structured spec whose `##` are REQUIREMENTS, `### Contract` the binding interface, `### Definition of
  done` the gate-checkable target (pseudo-code where it helps). The agent INGESTS the whole spec, instantiates
  a **knowledge graph** seeded from the spec itself (authored, not LLM-derived — so the graph is deterministic),
  then builds exactly ONE node per pass — the first `pending` node whose `depends_on` are all `done` — embedding
  only that requirement's section + the GLOSSARY + the specs it names + what is already built. On a green gate
  the node flips to `done` and records its `produces`/`exports`, so later steps READ the graph instead of
  re-deriving context (this is what stops a step from re-inventing a module an earlier step already built). The
  KG is the source of truth for ordering, progress, and cross-step memory. Per-step gates run at the level the
  intermediate state can satisfy (`PLAYABILITY_GATE=0` while modules are un-wired); the phase's stricter
  definition-of-done is a FINAL gate after the wiring step.

- **Frontier auto-unblocker (Antigravity `agy`) — the tiered fleet, realized.** When the local swarm is
  AUTO-STUCK (3× the same gate error), run_sprint now hands the failure to `agy` (a frontier agentic CLI) to
  fix autonomously BEFORE escalating to a human (`SPRINT_AGY=1`; sandboxed; one shot per error signature;
  human-HELP fallback intact, so it's safe + opt-in). This automates the "Claude unblocks the hard parts"
  role that was previously HUMAN-RELAYED — the bottleneck that let the swarm spin for hours overnight.
  Three gotchas that cost real time: (1) **`agy --print` takes the PROMPT AS ITS FLAG VALUE** — `--print`
  must be ADJACENT to the task and LAST in argv, else it consumes the next token (`--add-dir`) as the prompt
  and the agent dutifully explains that flag on every run (this looked like "roaming / off-task" but was a
  malformed invocation). (2) **`--model <id>` is silently ignored** — it ran the default (3.5 Flash) whether
  given the display name OR the binary's `gemini-3.1-pro` id; the dependable lever is agy's CONFIGURED default
  model, not the flag. (3) **`--sandbox` restricts the terminal, not file access** — pair it with
  `--dangerously-skip-permissions` for autonomous file edits with a bounded blast radius. Always smoke-test a
  new CLI backend with a trivial known-answer edit before trusting it unattended.

## Open framework work
- Auto-refresh the umbrella/specs when they lag the tree. A `spec_check` gate (every module has a spec; every
  spec maps to a module). Make the per-script spec format a template the council can consume directly as a
  feature-sprint nudge. Promote this from notes → a real CLI (`prismpath spec`, `prismpath sprint <spec>`).
