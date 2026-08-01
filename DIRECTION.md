# PrismPath — product direction notes (2026-08-01)

Strategic notes to keep in mind while developing PrismPath, from the Journeyman kernel-comparison
session. The through-line: **PrismPath is a specialist for the safety-minded, not a generalist.**
Lead with what it refuses to do; that is the moat.

## The positioning

Cater to users who need **determinism, auditability, portability, and certified routing** —
regulated, safety-conscious, reproducibility-first. Deliberately CEDE agentic expressiveness (tool
use, multi-agent, dynamic graphs) to LangGraph/CrewAI. "Others can have that all day." Trying to be
a generalist agent framework would dilute the only thing that makes PrismPath worth choosing.

## Measured comparison (Journeyman as the testbed, same lessons, swapped kernel)

- **LangGraph** (Python sidecar adapter): structural parity 79/79, advance parity 606/606 — it
  routes the deterministic curriculum identically, but brings **1 of 5** capabilities.
- **XState** (in-webview TS, closest paradigm — a lesson IS a statechart): parity 100% too; **2 of
  5** (it adds native single-step external-event routing).
- PrismPath's exclusive rows: **refuses a non-portable flow up front** (portability analysis),
  **certified locked P1 semantic routing**, **dual-implementation certification** against frozen
  corpora. No stock orchestrator gives these for free — that is why PrismPath is the default.

The parity is the *pluggability* proof (good for adoption); the capability gaps are the
*differentiation* proof (good for the safety pitch). Both matter; they are different slides.

## "Advanced state-machine features" — the fork in the road

XState-style features PrismPath lacks: hierarchical/nested states, parallel regions, history states,
invoked/spawned actors, entry/exit ACTIONS (side-effects), delayed transitions, tooling (visualizer,
devtools). Split them in two and treat the halves oppositely:

- **Side-effect / expressiveness features (actions, invoked actors, dynamic construction, arbitrary
  code in transitions): DO NOT BUILD.** They introduce side-effects and nondeterminism — the exact
  opposite of "the kernel makes a routing DECISION, it does not do WORK" (the line that keeps an
  audit ledger honest). Every one is more to certify and more untrusted surface. Building them
  *dilutes* the moat. This is the "agentic expressiveness" we cede on purpose.
- **Structure / rigor features: INVEST HERE.** The `advanced` energy goes into RIGOR, not feature
  count. `analysis.py` already proves reachability, no-terminal, four-tier shadowing, unbounded
  cycles, contracts. Extend toward exhaustive property proofs: determinism guarantees, liveness,
  "this flow can never reach state X," termination bounds, model checking. **XState and LangGraph do
  not compete on formal verification — own that category.** Hierarchy is the ONE
  expressiveness-adjacent feature plausibly worth it (large flows staying analyzable via composition
  — seeded by `@spawn`), but only if it preserves static analysis + dual-cert.

## Integration library — plug-INTO, not call-OUT-to

Nothing technically prevents PrismPath from growing a large integration library. But do NOT chase
LangGraph's KIND:

- **Call-out-to (tool wrappers, API/agent connectors, vector stores, memory): keep minimal +
  sandboxed, or cede.** That surface is untrusted and hard to audit — the risk safety-minded users
  came here to avoid. Ecosystem *size* is also an incumbent's network-effects game a new entrant loses.
- **Plug-into (host/seam adapters: FlowKernel adapters, LTI/xAPI, observability, ledgers, worker
  runtimes): GROW THIS.** Breadth of what PrismPath plugs INTO, not what it calls OUT to. Certifiable
  seams, community-extensible against an **Apache-licensed interface**. Reference adapters
  (XState, LangGraph) already exist as blueprints (see Journeyman
  `docs/DESIGN_KERNEL_ADAPTERS.md`). Let the community write adapters; PrismPath stays the certifiable
  core.

## A credible win/lose testing methodology (needs 3 testbeds, not 1)

Journeyman alone is a *biased* testbed — it plays to PrismPath's niche (deterministic, offline,
auditable). Publish the losses to be believed:

1. **Journeyman** — niche strengths + the pluggability proof. (Have it.)
2. **`routing_bench`** (this repo) — the NEUTRAL axis: routing accuracy / LLM-calls / latency /
   determinism vs langgraph/crewai/llm-router on 300 labeled decisions. (Have it.)
3. **An adversarial agentic benchmark** (tool-use / multi-step / dynamic branching) — where PrismPath
   *loses* to LangGraph/CrewAI, plus a state-machine-richness scenario where it loses to XState.
   (To build — the missing piece.)

Deck one-liner: *PrismPath wins on deterministic-first routing, cost, determinism, auditability, and
portability in its niche, and deliberately loses on agentic expressiveness and rich state-machine
features, because it isn't trying to be those.* Leading with the loss is what makes the wins credible.

## Licensing

Interface + pack/kernel SPEC → **Apache-2.0** (so others implement freely and write adapters). The
PrismPath kernel → **Apache-2.0**. Reference adapters that ship inside a host → BSL (shell-coupled).

## Housekeeping done this session

- `shadowed-event-edge` analysis check added (the event-tier first-match hazard `_check_shadowing` /
  `_check_error_shadowing` did not cover) — surfaced by the Journeyman comparison catching a real
  malformed lesson. Commit `348a77b`.
