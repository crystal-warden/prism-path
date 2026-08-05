# Architecture

PrismPath is layered so the **engine stays platform-agnostic** and everything target-specific
lives behind one plugin interface. Two layers, one seam.

## 1. The flow kernel

A pure, dependency-light core that turns a markdown file into a routed agent run.

```
parser.py ──▶ Graph ──▶ engine.run(graph, agent, router) ──▶ RunResult
                              │
                              ├─ predicates.py   safe `when` evaluator (deterministic edges)
                              └─ router.py       Embedding / LLM / Hybrid (semantic edges)
                                     └─ embedder.py (bge), llm_local.py (LLM fallback)
```

- **`parser.py`** — `## heading` → node; `-> target: condition` → edge; YAML front-matter (`name`,
  `start`); terminal detection (a node with no outgoing edges).
- **`predicates.py`** — evaluates `when <expr>` over the agent's structured outcome. **No calls,
  attribute access, or subscripts** are permitted in an expression, so a `when` clause can never
  execute arbitrary code.
- **`router.py`** — resolves semantic edges. `HybridRouter` embeds the outcome against each edge
  condition and only escalates to a 1-shot LLM when the top-1↔top-2 margin is below `margin`.
- **`engine.py`** — at each node: evaluate deterministic edges in document order (first true wins);
  if none match, hand the semantic edges to the router. Records a `StepLog` per transition
  (`info["used"]` ∈ `{deterministic, embed, llm, single, semantic}`).

The kernel knows nothing about sprints, gates, or build targets.

### The portable kernels — one spec, four implementations

The decidable subset of the kernel is re-implemented, dependency-free, in three more languages —
JavaScript ([`portable/prismpath.mjs`](portable/prismpath.mjs), browser/edge/Node), Rust
(`prismpath-rs/`, native + WASM), and Go (`prismpath-go/`) — each certified against the frozen
conformance vectors ([`portable/conformance/`](portable/conformance/README.md): 1,067 predicate
cases + 27 engine fixtures, bit-for-bit). The Python kernel stays the reference (vectors are
generated from it); the ports are runtime surfaces, and the tooling (validate/verify/test/lock/
ci-report/lsp) deliberately lives only on the reference side — an asymmetry, not a gap.

## 2. The control plane

`run_sprint.py` is the loop that drives a real agent swarm to build a real tree against a gate.

```
              SPRINT_NUDGE / spec                 (human intent)
                      │
        ┌─────────────▼──────────────┐
        │  council  (dice.py)         │  pick the next unit of work (vote diversity + oblique-strategy dice)
        └─────────────┬──────────────┘
                      │  + RAG grounding (retriever.py, index from the active plugin)
        ┌─────────────▼──────────────┐
        │  executor                   │  edit the REAL tree: cecli diff-edit / swarm_runner / served model
        └─────────────┬──────────────┘
                      │
        ┌─────────────▼──────────────┐
        │  GATE  (the seam)           │  validate(proj) -> {valid, errs, oversized, ...}
        │  browser: gates.py          │  compiles? types? builds? tests? wired? reachable?
        │  other:   plugin.validate   │
        └─────────────┬──────────────┘
            green → commit unit, advance        red ×3 same error → escalate:
                                                  frontier auto-unblock (SPRINT_AGY) → human HELP.md
```

Supporting services:

- **`orchestrator.py`** — a FastAPI front for a chat UI: `planning → awaiting_approval → executing →
  done`, streaming build status over SSE; on approval it launches `run_sprint.py` as a subprocess.
- **`mission_control.py`** — a loopback-only console (`127.0.0.1`) that auto-discovers live sprints,
  can start/stop/pause them, and records an append-only **action log** (`audit_log.py`).
- **`swarm_runner.py`** — `make_swarm_agent(spec, backend="auto")` returns a PrismPath agent backed by
  the real swarm, falling back to `llm_local` when no backend is up.
- **`retriever.py`** — dense retrieval over a turbovec docs index to ground the coder in real APIs.
  The engine is index-agnostic; the path comes from the active gate plugin's `RAG_INDEX`.

### Execution modes

- **`council`** — dice-driven free expansion; for open-ended "what should this grow into."
- **`spec`** (`SPRINT_SPEC_ORDER`) — build a flat list of module files, each from its embedded spec.
- **`kg`** (`SPRINT_KG`) — the most deterministic: one structured spec becomes an authored knowledge
  graph; build exactly one node per pass (the first `pending` whose `depends_on` are all `done`),
  embedding only that requirement + the glossary + named specs + what's already built.

## 3. The seam — the gate plugin interface

`SPRINT_GATE` (and `ORCH_TARGET`) selects the target. `"browser"` is built in (`gates.py`); any other
value resolves via `plugins/load_gate(name)` to an optional plugin. **This is the only place a target's
specifics live** — extractable to a standalone package/image. A plugin module exposes:

| attribute | purpose |
|---|---|
| `validate(proj) -> dict` | the gate: `{valid, errs, oversized, biggest_file, ...}` |
| `HAS_SPEC_LAYER` | whether the gate runs unit specs the test-author owns |
| `ARCH_PATH` | the architecture-contract file injected into builder prompts |
| `LESSONS_PATH` | hard-won target lessons injected into the coder |
| `RAG_INDEX` | the docs vector index for grounding (or unset) |
| `FILE_EXTS` | source extensions the engine collects |
| `SOURCE_DIRS` / `KG_SOURCE_DIRS` / `CORE_DIR` / `ENTRY_FILES` | project **layout** the coder edits ("focus") |
| `SPEC_SUFFIXES` / `TESTABLE_DIRS` | how the test-author detects specs and headlessly-exercisable modules |
| `PLANNER_NOTE` | appended to the planner's system prompt (orchestrator) |
| `BUILD_RULES` / `BUILD_RULES_SPEC` | target build discipline injected into the coder |

The engine reads these through `getattr` with safe defaults, so with **no plugin** (the browser path)
it degrades to an empty, layout-agnostic configuration and runs entirely on the built-in gate. A
gate plugin is any module exposing this table's attributes (discovered via `plugins/registry.py`).

> Design property: because the seam is a narrow ports/adapters boundary, adding a build target is a
> new plugin module — not a change to the engine.
