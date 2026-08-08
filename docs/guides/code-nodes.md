# Code nodes

A **code node** is a node whose worker is plain code — a local function — instead of an LLM or an
mdflow task. It is the same worker seam mdflow rides on (`prismpath/connector.py`, `run(graph, agent, …)`),
applied to a function. mdflow proved the mechanism; a code node is the simpler case.

## The one rule

**PrismPath governs the routing, provably; a code node is a leaf action that returns fields.** The
branching lives on the flow's `->` edges — never inside the code. If you find yourself writing `if/else`
in the function to decide *where the flow goes next*, that logic belongs on an edge. Keeping control flow
on the edges is what keeps the routing proof meaningful; a code node that hides branching turns the proof
vacuous.

```markdown
## extract
@code(net=false, fs=none, timeout_s=5, mem_mb=128)
Parse the refund amount from the request. Emits `amount`.
-> high_value: when amount > 500
-> standard:   when amount >= 0
-> invalid:    else
```

The code node returns `{"amount": …}`; the three edges decide the rest.

## The capability envelope

Every code node declares what it may touch:

    @code(net=false, fs=none, timeout_s=5, mem_mb=128)

| key | meaning | default |
|---|---|---|
| `net` | may open network sockets | `false` |
| `fs` | filesystem: `none` / `ro` / `rw` | `none` |
| `timeout_s` | wall-clock budget | `10` |
| `mem_mb` | memory ceiling | `256` |

The envelope is **flow data** — portable and inspectable. `prismpath.code_nodes.check_code_nodes(graph)`
is a **static gate**: it flags any `@code` node with a missing or invalid envelope. That's a verifiable
property, the same shape as Level M membership — any kernel can check it from the flow alone.

## Governed execution (fail-closed)

`prismpath.code_nodes.code_agent(graph, handlers, runner=…)` builds the flow agent and refuses to:
- run a handler on a node that is **not** declared `@code` (no undeclared code sneaks in),
- run an **invalid** envelope,
- run a code node with **no runner** (never execute code un-governed).

Runners:
- **`in_process_runner`** — trusted, pure code (deterministic transforms, tests). No enforcement.
- **`prismpath.sandbox.SandboxRunner`** — untrusted or effectful code. Runs the function in a sandbox
  whose profile is *derived from the envelope* (network off, fs scope, memory + time limits) via `bwrap`.
  Same agent; the envelope is enforced at runtime, and an unavailable sandbox **refuses** rather than
  running un-sandboxed.

## Two governed safety floors

A worker can do two things — emit text, or execute code — and PrismPath governs both boundaries with the
same discipline: the **guard** screens outcomes/text (`prismpath/guard.py`), and the **code-node sandbox**
governs code execution (this page). Both are declared, enforced, loud-when-absent, and honestly
best-effort; neither is a guarantee against determined untrusted code.

## Scope

Code nodes are **software-tier (P2)**: substrate-specific (a Go/Rust/JS kernel can't run a Python
function), and never Level M / never the hardware target. Keep them leaf actions with routing on their
outcome fields. For a worker that orchestrates a whole tool run rather than a single function, see the
mdflow interop example (`prismpath/examples/mdflow_interop/`).
