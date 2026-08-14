# Code nodes

> **Wiring in another language, or an existing binary?** A code node is specifically a **Python function**.
> To run a Go, Rust, JS, or Python *program* as a worker, see
> [Run any program as a worker](workers.md). This page is the Python function case, with a
> capability scoped sandbox.

A **code node** is a node whose worker is a local Python function instead of an LLM or an external tool.
You declare the node `@code` (see below), write a handler `(node, instruction, state) -> dict`, and
register it:

```python
from prismpath.code_nodes import code_agent, in_process_runner
from prismpath.engine import run

def extract(node, instruction, state):
    return {"amount": parse_amount(state["request"])}      # emit the fields the edges route on

agent = code_agent(graph, {"extract": extract}, runner=in_process_runner)
run(graph, agent)
```

It rides the same worker seam as mdflow and CLI workers (`prismpath/connector.py`), specialized to a
function. A full runnable example is in
[`prismpath/examples/code_nodes/`](../../prismpath/examples/code_nodes/README.md).

## The one rule

**PrismPath governs the routing, provably; a code node is a leaf action that returns fields.** The
branching lives on the flow's `->` edges, never inside the code. If you find yourself writing `if/else`
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
| `timeout_s` | wall clock budget | `10` |
| `mem_mb` | memory ceiling | `256` |

The envelope is **flow data**: portable and inspectable. `prismpath.code_nodes.check_code_nodes(graph)`
is a **static gate**: it flags any `@code` node with a missing or invalid envelope. That's a verifiable
property, the same shape as Level M membership: any kernel can check it from the flow alone.

## Governed execution (fail closed)

`prismpath.code_nodes.code_agent(graph, handlers, runner=…)` builds the flow agent and refuses to:
- run a handler on a node that is **not** declared `@code` (no undeclared code sneaks in),
- run an **invalid** envelope,
- run a code node with **no runner** (never execute code ungoverned).

Runners:
- **`in_process_runner`**: trusted, pure code (deterministic transforms, tests). No enforcement.
- **`prismpath.sandbox.SandboxRunner`**: untrusted or effectful code. Runs the function in a sandbox
  whose profile is *derived from the envelope* (network off, fs scope, memory + time limits) via `bwrap`.
  Same agent; the envelope is enforced at runtime, and an unavailable sandbox **refuses** rather than
  running unsandboxed.

## Where safety lives (and doesn't)

A worker can do two things (emit text or execute code), and the two have **opposite ownership**:

- **Execution is ours.** PrismPath runs the code, so PrismPath must contain it: the code node sandbox
  above fails closed: a sandbox that silently degrades to an unsafe fallback is worse than none, so
  ours refuses instead. There is no upstream party whose job this is.
- **Content is the model's.** Whether generated text is *harmful* is owned by the model and its
  provider's moderation, not the routing layer. PrismPath delegates it. An optional deny floor
  (`prismpath/guard.py`) is available for the weak local model case, and you can compose a guardrail at
  the worker boundary, but it is **not** a kernel feature. See `docs/design/spec-guard-onion.md`.

## Scope

Code nodes are **software tier (P2)**: substrate specific (a Go/Rust/JS kernel can't run a Python
function), and never Level M / never the hardware target. Keep them leaf actions with routing on their
outcome fields. For a worker in another language, an existing binary, or a whole tool run rather than a
single function, see [Run any program as a worker](workers.md) (and the mdflow interop example,
`prismpath/examples/mdflow_interop/`).
