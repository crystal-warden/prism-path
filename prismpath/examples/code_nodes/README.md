# Code nodes — a function as a governed flow worker

A **code node** runs plain code instead of an LLM. It's the same worker seam mdflow uses
(`prismpath/connector.py`), applied to a local function. The rule that keeps PrismPath's thesis intact:
**the flow governs the routing; the code node is a leaf action that returns fields.** Branching lives on
the `->` edges, never inside the code.

- `pipeline.md` — a flow whose `extract` node is a code node (`@code(...)`), routing on its `amount` field.
- `adapter.py` — the code worker (`extract`) + `code_agent` wiring. Run it:

      python prismpath/examples/code_nodes/adapter.py
      # 'refund $750 please'    -> extract -> high_value
      # 'refund of 100 dollars' -> extract -> standard
      # 'no number in here'     -> extract -> invalid

## The capability envelope

Every code node declares what it may touch: `@code(net=false, fs=none, timeout_s=5, mem_mb=128)`. That
declaration is *flow data* — statically checkable by any kernel (`prismpath.code_nodes.check_code_nodes`),
exactly like Level M membership. Execution is **fail-closed**: `code_agent` refuses a handler on a node
that isn't declared `@code`, refuses an invalid envelope, and refuses to run with no runner.

## Runners

- `in_process_runner` — trusted, pure code (this example). No enforcement.
- `prismpath.sandbox.SandboxRunner` — untrusted/effectful code: runs the function in a sandbox whose
  profile is derived from the envelope (bwrap). Same agent, governed at runtime.

## Scope

Code nodes are **software-tier (P2)**: substrate-specific, never portable to another kernel or to the
Level M hardware target. Keep them leaf actions with routing on their outcome fields. See
`docs/guides/code-nodes.md`.
