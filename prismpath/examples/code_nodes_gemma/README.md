# code_nodes_gemma — sandboxed code nodes + a local LLM, one governed flow

A single flow (`alert_router.md`) that mixes both worker kinds and runs entirely on the box:

- **`parse`, `decide`** — `@code` nodes, executed in the **bwrap sandbox**
  (`prismpath.sandbox.SandboxRunner`), each under its declared `@code(net=false, fs=none, …)` envelope.
- **`triage`** — a Markdown node, executed by a **local served Gemma** endpoint (`chat_agent`).

The discipline the example demonstrates: **PrismPath governs the routing; Gemma advises** (the `urgent`
hint from `triage`); **the code node decides** (the fixed page/no-page policy in `decide`). Branching
lives on the edges, never inside the code. Nothing leaves the box — Gemma is served locally, code runs
sandboxed locally.

The composition seam is `code_agent(graph, handlers, runner=SandboxRunner(), base=gemma)`: code nodes go
to the sandbox, every other node falls through to the LLM, one composed agent, fail-closed on code.

## Run

```bash
LLM_BASE=http://127.0.0.1:8888/v1 LLM_MODEL=gemma4 \
  PYTHONPATH=prismpath/examples/code_nodes_gemma \
  python prismpath/examples/code_nodes_gemma/run_demo.py
```

It routes three alerts (a real outage, self-recovered noise, and a malformed blob) and prints the path
plus which worker (`sandbox` vs `gemma`) handled each hop.
