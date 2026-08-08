# The control plane — the reference deployment

## The reference deployment — what we run in production on top

Everything above is the format: the spec, the kernel, the toolchain. Everything below is what
we actually run on top of it — the control plane Crystal Warden Labs uses to build real software
with a local agent swarm. None of it is required by the format; it's here as proof the format
holds up under real use. Its examples (browser gates, sprint councils) are specific to our
setup, not yours.

## The two layers

PrismPath turns a **human's intent into a supervised, gated build run by a local-LLM agent swarm**.
It has two layers:

- **The flow kernel** — *one markdown file is the workflow.* Each `## heading` is a node (its prose
  is the instruction handed to an agent); `-> target: condition` lines are the edges. No `StateGraph`,
  no routing functions in code — a PM, analyst, or domain expert can author and read a flow.
- **The control plane on top** — a spec-driven **sprint** loop that drives the swarm: a council picks
  the next unit of work, an executor edits the real tree, and **deterministic gates decide when it's
  done**. Progress is observable live through Mission Control. Build targets (the browser gate is
  built in; others load as plugins) are pluggable; the engine itself stays target-agnostic.

> The short version: **you hold the vision, the swarm builds, and gates — not prose — decide
> when it's done.**
> See [docs/design/framework.md](framework.md) for the operating methodology and hard-won lessons.

---

## A worked example: one line in, a checked app out

Before the abstractions, here's the whole thing on a real task. You want a tip calculator. You hand the
control plane that one line of intent:

```bash
SPRINT_PROJ=/tmp/tip SPRINT_GATE=browser SPRINT_NUDGE="a tip calculator" python -u prismpath/run_sprint.py
```

From there the loop runs on its own:

1. **Build.** The swarm turns the intent into a small file layout (`index.html` + a little JS) and the
   coder writes the first version into `/tmp/tip`.
2. **Gate — the definition of done, machine-enforced.** The browser gate checks the result the way a
   reviewer would, not "does it look finished": every JS file parses (`node --check`); every `import`
   resolves to a symbol that's really exported; every `getElementById('total')` the JS references
   actually exists in the HTML; and then the real test — a **headless Chromium loads the page, fills the
   bill input, clicks the button, and asserts the DOM actually changed**.
3. **Red → fix, and loop.** If clicking does nothing, the gate says exactly that — *"the primary control
   produced no visible change… its handler is likely not wired"* — and that message becomes the coder's
   next task. Build → gate → fix repeats; if the same error recurs 3×, it escalates (to agy, then you).
4. **Green → done.** The build is "done" only when every check passes. You open `/tmp/tip/index.html`
   and it works — because a machine already confirmed the button *does* something, not just that code
   exists to handle it.

That's the **control plane** with the built-in **browser gate**. Swap `SPRINT_GATE` for a gate plugin
and the identical loop targets a different world — same discipline, different gate. The
rest of this README is the two layers underneath that run.

---

## The control plane

Above the kernel, PrismPath runs **spec-driven feature sprints** against a local agent swarm.
The loop's semantics are themselves a PrismPath flow ([`flows/sprint_loop.md`](../../prismpath/flows/sprint_loop.md),
run with `SPRINT_FLOW=1` via [`sprint_flow.py`](../../prismpath/sprint_flow.py)): the gate routes on `when
gate_green`, the 3×-same-error rule is an `on error` edge, escalation is a `needs_human`
suspension, and each gate-green unit is a `@checkpoint` proof-commit — the control plane that
builds PrismPath is driven by a PrismPath document. The wall clock, pause, and heartbeat stay in the
driver, where harness concerns belong:

```
  human intent ──▶ spec / nudge
                      │
                      ▼
        run_sprint.py  (the sprint loop)
            │  council picks the next unit of work (dice-steered)
            │  executor edits the REAL tree (cecli / swarm / served model)
            ▼
        GATE (pluggable)  ── compiles? types? builds? tests? wired? reachable? ──┐
            │ green → next unit                                                  │
            │ red ×3 (same error) → escalate (frontier auto-unblock, then human)│
            └────────────────────────────────────────────────────────────────◀─┘
                      │
                      ▼
        Mission Control (:9109, loopback)  — proving + observability command center + audit
```

- **Gates are the definition of done, machine-enforced.** A build is not green until it compiles,
  type-checks, builds, passes tests, is wired into a composition root, and is reachable. *Never write
  a completeness claim a gate doesn't enforce.*
- **Targets are plugins.** `SPRINT_GATE=browser` is the built-in gate (syntax → link → DOM →
  headless behavioral). Any other value loads an optional plugin behind one uniform interface
  (NAME / ARCH_PATH / RAG_INDEX / validate(proj) — see `prismpath/plugins/registry.py`). The
  engine only ever touches the plugin interface, never a target's specifics.
- **Execution backends** range from a served model to the full multi-agent swarm
  (`SPRINT_AGENT=swarm`, `SPRINT_EXEC=cecli`); `swarm_runner.py` prefers the real swarm and falls
  back to `llm_local` so a run always proceeds.
- **Mission Control is proving + observability** (`prismpath/mission_control/`, a FastAPI package):
  a single-user, loopback command center over a versioned JSON API (`/api/v1`, OpenAPI at `/docs`) —
  the flow topology with live run-state over SSE, **text-in proving** (`/prove/level-m`,
  `/prove/reach`, audit self-verify), RAG-retrieval visibility, and the sprint controls (incl. a
  buffered/unbuffered launch toggle). It runs **no models** — PrismPath routes and proves; inference
  belongs to the worker tier. The proving/observability API is the driving adapter other services
  connect to; the command center is its first client. Needs the `control-plane` extra.

---

## Commands

```bash
# --- control plane (needs a served model / swarm) ---
pip install -e .          # or: export PYTHONPATH=$PWD
SPRINT_PROJ=/tmp/demo SPRINT_GATE=browser SPRINT_NUDGE="a tip calculator" \
  python -u prismpath/run_sprint.py
pip install -e ".[control-plane]"        # Mission Control needs FastAPI/uvicorn (the control-plane extra)
python -m prismpath.mission_control      # proving + observability command center at http://127.0.0.1:9109 (loopback)
```

The operating methodology and hard-won lessons behind this loop:
[framework.md](framework.md).
