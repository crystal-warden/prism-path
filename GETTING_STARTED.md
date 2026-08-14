# Getting started · from "what's PrismPath?" to using it, counted in steps

This document is an experiment in honesty: every step below was executed verbatim in a fresh
virtualenv before being written down, and the counts include *everything*; no "assuming you
already have…" steps hidden in the prose. The scoreboard:

| you want to… | steps | installs | time |
|---|---|---|---|
| **see it route** (browser, no terminal) | 3 | none | ~2 min |
| **use the toolchain** (validate + test a real flow) | 4 | 1 (`pip`) | ~3 min |
| **run your own flow with a real agent** | 8 | 1 | ~10 min |
| **make it a team process** (fixtures in CI: the PR loop) | 10 | 1 | ~15 min |

There is no API key, no account, no config file, and no model download anywhere on this page.
The one dependency the minimal path installs is numpy.

---

## Path 1 · see it route (3 steps, nothing installed)

The portable kernel runs in your browser; nothing leaves the page.

1. `git clone https://github.com/crystal-warden/prism-path.git && cd prism-path`
2. `cd prismpath/portable && python3 -m http.server 8321`
3. Open `http://localhost:8321/playground.html`; pick a preset, press **▶ Run**, watch the
   path light up. Edit an edge; the tier badges and checks update as you type.

*(Once the hosted playground is live, this path is 1 step: open the link.)* Any flow is
**shareable as a link**: 🔗 Share puts the whole flow in the URL fragment (nothing leaves
the page), so a tweet, HN comment, or bug report can carry an executable flow.

## Path 2 · use the toolchain (4 steps)

```bash
git clone https://github.com/crystal-warden/prism-path.git && cd prism-path   # 1
pip install -e .                            # 2  (numpy only)
prismpath validate prismpath/examples/pr_demo/triage.md  # 3  → "clean ✅ · the flow compiles"
prismpath test prismpath/examples/pr_demo/triage.md      # 4  → "6/6 passed"  (no model, milliseconds)
```

You have now linted a workflow's control structure and asserted its routing against fixtures;
before running anything, with no model in the loop. That pair of commands is the whole CI story.
To start from a scaffold instead of the example, **`prismpath init`** writes a starter flow + its
routing-test table into the current directory and prints exactly these commands against it;
or start from a real gallery workflow with `prismpath init --template <name>` (`--template list`).
Editing in VS Code? `prismpath/editor/vscode/` ships tier-aware highlighting, a live playground
preview (no Python needed), and validate-on-save squiggles. Any other LSP editor (Neovim,
JetBrains, Zed, …): `prismpath lsp` serves live diagnostics, completion, and hover; see
`prismpath/editor/README.md`.

## Path 3 · your own flow, with a real agent (steps 5 · 8)

**5.** Write the flow. This is the entire program:

```markdown
---
name: inbox_triage
start: classify
---

## classify
Read the message below and decide: is it urgent, routine, or spam?
Reply with JSON: {"text": "<one line>", "kind": "urgent"|"routine"|"spam"}
Message: "URGENT: production database is down, customers cannot log in!"
-> page_me: when kind == "urgent"
-> queue: when kind == "routine"
-> bin: else

## page_me
Send the page.

## queue
File it for the morning.

## bin
Delete it.
```

**6.** `prismpath validate my_first_flow.md`; catch the typo *now*, not at 3 a.m.

**7.** Wire a worker; or skip the driver file entirely if you run local models:
`prismpath run my_first_flow.md --agent ollama:llama3.2` (any Ollama model; or
`--agent openai:MODEL@http://host:port/v1` for vLLM / LM Studio / llama.cpp). JSON replies
feed the `when` predicates; failures ride the `on error` edges. For full control, wire it
yourself; any CLI that reads stdin and prints to stdout is an agent (Claude Code, a
Gemini CLI, aider, or a shell script):

```python
# drive.py
from prismpath.parser import parse_file
from prismpath.engine import run
from prismpath.cli_worker import cli_agent

agent = cli_agent(["claude", "-p"])          # or ["gemini"], or any command you trust
res = run(parse_file("my_first_flow.md"), agent)
print("path:", " -> ".join(res.path), "| stopped:", res.stopped)
```

If the CLI prints JSON, its fields feed the `when` predicates directly (that's what the flow's
instruction asks for); plain text routes semantically. If it exits nonzero or hangs, that lands
on the flow's **error tier**: add `-> classify: on error when error_count < 3` and the retry
budget is an edge you can read, not a wrapper you wrote.

**8.** `python drive.py` →

```
path: classify -> page_me | stopped: terminal
```

Eight steps, and the part you'll maintain forever (the control flow) is a document your whole
team can read. A different engine per node is one dict away
(`cli_agent({"classify": [...], "page_me": [...]})`): route between *engines* by outcome, not
by hardcoding.

## Path 4 · make it a team process (steps 9 · 10)

**9.** Pin the routing with fixtures; `my_first_flow.tests.md`:

```markdown
| node     | outcome                  | fields        | expect  |
|----------|--------------------------|---------------|---------|
| classify | prod is down             | kind=urgent   | page_me |
| classify | invoice question         | kind=routine  | queue   |
| classify | congratulations you won  | kind=spam     | bin     |
```

`prismpath test my_first_flow.md` → `3/3 passed`. Every past mis-route becomes a row.

**10.** Put `prismpath validate && prismpath test` in CI. From here on, **a pull request is a process
change**: someone edits an edge in prose, a fixture row asserts it, the merge changes production
routing. The bundled GitHub Action takes it further: on every PR it posts a sticky comment
with the flow's topology **before → after** (live Mermaid) plus the fixture verdicts; the
process change reviewable in the conversation. That loop (the point of the whole system)
is demonstrated end to end in
[`examples/pr_demo/`](prismpath/examples/pr_demo/README.md).

---

## Where the steps go from here (each is optional, none is required)

- **Semantic edges**: write a condition in plain language (`-> escalate: the customer is
  threatening to leave`) and `pip install -e ".[embeddings]"` (~90 MB, local, no API): embedding
  similarity routes it, and a one-shot LLM is consulted only on low-confidence margins.
- **Reproducibility**: `prismpath lock` pins the semantic routing bit-for-bit;
  `prismpath calibrate` *derives* the escalation threshold with a finite-sample guarantee instead
  of a magic constant; `prismpath centroids` learns from your labeled history (the measured best
  accuracy-per-call; see `prismpath/benchmark/`).
- **Durability**: `checkpoint.run_durable(...)` makes any run crash-resumable and lets it
  suspend for a human with the evidence packet; `@spawn` fans out child runs.
- **The edge**: `prismpath portable <flow>` tells you if your flow is P0: zero-ML, runnable by
  the same kernel the playground uses, anywhere JavaScript runs. (The Level M core goes further
  still; it now runs as table images in FPGA fabric, declared-subset certified: see
  [ROADMAP Phase 6](ROADMAP.md).)
- **Your role's door**: the [persona examples](prismpath/examples/README.md): SOC triage, support
  routing, release trains, HR onboarding, fan-out review, and the sprint loop that builds this
  repo.

## The honest fine print

- The minimal path routes **deterministic edges only**: that's a feature (free, exact,
  portable), but judgment-shaped conditions need the embeddings extra.
- A CLI worker is **arbitrary code execution by design**: you chose the command, exactly as
  you choose a dependency. PrismPath's sandbox guarantee covers the *routing* layer: `when`
  predicates never execute worker-influenced strings.
- Fixture tests assert deterministic rows with no model; semantic rows use the embedder (and
  the lockfile, if present); still no LLM, still CI-safe.
