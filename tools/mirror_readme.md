# PrismPath

[![PyPI](https://img.shields.io/pypi/v/prismpath.svg)](https://pypi.org/project/prismpath/)
&nbsp;[![license: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/crystal-warden/prismpath/blob/main/LICENSE)

**Control flow as data, not code.** Deterministic, diffable AI agent workflows written entirely in
Markdown. One file is the graph: each `## heading` is a step, each `-> target: condition` an edge. A
routing spectrum decides every transition at the cheapest tier that can, so you pay for a model only
where meaning genuinely requires one.

## Use it for

### Deciding what an agent does next, provably

The most common job: route an agent between steps, and be able to prove the routing before it runs.
`-> t: when <expr>` is a free deterministic edge (first true wins, in document order) and `else` is the
fallthrough; a bare `-> t: <natural language>` escalates to embeddings, then to a one shot LLM only on
doubt. `prismpath validate` and `prismpath test` check the deterministic paths with no model.

A test driven development loop, every edge deterministic:

```markdown
---
name: tdd_loop
start: write_test
---

## write_test
Write one failing test for the next untested behavior. Emit `has_test`.
-> run: when has_test == true
-> done: else

## run
Run the suite. Emit `status` (pass, fail, or error).
-> implement: when status == "fail"
-> refactor: when status == "pass"
-> fix_test: else

## implement
Write the least code that makes the failing test pass.
-> run: always

## fix_test
The test errored or came back unexpected. Repair it, then rerun.
-> run: always

## refactor
Green. Clean up without changing behavior.
-> write_test: when visits < 25
-> done: else

## done
Every behavior is covered and the suite is green.
```

Then the gate that decides whether a green change can merge. The loop above hands its `done` step to
this flow's `check`:

```markdown
---
name: pr_gate
start: check
---

## check
Read the diff and CI result. Emit `tests_pass`, `coverage`, and `size`.
-> request_changes: when tests_pass == false
-> human_review: when size > 400
-> auto_merge: when coverage >= 0.8
-> human_review: else

## request_changes
Return the failing checks to the author.

## human_review
A maintainer reviews a large or low coverage change.

## auto_merge
Small and well tested. Approve and merge.
```

Two files, two graphs, one convention: compose them by feeding one flow's exit into the next flow's
start. Both above validate with no model. Unlike LangGraph or CrewAI, the flow is inert Markdown you
check before anything runs, and the four baselines it is measured against are
[real, runnable implementations](https://github.com/crystal-warden/prismpath/blob/main/prismpath/comparisons/README.md),
not a strawman.

### One policy across your whole stack

The same signed table decides byte for byte identically on Python, JavaScript, Rust, and Go, plus a C
reference interpreter. Author the policy once; run it in whatever language each service already speaks,
and know they agree.

### Enforcing decisions in the Linux kernel

The same table compiles to an eBPF/XDP program the kernel verifier accepts, deciding at the packet
layer in roughly 130 to 180 ns and hot swappable without a rebuild.

### Running on the edge, from an FPGA to an 8 bit MCU

Certified byte for byte across four microcontroller instruction sets (AVR, ARM Cortex-M33, RISC-V,
Xtensa) and a Zynq FPGA fabric that routed thousands of live sensor readings, on device and offline.

### Shipping the decision, not the telemetry

When the consumer of telemetry is a proven policy, the only thing worth sending is the decision.
Figueroa quantization reduces a reading to the minimum sufficient statistic for that policy, about a
byte and a half; the Facet protocol carries those symbols on a wire that frames itself, about 67x
smaller than OTLP.

> The pip package is the portable kernel and the `prismpath` CLI: authoring, validation, testing, and
> running flows. The kernel (eBPF/XDP), FPGA, and MCU ports, the Facet protocol, the decidability
> proofs, and an evidence ledger timestamped to Bitcoin live in the research repo:
> **[crystal-warden/prism-path](https://github.com/crystal-warden/prism-path)**.

## Quickstart

```bash
pip install prismpath
prismpath init                 # scaffolds flow.md + flow.tests.md
prismpath validate flow.md     # does it compile? no model
prismpath test flow.md         # does it route as written? no model
```

To run the flow end to end (the starter has a semantic edge), add the embeddings extra, then point it
at a worker:

```bash
pip install 'prismpath[embeddings]'   # ~90 MB, on your machine, no cloud, no API key
prismpath run flow.md                 # mock worker by default; --agent ollama:llama3.2 for a real LLM
```

## Going deeper

[The ten minute tour](https://github.com/crystal-warden/prismpath/blob/main/docs/guides/tour.md) walks
the whole engine end to end.

Apache-2.0 ([LICENSE](https://github.com/crystal-warden/prismpath/blob/main/LICENSE),
[NOTICE](https://github.com/crystal-warden/prismpath/blob/main/NOTICE)). Fork it and ship it, including
inside a proprietary product: retain LICENSE and NOTICE, mark changed files. No user facing attribution
required.
