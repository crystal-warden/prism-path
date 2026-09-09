# PrismPath

[![PyPI](https://img.shields.io/pypi/v/prismpath.svg)](https://pypi.org/project/prismpath/)
&nbsp;[![license: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/crystal-warden/prismpath/blob/main/LICENSE)

**A control plane for autonomous systems.** Define what an autonomous system is allowed to do, enforce
it where the system runs, change it without rebuilding the system, and get a signed receipt for every
decision. PrismPath is one of many control planes; what is unusual is the approach. The decision
structure a person authors is restricted to a decidable, tabular fragment, so one compiled image decides
identically from this Python engine down to a 1.7 KB interpreter on an 8 bit microcontroller or an FPGA
fabric, and carries a signed worst case bound. This package is the Python engine and the `prismpath`
command line; the kernel, microcontroller, and fabric ports, the Facet wire, the proofs, and the evidence
ledger live in the research repo linked below.

## Prove what can happen. Enforce what may happen. Prove what happened.

One Markdown file is the program: each `## heading` is a step, each `-> target: condition` an edge.
Deterministic edges decide first and free, in document order; an embedding router and a one shot model
are reached only where meaning genuinely requires one, and low confidence abstains or escalates to a
person instead of guessing. `validate` and `test` check the deterministic paths with no model; `verify`
model checks reachability; `capability` says which targets the flow compiles to; every decision can
leave a receipt with a cause code, Merkle rooted per session.

The predicates are authored by a person. PrismPath does not compile policy from prose; it compiles that
authored structure, and the deterministic fragment (Level M) becomes a table image a few hundred bytes
long that every substrate executes.

## Use it for

### Governing what an agent does next, provably

Route an agent between steps, and prove the routing before it runs. A test driven development loop,
every edge deterministic:

```markdown
---
name: tdd_loop
start: write_test
---

## write_test
Write one failing test for the next untested behavior. Emit `has_test`.
-> run: when has_test
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

The worker underneath can be a hosted model, a local model, a shell process, a function, or another
orchestration system; PrismPath governs where the run goes next and records why. A change to the policy
is a Markdown diff a non engineer can approve.

### One policy across your whole stack

The same signed image decides byte for byte identically on Python, JavaScript, Rust, and Go, plus a C
reference interpreter, judged by one frozen corpus of 1,079 predicate and 27 flow vectors. Author the
policy once; run it in whatever language each service already speaks, and know they agree.

### Enforcing decisions in the Linux kernel

The same image is executed by an eBPF/XDP program the kernel verifier accepts, deciding at the packet
layer in roughly 130 to 180 ns per evaluation, hot swappable without a rebuild, certified 124 of 124 in
kernel on every push.

### Running on the edge, from an FPGA to an 8 bit MCU

Certified byte for byte across four microcontroller instruction sets (AVR, ARM Cortex-M33, RISC-V,
Xtensa) and a Zynq FPGA fabric whose signed worst case bound was witnessed on the pins. The whole AVR
firmware, interpreter and serial protocol included, is 1,720 bytes of flash.

### Shipping the decision, not the telemetry

When the consumer of telemetry is a proven policy, the only thing worth sending is the decision.
Figueroa quantization reduces a reading to the distinctions that can change that policy's decision,
about a byte and a half per decision; its decision preservation is proven in Lean 4 within a declared
domain. The Facet protocol carries those symbols on a wire that frames itself, 66.9 times under an
OpenTelemetry record of the same decision.

### Where it stands against the alternatives

A pre registered comparison against OPA, Cedar, Cerbos, OpenFGA, and Openlane, run to the end on real
systems and hardware, found every property PrismPath builds in reachable by at least one comparator
with bounded glue, so PrismPath is not a layer the existing engines cannot reach. The same table shows
PrismPath native on all eight where no comparator is native on more than two, and two orders of
magnitude less memory on the same microcontroller. The verdict is published in full.

> The pip package is the Python engine and the `prismpath` CLI: authoring, validation, testing, and
> running flows, plus the signed pack, the audit trail, and the Facet codec. The kernel, FPGA, and MCU
> ports, the proofs, the comparison, and an evidence ledger timestamped to Bitcoin live in the research
> repo: **[crystal-warden/prism-path](https://github.com/crystal-warden/prism-path)**.

## Quickstart

```bash
pip install prismpath
prismpath init                 # scaffolds flow.md + flow.tests.md
prismpath validate flow.md     # does it compile? no model
prismpath test flow.md         # does it route as written? no model
prismpath --help               # commands grouped by who runs them
```

To run the flow end to end (the starter has a semantic edge), add the embeddings extra, then point it
at a worker:

```bash
pip install 'prismpath[embeddings]'   # about 90 MB, on your machine, no cloud, no API key
prismpath run flow.md                 # mock worker by default; --agent ollama:llama3.2 for a real LLM
```

## Going deeper

[The ten minute tour](https://github.com/crystal-warden/prismpath/blob/main/docs/guides/tour.md) walks
the engine end to end and ends at a receipt. [The public
position](https://github.com/crystal-warden/prism-path/blob/main/docs/POSITION.md) says what is
claimed and what is not.

Apache-2.0 ([LICENSE](https://github.com/crystal-warden/prismpath/blob/main/LICENSE),
[NOTICE](https://github.com/crystal-warden/prismpath/blob/main/NOTICE)). Fork it and ship it, including
inside a proprietary product: retain LICENSE and NOTICE, mark changed files. No user facing attribution
required.
