# PrismPath: a control plane you can prove

[![ci](https://github.com/crystal-warden/prism-path/actions/workflows/ci.yml/badge.svg)](https://github.com/crystal-warden/prism-path/actions/workflows/ci.yml)
&nbsp;[![license: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
&nbsp;[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21816125.svg)](https://doi.org/10.5281/zenodo.21816125)

**One signed policy, authored as a Markdown document, that decides byte identically from a Linux kernel to
an 8 bit MCU, coordinates a swap across a wireless fleet, and is tamper evident by construction.**
PrismPath is a decidable match action control plane: the entire policy is one inspectable, signed
artifact, so you can prove it, port it, sign it, and hot swap it, and every proof is machine checked in CI.

## See it decide

[![the demo rig: a signed hysteresis policy holding a steady band on silicon, the resident OLED readout agreeing with the LED](docs/media/demo-poster.jpg)](https://github.com/crystal-warden/prism-path/releases/download/demo-2026-08/prismpath-demo-take4.mp4)

**Two minutes, eighteen seconds, one take.** A button press swaps signed policies from a ROM inside
the fabric, no processor in the loop: the exact rule flickers honestly on a knife edge threshold,
the resident rule holds the same dial rock steady under signed deadbands, and then the input stops
being a dial at all and becomes a sensor carried across the room, deciding over a radio mesh the
chip decodes itself. Every decision in the take wrote a receipt. The camera original is sha256
`aee428a5...` and its decision stream, the signed policies, and the full certification chain (4568/4568
silicon replay, live sweep witness, WCET on the pins) ship as one hashed manifest in
`prismpath-hw/hyst-cert/evidence/`, OTS anchored into Bitcoin. Watch it, then verify it:
[`prismpath-hw/hyst-cert/VERIFY.md`](prismpath-hw/hyst-cert/VERIFY.md) walks the whole chain in six
commands, from the video hash down to the Bitcoin block.

Provability is the whole point. Every routing decision is total and decidable (Level M), every safety
property is model checked, and the exact same signed table runs identically across a dozen substrates,
from the kernel to an FPGA fabric to bare metal silicon. And because that policy is a document your team
can read, a workflow you can read is one you can **diff, lint, test, lock, and prove**, five shipped
commands with no Python callback in sight: a routing change lands as a prose diff a non engineer approves,
which the engine renders as a live before and after graph in the pull request itself.

**[Try it in your browser.](https://www.crystalwardenlabs.com/playground)** The kernel runs client side;
nothing to install, nothing you type leaves the page.

## The primitives, named and measured

- **Figueroa quantization.** The policy derived mapping that reduces a reading to the minimum
  sufficient statistic for the policy's decisions, with machine checked decision preservation:
  reconstructing any representative of a cell routes identically to the original reading.
  [PROTOCOL.md §1](PROTOCOL.md) · [paper](docs/research/paper-facet-figueroa-quantization.md)
- **The Facet wire.** Decisions travel as self framing symbols with zero per reading header,
  about a byte and a half per decision on the alert corpus and **66.9x smaller per decision than
  an OpenTelemetry protobuf baseline** over a matched population; tamper evident via per packet
  Merkle roots anchored through OpenTimestamps, and visible to standard network tooling through
  the shipped Wireshark dissector.
  [protocol](PROTOCOL.md) · [dissector](integrations/wireshark/README.md)
- **Cause codes.** One byte on the receipt answers WHY the system refused, parked, or escalated,
  drawn from a stable, append only registry, so identical surface refusals with different
  structural causes present as the different situations they are.
  [spec](docs/design/spec-cause-codes.md)
- **The signed WCET bound.** Every policy manifest carries its worst case execution bound,
  calibrated cycle exact on the RTL and witnessed on physical fabric pins (16,009 evaluations,
  global max 9 cycles inside the signed 11 cycle bound).
  [evidence ledger](docs/research/supporting-evidence.md)
- **Every substrate, byte identical.** The same signed table decides identically from a Linux
  kernel (eBPF/XDP) to an FPGA fabric to bare metal MCUs across four ISAs (8 bit AVR, ARM
  Cortex-M33, RISC-V, Xtensa), 124/124 on the conformance subset each, and three wireless nodes
  hot swap it together (reverify per node, refuse rather than downgrade) behind a two phase
  commit.
  [hardware](prismpath-hw/README.md) · [conformance](prismpath/portable/conformance/README.md) ·
  [mesh demo](prismpath-hw/mesh/README.md)

Everything above is reproducible from this repo; the evidence is timestamped to Bitcoin.

## The whole idea in ten minutes

One Markdown file is the program: each `## heading` is a step, each `-> target: condition` an edge,
and every deterministic transition is decidable before anything runs. Routing is a spectrum the
engine chooses, not the author: deterministic edges evaluate first and free, in document order,
first true wins, and a semantic edge reaches an embedding router and a one shot model only where
meaning genuinely requires one. The worker is yours (an LLM agent, a plain function, a shell
script, another tool's task run); PrismPath decides *where the run goes next*, provably, and
records *what happened*. And because the flow is data, **a pull request is a process change** a non
engineer can approve, rendered as a live before and after graph in the PR itself
([`examples/pr_demo/`](prismpath/examples/pr_demo/README.md)). The worked example, the routing
spectrum, the worker boundary, the adapter ports, and the rest of the machinery are the ten minute
tour: **[docs/guides/tour.md](docs/guides/tour.md)**.

## It runs all the way down: to the FPGA and inside the kernel

Most of what routes agents is a heavy Python runtime. PrismPath's deterministic core is a **decidable
match-action fragment** ([SPEC §4.3](SPEC.md)), and a decidable thing is portable to places a runtime
can't go. **One fixed interpreter; every flow is data.** Edit the Markdown, recompile a small binary
table, and the circuit or program never changes:

- **FPGA fabric.** A Level M flow compiles to a block-RAM table image (`incident_severity` = **136
  bytes**; `wazuh_triage`, the production SOC flow unmodified, = 302 bytes). On a Zynq-7020 at 50 MHz a
  routing decision is **5 to 21 cycles (100 to 420 ns)** in **1,064 LUTs, 2.0% of the part**; the RTL
  reproduced **7,436 live sensor samples** bit-for-bit against the C reference.
  ([`prismpath-hw/`](prismpath-hw/README.md))
- **Linux kernel / eBPF.** The same table compiles to a **verifier-accepted XDP program**, certified
  in-kernel against the frozen corpus. On a live-traffic mirror it classifies real packets at **132 to 182
  ns/packet (~5.5 to 7.6 Mpps/core)**, and its **policy hot-swaps live from a Markdown edit**: repopulate
  the running program's maps, no detach, no reload. Each swap can be cryptographically **authorized,
  envelope-checked, and audited** (secure hot swap, published as prior art:
  [`docs/design/spec-secure-hotswap.md`](docs/design/spec-secure-hotswap.md)).
  ([`prismpath-ebpf/`](prismpath-ebpf/README.md))

Both are certified on a **declared subset** of the frozen vectors. This is the portability pattern taken
one level below software, never claimed as full SPEC §8 conformance, with every excluded vector carrying a
machine-readable reason.

## Measured, not asserted

N=301 labeled routing decisions, 7 flows, the same local model for every arm
([benchmark/](prismpath/benchmark/), reproducible):

| arm | accuracy | LLM calls / 1k decisions | median latency | p95 |
|---|---|---|---|---|
| **PrismPath** (hybrid over learned centroids, δ=0.03) | **95.3%** | **360** | **205 ms** | 655 ms |
| **PrismPath** (economy point, δ=0.01) | 90.0% | **160** | ~205 ms | n/a |
| PrismPath (zero-shot hybrid, δ=0.05) | 83.7% | 383 | 205 ms | 655 ms |
| LangGraph / CrewAI / LLM-router | 99.0% | 1000 | ~435 ms | ~460 ms |

```bash
python -m prismpath.comparisons.run_comparison   # reproduce against your own endpoint
```

The trade is a **dial, not a verdict**. LLM-on-doubt over learned per-condition centroids (5-fold
cross-validated) hits 95.3% at **2.8× fewer LLM calls** and about half the median latency; turn δ up (or
derive τ with `prismpath calibrate`) to trade toward ~99.7% at always-call prices. The external arms are
more accurate out of the box because they pay the model on *every* transition. If call volume is
irrelevant to you, that's the right trade and you should use them. PrismPath's whole point is spending the
model only where it earns its cost.

## Correctness you can check, not an author you have to trust

Much of this code was written by AI agents under a gated control plane, the same one this repo ships. So
the project is built on a bet: **correctness shouldn't depend on trusting whoever (or whatever) wrote
it.** Everything is therefore checkable.

- **[1,079 predicate + 27 flow conformance vectors](prismpath/portable/conformance/README.md)**, frozen,
  passed bit-for-bit by the Python reference *and* three independent re-implementations
  ([JS](prismpath/portable/README.md), [Rust](prismpath-rs/CONFORMANCE.md), [Go](prismpath-go/README.md)).
  Four kernels, four languages, one answer: the one check a plausible-looking codebase can't fake.
- **~890 tests**: 649 in the kernel package, 227 across the two adapters (telemetry, fusion), 18 in the
  Node kernel, plus a fuzz-hardened predicate sandbox. [Run them yourself](#running-the-tests).
- **[A reproducer for every measured number](docs/research/supporting-evidence.md)**: each claim maps to
  the script that made it, the benchmark table regenerates with one command, and the silicon and kernel
  rows (#72 to #78) are each anchored in Bitcoin via OpenTimestamps. **Check the artifact, not the
  author.**
- **[Machine-enforced boundaries](tools/arch_guard.py)**: the standing rule is *never write a completeness
  claim a gate doesn't enforce*, and it binds the authors too, since agent-written code landed only after
  it compiled, passed the suites, and survived the gates.

## Quickstart

```bash
git clone https://github.com/crystal-warden/prism-path.git && cd prism-path
pip install -e .                                          # numpy only; embedder is an optional extra
prismpath validate prismpath/examples/pr_demo/triage.md   # "your flow compiles"
prismpath test prismpath/examples/pr_demo/triage.md       # fixture-asserted routing, no model
```

Or skip the terminal entirely: the [live playground](https://www.crystalwardenlabs.com/playground) runs
the portable kernel in your browser (it also ships offline at
[`portable/playground.html`](prismpath/portable/playground.html)).
**[GETTING_STARTED.md](GETTING_STARTED.md)** goes from clone to a real agent driving your own flow in
eight steps, each run before it was written down.

## Where PrismPath is the wrong tool

Honesty is part of the identity, so here is where it loses:

- **A linear pipeline with no branching.** You don't need routing; write a script.
- **Maximum accuracy at any cost.** An LLM-on-every-transition router hits 99% here; if call volume
  doesn't matter, that edge is real and it isn't ours.
- **A hosted platform with a connector catalog.** PrismPath is a format plus kernel plus control plane,
  deliberately not a SaaS or an integration ecosystem.
- **Control flow that writes itself at runtime.** If the *graph* must be generated on the fly (an agent
  inventing its own next steps, unconstrained), reach for a generalist framework (LangGraph, CrewAI).
  PrismPath fixes the routing as auditable data; the open-ended work lives in the workers, not the graph.

The two strongest objections, *"structured output already solved routing"* and *"logic-as-data is just a
rules engine"*, get full answers (concessions included) in **[docs/objections.md](docs/objections.md)**;
the head-to-head against other paradigms lives in [comparisons/](prismpath/comparisons/README.md).

## Status

Working end to end: the flow kernel (parser / predicates / hybrid router / engine); the data-plane
toolchain (validate/lint, `test`, lockfile, calibrate, centroids, graph, import, label, portable, verify,
lsp); fan-out/composition with its Mission Control view; the durable layer (checkpoints, scheduler, git
Flow-Ledger, OTS anchoring, and a signed, envelope-checked policy hot-swap); the Connector SDK (six ports); the sprint control plane; and the portable
kernels, the Python reference plus three independent re-implementations (JS, Rust, Go), each passing all
**1,079 predicate + 27 flow vectors**. The Level M fragment additionally
[runs in FPGA fabric and as an in-kernel eBPF/XDP program](#it-runs-all-the-way-down-to-the-fpga-and-inside-the-kernel),
each certified on a declared subset. **649 Python + 18 Node kernel tests pass** (the two adapters add
227 more, with adversarial attestation-tamper and property coverage); the format is specified in
[SPEC.md](SPEC.md) (v1 draft). This repo is a curated export of an active research control plane. Licensed
Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). You may fork it and ship it, including inside a proprietary product; a redistributor keeps the LICENSE and NOTICE files and marks changed files, and Apache-2.0 requires no user-facing attribution.

**The launch is anchored.** The project that ships tamper-evident attestation pointed its own machinery at
itself: the `v0.1.0` release artifact is OpenTimestamps-anchored in **Bitcoin block 961224** (2026-08-06).
Don't take our word, or GitHub's timestamps; rebuild from the tag and check the chain:

```bash
git archive --format=tar.gz --prefix=prismpath-0.1.0/ v0.1.0 | sha256sum
# b3f07facaacc4daaead1cc8f53caf4637b7b1aaf1a165b3c50b949566ce52112
ots verify prismpath-0.1.0.tar.gz.ots   # .ots proofs ship with the release
```

## Docs and contributing

Start at the **[docs index](docs/README.md)**; the [decoder-ring](docs/decoder-ring.md) is the glossary
and repo map (every borrowed term in plain language, and where every module, kernel, and command lives).

- **Format and design:** [SPEC.md](SPEC.md) · [ten-minute tour](docs/guides/tour.md) ·
  [authoring](docs/guides/authoring.md) · [control plane](docs/design/control-plane.md) ·
  [architecture](docs/design/architecture.md) · [ledger anchoring](docs/design/spec-ledger-opentimestamps.md).
- **Research:** [primer](docs/research/primer-students-guide.md) ·
  [routing-spectrum paper](docs/research/paper-routing-spectrum.md) ·
  [engineering white paper](docs/research/whitepaper-engineering.md) ·
  [supporting evidence](docs/research/supporting-evidence.md).
- **Contribute:** [CONTRIBUTING.md](CONTRIBUTING.md). The perfect first PR is a lint rule (ten are
  waiting); DCO sign-off, not a CLA. Use it in CI via the [`prismpath` GitHub Action](action.yml) or the
  [pre-commit hooks](.pre-commit-hooks.yaml). Real workflows welcome in the
  [gallery](prismpath/gallery/README.md).
- Also: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) · [SECURITY.md](SECURITY.md) · [ROADMAP.md](ROADMAP.md) ·
  [CHANGELOG.md](CHANGELOG.md) · [CITATION.cff](CITATION.cff).

> **Commercial support and custom flows.** PrismPath is developed by Crystal Warden Labs; we build
> custom decidable flows and stand up the provable control plane around them, from the kernel to the
> FPGA to bare-metal MCUs, and support teams adopting it.

## Running the tests

```bash
python -m pytest prismpath/tests -q               # kernel: parser, predicates, router, engine
python -m pytest adapters/telemetry -q            # each adapter is self-rooted, so run them separately
python -m pytest adapters/fusion -q
node --test prismpath/portable/prismpath.test.mjs # the portable JS kernel
```
