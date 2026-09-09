# PrismPath: a control plane you can prove

[![ci](https://github.com/crystal-warden/prism-path/actions/workflows/ci.yml/badge.svg)](https://github.com/crystal-warden/prism-path/actions/workflows/ci.yml)
&nbsp;[![license: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
&nbsp;[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21816125.svg)](https://doi.org/10.5281/zenodo.21816125)

**Your agents' control policy as one signed document you can prove before it runs, that acts on only the
few bytes of each input that can actually change the decision.**

PrismPath is a decidable control plane. The policy that routes your agents and pipelines is a single
Markdown document you can read, prove, sign, and run byte identically from a browser to an FPGA. And because
the policy names exactly which distinctions in the data can change an outcome, a node ships only those: the
minimum sufficient statistic, provably the same decision as the full reading, about two bytes on the wire
instead of a hundred. That map is **Figueroa quantization**, and its decision preservation is machine
checked, not asserted.

**[Try it in your browser.](https://www.crystalwardenlabs.com/playground)** The kernel runs client side;
nothing to install, nothing you type leaves the page.

## Why you would use it

- **Prove the decision before it runs.** Routing is a total, decidable fragment (Level M): reachability and
  every transition are checkable ahead of time, and safety properties are model checked. No dead branch, no
  path you did not authorize, no runtime surprise.
- **Ship the decision, not the data.** The policy names exactly which slice of each input can change the
  outcome, so a node sends only that: provably the identical decision, about two bytes each, roughly 67
  times smaller than an OpenTelemetry record, and tamper evident on the wire.
- **Run it wherever the decision lives.** One signed table, compiled once as data, decides byte identically
  from a browser, to a verifier accepted program that hot swaps live inside the Linux kernel, to FPGA
  fabric, to bare metal MCUs across four instruction sets.
- **Enforce it cryptographically.** Every policy is signed, every hot swap is authorized and audited, and
  every decision leaves a tamper evident receipt. A change is a Markdown diff a non engineer can approve,
  rendered as a live before and after graph in the pull request itself.

None of this is asserted. Every claim is a reproducible row in the **[evidence
ledger](docs/research/supporting-evidence.md)**, anchored to Bitcoin, and much of this code was written by
AI agents under this same gated control plane, landing only after it cleared the checks. Check the artifact,
not the author.

## The idea, in one file

One Markdown file is the program. Each `## heading` is a step, each `-> target: condition` an edge, and
every deterministic transition is decidable before anything runs. Deterministic edges decide first and free,
in document order; an embedding router and a one shot model are reached only where meaning genuinely
requires one. The worker does the open ended work (an LLM agent, a plain function, a shell script);
PrismPath governs where the run goes next and writes a receipt for every decision, each carrying a one byte
cause code that says why it routed, refused, parked, or escalated. The ten minute tour walks a real flow end
to end: **[docs/guides/tour.md](docs/guides/tour.md)**.

## Go deeper

- **The whole system on one page**: who touches what, where every part lives, and what keeps the many
  implementations of one idea in agreement. [system map](docs/SYSTEM_MAP.md)
- **Figueroa quantization**, the decision preserving map from a reading to its minimum sufficient statistic
  (any representative of a cell routes identically). [paper](docs/research/paper-facet-figueroa-quantization.md)
- **The Facet wire**, self framing decision symbols with per packet Merkle roots, readable by standard
  network tooling through the shipped dissector. [protocol](PROTOCOL.md) · [dissector](integrations/wireshark/README.md)
- **A signed worst case bound** in every policy manifest, calibrated cycle exact on the RTL and witnessed on
  physical fabric pins (16,009 evaluations, max 9 cycles inside the signed 11).
- **The hardware**: FPGA fabric, four MCU ISAs, and a three node wireless fleet that hot swaps together
  behind a two phase commit, with a two minute silicon take that shows the whole chain deciding live.
  [prismpath-hw/](prismpath-hw/README.md)

## Try it

```bash
git clone https://github.com/crystal-warden/prism-path.git && cd prism-path
pip install -e .                                          # numpy only; embedder is an optional extra
prismpath validate prismpath/examples/pr_demo/triage.md   # your flow compiles
prismpath test prismpath/examples/pr_demo/triage.md       # fixture asserted routing, no model
```

Or skip the terminal: the **[live playground](https://www.crystalwardenlabs.com/playground)** runs the
portable kernel in your browser. **[GETTING_STARTED.md](GETTING_STARTED.md)** goes from clone to a real
agent driving your own flow in eight steps, each run before it was written down.

## Status and docs

Working end to end: the flow kernel; the data plane toolchain (validate, lint, test, lockfile, calibrate,
centroids, graph, verify); fan out and composition with its Mission Control view; the durable layer
(checkpoints, scheduler, git Flow-Ledger, OTS anchoring, and a signed, envelope checked hot swap); the
Connector SDK; and four portable kernels (Python, JS, Rust, Go), each passing all 1,079 predicate and 27
flow vectors. Specified in [SPEC.md](SPEC.md) (v1 draft), licensed Apache 2.0 (see [LICENSE](LICENSE) and
[NOTICE](NOTICE)). This repo is a curated export of an active research control plane, and its `v0.1.0`
release is OpenTimestamps anchored in Bitcoin block 961224 (2026-08-06):

```bash
git archive --format=tar.gz --prefix=prismpath-0.1.0/ v0.1.0 | sha256sum
# b3f07facaacc4daaead1cc8f53caf4637b7b1aaf1a165b3c50b949566ce52112
ots verify prismpath-0.1.0.tar.gz.ots   # .ots proofs ship with the release
```

Start at the **[docs index](docs/README.md)**; the **[decoder-ring](docs/decoder-ring.md)** is the glossary
and repo map. Contribute via **[CONTRIBUTING.md](CONTRIBUTING.md)** (the perfect first PR is a lint rule,
ten are waiting; DCO sign off, not a CLA). Run the tests with `python -m pytest prismpath/tests -q`.

> **Commercial support and custom flows.** PrismPath is developed by Crystal Warden Labs; we build custom
> decidable flows and stand up the provable control plane around them, from the kernel to the FPGA to bare
> metal MCUs, and support teams adopting it.
