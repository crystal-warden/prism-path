# Documentation

Long-form documentation lives here, in three groups. Start at the repo root if you're new —
[`README.md`](../README.md) is the front door and [`GETTING_STARTED.md`](../GETTING_STARTED.md)
is the walk from "what's this?" to a running flow.

## guides/ — how to use it

| doc | what it covers |
|---|---|
| [authoring.md](guides/authoring.md) | the flow authoring reference: file anatomy, the four edge tiers, the agent contract, predicates, durable execution, annotations, plugins, fan-out, the portable subset — and the invariants to preserve when extending |
| [frontier-agent-integration.md](guides/frontier-agent-integration.md) | pairing PrismPath with frontier agents and LLMs: CLI workers, API/local backends, auto-unblock loops, `@spawn` swarms, human-in-the-loop |

## design/ — how and why it is built

| doc | what it covers |
|---|---|
| [architecture.md](design/architecture.md) | the flow kernel, the portable kernels, the control plane, and the gate-plugin seam |
| [framework.md](design/framework.md) | the operating methodology: spec-per-module, gates as the definition of done, the hard-won lessons |
| [spec-guard-onion.md](design/spec-guard-onion.md) | formal design spec for the safety floor — the policy grammar with no verb for permitting |
| [spec-ledger-opentimestamps.md](design/spec-ledger-opentimestamps.md) | formal design spec for Flow-Ledger anchoring: OpenTimestamps, the air-gap tier, and the honest caveats |

Running `python tools/arch_guard.py` writes a hexagonal-boundary scorecard to
`docs/design/arch-scorecard.md`. It is generated, git-ignored, and regenerated on every run — the
committed artifact is [`tools/arch_scorecard.json`](../tools/arch_scorecard.json).

## research/ — papers, evidence, measurement

| doc | what it covers |
|---|---|
| [primer-students-guide.md](research/primer-students-guide.md) | **start here for the ideas** — the papers' thesis without the vocabulary; no CS degree required |
| [paper-routing-spectrum.md](research/paper-routing-spectrum.md) | the research paper: the routing spectrum, the N=301 evaluation, the head-to-head, limitations |
| [whitepaper-engineering.md](research/whitepaper-engineering.md) | the engineering white paper: format, runtime, data plane, control plane, operational lessons |
| [supporting-evidence.md](research/supporting-evidence.md) | the results ledger — every claim mapped to a measured result and its provenance, negative results included |
| [bypass-measurement.md](research/bypass-measurement.md) | the pre-registered protocol for measuring the safety floor's bypass rates, with its amendment trail |
| [soc-triage-case-study.md](research/soc-triage-case-study.md) | a measured deployment: blue-team SOC triage over a live SIEM |

## What isn't here (and why)

- **Normative + entry-point docs stay at the repo root** — [`SPEC.md`](../SPEC.md) (the format
  specification), [`GETTING_STARTED.md`](../GETTING_STARTED.md), [`ROADMAP.md`](../ROADMAP.md),
  plus the files GitHub reads there by convention (`CONTRIBUTING`, `CODE_OF_CONDUCT`, `SECURITY`,
  `CHANGELOG`, `LICENSE`, `CITATION.cff`).
- **A `README.md` documents the directory it sits in**, so subsystem docs stay with their code:
  [portable kernel](../prismpath/portable/README.md) ·
  [conformance vectors](../prismpath/portable/conformance/README.md) ·
  [benchmark](../prismpath/benchmark/README.md) ·
  [comparisons](../prismpath/comparisons/README.md) ·
  [examples](../prismpath/examples/README.md) · [gallery](../prismpath/gallery/README.md) ·
  [editor surfaces](../prismpath/editor/README.md) ·
  [adapters](../adapters/ADAPTER_GUIDE.md) · [Go kernel](../prismpath-go/README.md).
- **Some `.md` files are program data, not documentation** — the flows in `prismpath/flows/`, the
  gallery templates, the prompt assets in `prismpath/nudges/`, the guard's
  `prismpath/policies/statutory_floor.md`, and the deliberately-broken corpus in
  `prismpath/tests/fixtures/broken/`. Code reads these at runtime; they are not prose.
