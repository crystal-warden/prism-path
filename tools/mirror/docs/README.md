# Documentation

Long form documentation lives here, in three groups. Start at the repo root if you're new:
[`README.md`](../README.md) is the front door and [`GETTING_STARTED.md`](../GETTING_STARTED.md)
is the walk from "what's this?" to a running flow.

> **[DICTIONARY.md](DICTIONARY.md)**: the vocabulary: one thing, one name, at one layer, every term
> defined from the point of view of a single decision. The product subset of the research Dictionary;
> the substrate and GRC entries stay with the code they describe.
>
> **[../COMPATIBILITY.md](../COMPATIBILITY.md)**: the research revision this product adopted, the
> specifications and formats, the frozen corpora with their hashes, and what the product CI checks.
> **[../DIVERGENCES.md](../DIVERGENCES.md)**: every intentional difference from research and why.

## guides/: how to use it

| doc | what it covers |
|---|---|
| [tour.md](guides/tour.md) | the ten minute engineer's tour of the flow kernel: worker contract, routers, prefilter, static analysis, `verify`, fan out, attestation, the portable subset |
| [authoring.md](guides/authoring.md) | the flow authoring reference: file anatomy, the four edge tiers, the worker contract, predicates, durable execution, annotations, plugins, fan out, the portable subset, and the invariants to preserve when extending |
| [workers.md](guides/workers.md) | run any program (Python, JS, Go, Rust, an existing binary) as a node's worker: the stdin/JSON/exit contract, worked examples in four languages across three jobs (CI gate, log alerting, semver release gate), error tier retry, per node engines |
| [code-nodes.md](guides/code-nodes.md) | the Python function worker case: the `@code` capability envelope, the static gate, and the fail closed sandbox |
| [frontier-agent-integration.md](guides/frontier-agent-integration.md) | pairing PrismPath with frontier agents and LLMs: CLI workers, API/local backends, auto unblock loops, `@spawn` swarms, human in the loop |
| [process-owner.md](guides/process-owner.md) | the process owner's guide: the flow and its fixtures as the policy of record, how a change reaches production |
| [engineer.md](guides/engineer.md) | the engineer's guide: the contract once, delivery, calibration, the kernels and the gates |
| [assessor.md](guides/assessor.md) | the assessor's guide: receipts, the trail, anchors, the evidence base |
| [operator.md](guides/operator.md) | the operator's day: Mission Control, swap and attest, short lived policy changes that expire by construction, reading the trail |
| [mission-control-api.md](guides/mission-control-api.md) | the Mission Control API: observe, control, events, prove |

## design/: how and why it is built

| doc | what it covers |
|---|---|
| [rust-lockfiles.md](design/rust-lockfiles.md) | where a Cargo lockfile is committed and where it is not, and how the minimum supported Rust version is declared and built |
| [orchestration.md](design/orchestration.md) | the reference deployment: the sprint loop, gates as the definition of done, Mission Control, the worked example |
| [architecture.md](design/architecture.md) | the flow kernel, the portable kernels, the orchestration layer, and the gate-plugin seam |
| [framework.md](design/framework.md) | the operating methodology: spec per module, gates as the definition of done, the hard won lessons |
| [spec-guard-onion.md](design/spec-guard-onion.md) | formal design spec for the safety floor: the policy grammar with no verb for permitting |
| [spec-ledger-opentimestamps.md](design/spec-ledger-opentimestamps.md) | formal design spec for Flow Ledger anchoring: OpenTimestamps, the air gap tier, and the honest caveats |
| [spec-telemetry-cbor.md](design/spec-telemetry-cbor.md) | interop framing spec: carry the telemetry decision symbols in CBOR (RFC 8949) for friction free integration, alongside the compact Fibonacci wire |
| [spec-secure-hotswap.md](design/spec-secure-hotswap.md) | formal design spec for the secure policy hot swap: authorized, envelope bounded, attested, audited + atomic, published deliberately as prior art |
| [spec-cause-codes.md](design/spec-cause-codes.md) | the cause code registry: one byte that says why a decision or refusal happened, the same byte in the engine, the pack verifier, the kernel, the fabric, and on the wire |
| [spec-crypto-agility.md](design/spec-crypto-agility.md) | the signing suite registry and the proofs that a suite migration cannot strand a policy |

## Research, at the adopted revision

The papers, the evidence ledger and the measurement protocols live in the research repository. These
links are pinned to the revision this product adopted (`COMPATIBILITY.md`), so a claim and the evidence
behind it stay matched even as research moves on.

| doc | what it covers |
|---|---|
| [the public position](https://github.com/crystal-warden/prism-path/blob/40a9b05b3523cb4943b583b77c6fb86f93d795ee/docs/POSITION.md) | one sentence, the problem, the architecture in three words, capability status, the claims made and the claims not made |
| [the system map](https://github.com/crystal-warden/prism-path/blob/40a9b05b3523cb4943b583b77c6fb86f93d795ee/docs/SYSTEM_MAP.md) | the whole system on one page: where every part lives and the conformance topology across every implementation |
| [primer-students-guide.md](https://github.com/crystal-warden/prism-path/blob/40a9b05b3523cb4943b583b77c6fb86f93d795ee/docs/research/primer-students-guide.md) | the papers' thesis without the vocabulary |
| [paper-routing-spectrum.md](https://github.com/crystal-warden/prism-path/blob/40a9b05b3523cb4943b583b77c6fb86f93d795ee/docs/research/paper-routing-spectrum.md) | the routing spectrum, the N=301 evaluation, the head to head, limitations |
| [whitepaper-engineering.md](https://github.com/crystal-warden/prism-path/blob/40a9b05b3523cb4943b583b77c6fb86f93d795ee/docs/research/whitepaper-engineering.md) | format, runtime, data plane, control plane, operational lessons |
| [supporting-evidence.md](https://github.com/crystal-warden/prism-path/blob/40a9b05b3523cb4943b583b77c6fb86f93d795ee/docs/research/supporting-evidence.md) | the results ledger: every claim mapped to a measured result and its provenance |
| [paper-facet-figueroa-quantization.md](https://github.com/crystal-warden/prism-path/blob/40a9b05b3523cb4943b583b77c6fb86f93d795ee/docs/research/paper-facet-figueroa-quantization.md) | Figueroa quantization, the decision sufficient wire, the measurements |
| [the decoder ring](https://github.com/crystal-warden/prism-path/blob/40a9b05b3523cb4943b583b77c6fb86f93d795ee/docs/decoder-ring.md) | every borrowed term explained in plain language |

## What isn't here (and why)

- **Normative and entry point docs stay at the repo root**: [`SPEC.md`](../SPEC.md) (the format
  specification), [`PROTOCOL.md`](../PROTOCOL.md) (the Facet wire), [`GETTING_STARTED.md`](../GETTING_STARTED.md),
  [`COMPATIBILITY.md`](../COMPATIBILITY.md), [`DIVERGENCES.md`](../DIVERGENCES.md), plus the files GitHub reads
  there by convention (`CONTRIBUTING`, `CODE_OF_CONDUCT`, `SECURITY`, `CHANGELOG`, `LICENSE`, `CITATION.cff`).
- **A `README.md` documents the directory it sits in**, so subsystem docs stay with their code:
  [conformance vectors](../prismpath/portable/conformance/README.md) · [Facet](../prismpath/telemetry/README.md) ·
  [examples](../prismpath/examples/README.md) · [gallery](../prismpath/gallery/README.md) ·
  [the kernel crate](../prismpath-rs/README.md) · [the telemetry crate](../prismpath-telemetry-rs/README.md) ·
  [the hot swap crate](../prismpath-hotswap-rs/README.md) · [preflight](../prismpath-preflight/README.md) ·
  [the maintenance tools](../tools/README.md).
