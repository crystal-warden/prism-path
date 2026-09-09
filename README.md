# PrismPath: a control plane for autonomous systems

[![ci](https://github.com/crystal-warden/prism-path/actions/workflows/ci.yml/badge.svg)](https://github.com/crystal-warden/prism-path/actions/workflows/ci.yml)
&nbsp;[![license: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
&nbsp;[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21816125.svg)](https://doi.org/10.5281/zenodo.21816125)

**Define what an autonomous system is allowed to do. Enforce it where the system runs. Change it without
rebuilding the system. Get a signed receipt for every decision.**

PrismPath is a control plane for autonomous systems, one of many. What is unusual is the approach: the
decision structure a person authors is restricted to a decidable, tabular fragment, so one compiled image
decides identically from a Python process down to a 1.7 KB interpreter on a microcontroller or an FPGA
fabric, carries a signed worst case bound, and admits a decision sufficient telemetry wire on top. The
engine is open. The policy is inspectable. The decisions are proven before they run and receipted after.

**[Try it in your browser](https://www.crystalwardenlabs.com/playground)** · **[Read the
architecture](docs/SYSTEM_MAP.md)** · **[Run it](#try-it)**

## The problem

Autonomous systems increasingly separate the component that produces a candidate action, a model, an
agent, an optimizer, a workflow engine, from the question of whether that action is permitted. Today that
boundary is spread across application code, prompts, orchestration callbacks, and after the fact
monitoring. Nobody can point at it, diff it, prove anything about it, or show that it held.

PrismPath makes the boundary an explicit artifact.

```
model / agent / worker
        |
        | candidate outcome
        v
    PrismPath  --->  allow | deny | abstain | human | refusal with cause
        |
        v
      action  --->  receipt
```

## Prove what can happen. Enforce what may happen. Prove what happened.

- **Before execution.** Routing is a total, decidable fragment: undefined targets, unreachable nodes,
  unbounded cycles and always false edges are caught by `validate`; reachability under an assumption is
  model checked by `verify`; `capability` says which targets the flow compiles to.
- **During execution.** Deterministic edges decide first and free, in document order; an embedding
  router and a one shot model are reached only where meaning genuinely requires one, and low confidence
  abstains or escalates to a person instead of guessing. The signed pack is verified, envelope checked
  and version floored before it takes effect.
- **After execution.** Every decision leaves a receipt with a one byte cause code that says why it
  routed, refused, parked or escalated; receipts Merkle root per session and anchor to a timestamp a third
  party can verify without trusting the emitter.

## Works with the systems you already have

PrismPath does not own the model, agent, orchestrator, operating system or hardware that produces a
candidate action. A worker can be a hosted model, a local model, a shell process, a function, another
orchestration system or a deterministic program. PrismPath governs the transitions between them: worker
to worker, agent to human, tool to agent, software to device, policy version to policy version. Its wire
and its receipt machinery compose with other engines too; the comparison below carried OPA's input on the
wire and wrapped OPA's decision logs in receipts.

## The idea, in one file

One Markdown file is the program. Each `## heading` is a step, each `-> target: condition` an edge. The
document your team reads is the graph the engine runs.

```markdown
## classify
Read the incoming support ticket. Emit `category`, `amount`, and `sentiment`.
@emits(category, amount, sentiment)
-> human_review: when category == "billing_dispute" and amount > 500
-> billing: when category in ("billing", "billing_dispute")
-> outage: when category == "outage"
-> retention: when sentiment == "angry"
-> general: else
```

The predicates are authored by a person; PrismPath does not compile policy from prose. What it compiles
is that authored structure: the deterministic fragment (Level M: field against constant, membership in a
literal list, truthiness, and, or, not) becomes a table image of a few hundred bytes with a computed
worst case bound, signed into a pack, and the same image is what every substrate executes. A change to
the policy is a Markdown diff a non engineer can approve, rendered as a live before and after graph in
the pull request. The ten minute tour walks a real flow end to end: **[docs/guides/tour.md](docs/guides/tour.md)**.

## One authority model, many substrates

```
                 one authored policy
                         |
              signed image + wcet bound
                         |
     +---------+---------+---------+---------+
     |         |         |         |         |
  Python     JS/Rust    eBPF    RP2350     Zynq
  engine      /Go      kernel  AVR ESP32  fabric
     |         |         |         |         |
     +---------+---------+---------+---------+
                         |
                  the same decision
```

The same image decided the same 23 corpus readings identically on host Python, the C reference, in
kernel on aarch64 and x86_64, on both ISAs of an RP2350 and on a Zynq-7020 fabric. Four language kernels
pass the same 1,079 predicate and 27 flow vectors; the kernel target certifies 124 of 124 in kernel on
every push; the fabric's signed bound was witnessed on the pins at 34 of 35 and 23 of 24 cycles for the
comparison images and at most 9 cycles inside a signed 11 across 16,009 evaluations for the resident
policy. Two tiers are kept distinct so nobody infers that a model backed route compiles to a chip: P0, P1
and P2 describe how much of a flow runs without a model; Level M is the fragment every hardware target
executes.

## Ship the decision, not the data

A policy depends on only some distinctions in its input. **Figueroa quantization** derives, from the
policy text, the cells of each field that can change a decision, and a reading is sent as one symbol per
cell: any representative of a cell routes identically. That decision preservation is proven in Lean 4,
thirteen theorems with zero `sorry` on the standard axioms, within a declared domain of well typed
integer readings, and bridged to the shipped code by 623 evaluated checks. Stating the theorem found
three defects in the reference quantizer, now fixed and pinned by the corpus.

**Facet** is the wire on top: self framing Fibonacci codes, per packet Merkle roots, a staleness bound
by cadence, replay refusal with a named cause, and a concentrator for fleets. About 1.5 B per decision
with its integrity apparatus counted, 66.9 times under an OpenTelemetry record of the same decision;
2.06 B per reading at fleet 50; readable in Wireshark through the shipped dissector.
[protocol](PROTOCOL.md) · [paper](docs/research/paper-facet-figueroa-quantization.md) ·
[dissector](integrations/wireshark/README.md)

## What is implemented, what is demonstrated, what is research

| capability | status |
|---|---|
| declarative policy, deterministic and semantic routing, human escalation, durable execution | implemented |
| static analysis, reachability, bounded model checking, portability report | implemented |
| signed packs, envelope, version floor, atomic hot swap, attestation | implemented |
| receipts with cause codes, Merkle trails, OpenTimestamps and RFC 3161 anchoring | implemented |
| four language kernels on one frozen corpus | implemented |
| in kernel execution (eBPF, XDP and TC) | demonstrated, CI gated |
| microcontroller execution, four ISAs; FPGA fabric with a pin witnessed bound | demonstrated on hardware |
| distributed policy update behind a quorum on real radios | demonstrated in the field |
| Figueroa quantization | proven within the declared domain |
| Facet wire, Vector codec, Wireshark dissector | implemented and measured |
| GRC adjudication adapter: machine checkable controls, evidence typed verdicts, OSCAL | implemented, dogfooded on a real enclave |
| drift detection beyond the lockfile and staleness bound, authorized recovery, homeostatic control | research direction |
| multimodal sensing, quantum assisted computation | research direction |

## Don't take our word for it

Every claim above is a row in the **[evidence ledger](docs/research/supporting-evidence.md)**: claim,
method, result, honest scope, provenance, anchored to Bitcoin. Much of this code was written by AI
agents under this same gated control plane and landed only after it cleared the checks. Check the
artifact, not the author.

That includes the claim that did not survive. A **[pre registered
comparison](prismpath/comparisons/VERDICT.md)** against OPA, Cedar, Cerbos, OpenFGA and Openlane,
frozen before any comparator was installed and run to the end on real systems and hardware, found that
every property PrismPath builds in is reachable by at least one comparator with bounded glue, so
PrismPath is not a layer the existing engines cannot reach. The same table shows PrismPath native on all
eight properties where no comparator is native on more than two, that OPA reaches the row only with 391
lines of glue nobody ships, and that on the same microcontroller the OPA path needs about 312 KB of RAM
and a 136 KB module per policy against a 1.7 KB interpreter class and 224 B images. Those are the
differences the story above rests on, reported straight.

## Try it

```bash
git clone https://github.com/crystal-warden/prism-path.git && cd prism-path
pip install -e .                                          # numpy only; embedder is an optional extra
prismpath validate prismpath/examples/pr_demo/triage.md   # your flow compiles
prismpath test prismpath/examples/pr_demo/triage.md       # fixture asserted routing, no model
prismpath --help                                          # commands grouped by who runs them
```

Or skip the terminal: the **[live playground](https://www.crystalwardenlabs.com/playground)** runs the
portable kernel in your browser; nothing you type leaves the page. **[GETTING_STARTED.md](GETTING_STARTED.md)**
goes from clone to a real agent driving your own flow in eight steps.

## Who it is for

Four people touch a deployment, and the commands, the docs and the package layout are grouped by them: the
**process owner** who authors and tests the policy of record; the **engineer** who establishes the
interface once, calibrates for deployment and delivers; the **operator** who runs the system day to day,
swaps and attests policy, authors short lived changes that expire by construction, and reads the trail;
and the **evaluator** who anchors, verifies and reads the evidence. **[docs/SYSTEM_MAP.md](docs/SYSTEM_MAP.md)**
maps every directory to them and holds the conformance topology that keeps the many implementations of
one idea in agreement. The **[operator's guide](docs/guides/operator.md)** is the day to day view.

## Status and docs

The public position, what is claimed and what is not, is **[docs/POSITION.md](docs/POSITION.md)**.
Specified in [SPEC.md](SPEC.md) (the flow format and Level M) and [PROTOCOL.md](PROTOCOL.md) (Facet),
licensed Apache 2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). Start at the **[docs
index](docs/README.md)**; the **[decoder ring](docs/decoder-ring.md)** is the glossary and repo map.
Contribute via **[CONTRIBUTING.md](CONTRIBUTING.md)** (DCO sign off, not a CLA). Run the tests with
`python -m pytest prismpath/tests -q`.

This repo is a curated export of an active research control plane, and its `v0.1.0` release is
OpenTimestamps anchored in Bitcoin block 961224 (2026-08-06):

```bash
git archive --format=tar.gz --prefix=prismpath-0.1.0/ v0.1.0 | sha256sum
# b3f07facaacc4daaead1cc8f53caf4637b7b1aaf1a165b3c50b949566ce52112
ots verify prismpath-0.1.0.tar.gz.ots   # .ots proofs ship with the release
```

> **Commercial support.** PrismPath is developed by Crystal Warden Labs. The engine is open; the
> expertise is what you buy: we assess where an autonomous system's authority actually lives, put
> enforceable boundaries around one consequential workflow without replacing the stack, and stand up the
> control plane from the kernel to the FPGA to bare metal, then operate it with you.
