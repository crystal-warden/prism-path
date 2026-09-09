# The public position: one story, told at different depths

*The canonical statement of what PrismPath is, what it claims, and what it does not claim. The README,
the company site, the product page, the papers, and the package docstring are views over this document
and may not invent their own definition. Every number here names the evidence ledger row that backs it.
September 2026, position v1.*

## 1. One sentence

PrismPath is a control plane for autonomous systems, one of many. It lets people define what an
autonomous system is permitted to do, enforces those boundaries where the system actually runs, changes
them without rebuilding the system, and leaves a signed receipt for every consequential decision.

What is unusual is the approach, not the category: the decision structure a human authors is restricted
to a decidable, tabular fragment, so one compiled image decides identically from a Python process down to
a 1.7 KB interpreter on a microcontroller or a fabric, carries a signed worst case bound, and admits a
decision sufficient telemetry wire, Facet, on top.

## 2. The problem

Autonomous systems increasingly separate the component that produces a candidate action (a model, an
agent, an optimizer, a sensor pipeline, a workflow engine) from the question of whether that action is
permitted. Today that boundary is usually spread across application code, prompts, orchestration
callbacks, infrastructure configuration, and after the fact monitoring. Nobody can point at it, diff it,
prove anything about it, or show that it held.

PrismPath makes the boundary an explicit artifact: a document a person can read, a structure a tool can
verify, an image a substrate can execute, and a receipt an auditor can check.

## 3. The architecture, in three words

**Prove what can happen. Enforce what may happen. Prove what happened.**

| | before execution | during execution | after execution |
|---|---|---|---|
| what | static analysis, reachability, bounded model checking, portability, conformance | deterministic decisions, semantic escalation, abstention, human routing, the signed pack and its version floor | receipts with cause codes, Merkle roots, anchors, replay |
| where | `prismpath validate`, `verify`, `capability`, `test` | the engine, the kernels, the substrates, `swap` | `ledger`, `trail`, the audit log, the evidence ledger |

Three concerns stay separate on purpose:

- **Authority.** What may happen. Authored by a person, held in the flow document, compiled to an image.
- **Computation.** How a candidate action is produced. A model, an agent, a program, an optimizer. PrismPath
  does not own it and does not need to.
- **Evidence.** What happened. Receipts, trails, anchors, all verifiable without trusting the emitter.

## 4. What it governs, and what it does not replace

PrismPath governs the transitions between components: worker to worker, agent to human, tool to agent,
software to device, policy version to policy version. It does not require a particular agent framework,
model, orchestrator, or hardware. A worker can be a hosted model, a local model, a shell process, a
function, another orchestration system, or a deterministic program; PrismPath decides where the run goes
next and records why. It composes with existing engines rather than displacing them: the pre registered
comparison showed its wire carrying OPA's input and its receipt machinery wrapping OPA's decision logs
(ledger row #142).

## 5. The mechanism

1. **A person authors the decision structure.** A Markdown flow: each heading is a step, each edge a
   condition. Deterministic edges decide first and free, in document order; an embedding router and a one
   shot model are reached only where meaning genuinely requires one. The document your team reads is the
   graph the engine runs. PrismPath does not compile policy from prose; the step from a governing policy to
   its predicates and routes is authored, and the tooling checks the result.
2. **Tooling proves the structure before it runs.** Undefined targets, unreachable nodes, unbounded
   cycles, always false edges; reachability under an assumption; which targets the flow compiles to.
3. **The deterministic fragment compiles to a table image.** Level M, the match action fragment, is the
   part of the language every substrate can execute: field against constant comparisons, membership in
   literal lists, truthiness, and, or, not. The image is a few hundred bytes and carries a computed worst
   case bound.
4. **The image is signed and swapped.** A pack binds the image, its fields, its version, and its bound to
   a key; the host verifies the signature, the declared envelope, and a monotonic version floor, flips
   atomically, and writes one audit event either way.
5. **Every decision leaves a receipt.** A cause code says why the run routed, refused, parked, or
   escalated; receipts Merkle root per session and anchor to a timestamp a third party can verify.

## 6. One authority model, many substrates

The same image decided the same 23 corpus readings identically on host Python, the C reference, in
kernel on aarch64 and x86_64, on both ISAs of an RP2350, and on a Zynq-7020 fabric (row #143). Four
language kernels (Python, JavaScript, Rust, Go) pass the same 1,079 predicate and 27 flow vectors; the
kernel target certifies 124 of 124 in kernel on every push; the fabric's signed bound was witnessed on
the pins at 34 of 35 and 23 of 24 cycles for the comparison images (row #143) and across 16,009
evaluations at most 9 cycles inside a signed 11 for the resident policy (rows #122, #123).

Two tiers, kept distinct so nobody infers that a model backed route compiles to a chip: P0, P1, and P2
describe how much of a flow the general engine can run without a model; Level M is the decidable fragment
inside P0 that the images and every hardware target execute.

## 7. Decision sufficient execution: Figueroa quantization and Facet

A policy depends on only some distinctions in its input. Figueroa quantization derives, from the policy
text, the partition of each field into the cells that can change a decision, and a reading is sent as one
symbol per cell. Any representative of a cell routes identically; that property is proven in Lean 4,
thirteen theorems with zero sorry on the standard axioms, within a declared domain of well typed integer
readings, and bridged to the shipped code by 623 evaluated checks (row #140). Stating the theorem found
three defects in the reference quantizer, now fixed and pinned by the corpus (row #141).

Facet is the wire on top: self framing Fibonacci codes, per packet Merkle roots, a refresh profile that
bounds staleness by cadence, replay refusal with a named cause, and a concentrator that amortises the IP
envelope across a fleet. Measured: about 1.5 B per decision with its integrity apparatus counted, 66.9
times under an OpenTelemetry record of the same decision (rows #84, #95); 2.06 B per reading at fleet 50
(row #127); 4 to 6 B per reading against 117, 237, and 512 B for OPA, Cedar, and Cerbos over their
documented interfaces (row #142). The wire is PrismPath's own and composes with other engines.

## 8. Capability status

| capability | status | evidence |
|---|---|---|
| declarative policy, deterministic and semantic routing, human escalation, durable execution | implemented | `prismpath/kernel`, `routing`, `workers`; the test suite |
| static analysis, reachability, bounded model checking, portability report | implemented | `verify`, `capability`; conformance corpora |
| signed policy packs, envelope, version floor, atomic swap, attestation | implemented | rows #117 and onward, `hotswap/` |
| receipts with cause codes, Merkle trails, OpenTimestamps and RFC 3161 anchoring | implemented | `ledgers/`, `causes.py`, rows #128, #131 to #135 |
| four language kernels on one frozen corpus | implemented | `portable/conformance/` |
| in kernel execution (eBPF, XDP and TC) | demonstrated, CI gated | rows #78 to #80, #128 |
| microcontroller execution, four ISAs | demonstrated on hardware | rows #92, #97, #98, #143 |
| FPGA fabric execution with a pin witnessed bound | demonstrated on silicon | rows #108, #117, #122, #123, #143 |
| distributed policy update behind a quorum, real radios | demonstrated in the field | row #136 |
| Figueroa quantization | implemented, proven within the declared domain | rows #140, #141 |
| Facet wire, Vector codec, Wireshark dissector | implemented and measured | rows #84, #86, #124 to #127 |
| GRC adjudication adapter (machine checkable controls, evidence typed verdicts, OSCAL) | implemented, dogfooded on a real enclave | rows #137 to #139 |
| operator overlays that expire by construction, the trail read side | implemented | `docs/guides/operator.md` |
| drift detection beyond the lockfile and staleness bound, authorized recovery, homeostatic control | research direction | not claimed |
| multimodal sensing, quantum assisted computation, quantum sensing | research direction | not claimed |

## 9. What the comparison established

A pre registered comparison against OPA, Cedar, Cerbos, OpenFGA, and Openlane, frozen before any
comparator was installed and run to the end on real systems and hardware, computed every property
PrismPath builds in as reachable by at least one comparator with bounded glue, and every property where
PrismPath was expected to lose as a loss (rows #142, #143; `prismpath/comparisons/VERDICT.md`). So
PrismPath is not a layer the existing engines cannot reach. What the same table shows: PrismPath is native
on all eight properties where no comparator is native on more than two; OPA reaches the row only with 391
lines of glue that nobody ships; on the same microcontroller the OPA path needs about 312 KB of RAM and a
136 KB module per policy against a 1.7 KB interpreter class and 224 B images, and decides in milliseconds
against sub millisecond with no stated bound. Those are the differences of degree and composition the
public story rests on, and the verdict is published because it is the credibility of everything else.

## 10. Vocabulary contract

Use these words this way, everywhere.

- **control plane**: the category PrismPath is one of many in. Never "the" control plane, never a
  distinct layer.
- **authority, decision structure, policy**: the authored boundary. **Flow**: the Markdown document that
  holds it. **Image**, **pack**, **envelope**: the compiled, signed, and bounded forms.
- **Level M**: the decidable fragment every substrate executes. **P0, P1, P2**: how much of a flow runs
  without a model.
- **abstain**: insufficient information, distinct from **deny** (not authorized) and from a **refusal
  with cause** (nothing matched and no catch all, cause 36 on the receipt).
- **receipt**: the per decision record with its cause code; **trail**: the Merkle rooted sequence;
  **anchor**: its timestamp.
- **Figueroa quantization**: the decision sufficient map; **Facet**: the wire that carries it.
- **Mission Control**: the operator's console. **Orchestration**: the sprint and swarm machinery, kept as
  the fallback for an organisation without its own.

## 11. Claims we make

- One authored decision structure decides identically across the substrates listed in section 6.
- Every policy is signed; every swap is authorized, version floored, and audited; every decision leaves a
  receipt with a cause a third party can verify without trusting the emitter.
- Deterministic transitions are proven before execution; a per policy worst case bound travels signed with
  the image and has been honored on silicon.
- The wire ships the decision, not the data, and its decision preservation is proven within a declared
  domain.
- Defined governance requirements can be turned into enforceable controls that cannot be bypassed through
  the governed execution path, with evidence that they were enforced.

## 12. Claims we do not make

- Not a distinct layer the existing engines cannot reach. The comparison measured the opposite.
- Not a compiler of policy from prose. The predicates are authored; the tooling checks and compiles them.
- Not a legal compliance guarantee. Enforcement within the governed path plus evidence, nothing more.
- Not a sandbox. Execution isolation belongs to the runtime or the provider; PrismPath governs what is
  permitted to run, what outcome is accepted, and where execution goes next.
- Not an agent framework, not a model, not a replacement for an orchestrator. Workers sit underneath.
- Not a proof of the evaluator. The Lean development proves the quantization; the interpreters are
  certified by conformance.
- Not homeostasis, not quantum, not multimodal. Those are research directions and are labelled so.

## 13. The four people

| persona | horizon | their surface |
|---|---|---|
| process owner | the policy of record | the flow, `validate`, `test`, `graph` |
| engineer | the interface once, calibration, delivery | `contract`, `capability`, `compile`, `lock`, the kernels, CI |
| operator | day to day, short lived changes, the feedback wheel | Mission Control, `swap`, `attest`, `trail`, overlays |
| evaluator | after the fact | receipts, `ledger`, the evidence ledger, the comparison |

`docs/SYSTEM_MAP.md` maps every directory to these people and holds the conformance topology.

## 14. The canonical example

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

Validate it, test it against its fixture table, change one condition, watch the route change, read the
receipt. That is the product; everything below it is why the promise can be kept.
