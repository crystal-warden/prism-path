# System map: one signed rulebook, read two ways

PrismPath is a control plane with receipts, one of many control planes. What is unusual is the
approach: the decision structure a human authors from governing policy is restricted to a decidable,
tabular fragment (Level M), so one compiled image decides identically from a Python process down to a
1.7 KB interpreter on a microcontroller or a fabric, carries a signed worst case bound, and admits a
decision sufficient telemetry wire, Facet, on top. This page is the map a newcomer needs to see that
the parts are one system: who touches what, where each part lives, and what keeps the many
implementations of the same idea in agreement.

## 1. The two readings of the rulebook

```
policy of record (a Markdown flow)
        |
        | prismpath validate / test / verify        (the owner's side)
        v
compiled table image (.ppt) + signed pack + envelope + wcet bound
        |                                            (the engineer's side: contract, capability, compile, swap keygen/envelope/pack)
        +---- decides ----> Python engine, JS, Rust, Go kernels                 (host)
        +---- decides ----> C target, eBPF/XDP in the Linux kernel              (kernel, appliance)
        +---- decides ----> RP2350, AVR, ESP32 firmware, Zynq fabric RTL        (device, silicon)
        |
        | every decision leaves a receipt with a cause code, Merkle rooted, anchored
        v
receipts, audit trail, ledger anchors                (the evaluator's side: ledger, swap verify, facet decode)

readings ---- Facet: quantize to decision cells, Zeckendorf code, self framing ----> the same decision, on the wire
                                                     (the same policy induces the partition; the wire ships the decision, not the data)
```

The control plane and the protocol are not two systems: the partition Facet quantizes with is derived
from the same policy text the interpreters decide with, and the receipt that leaves the interpreter
is the same struct on the wire, in the kernel, and on the fabric.

## 2. Who touches what

| persona | horizon | primary surface | commands |
|---|---|---|---|
| process owner | the policy of record, long term change management | the flow document, `prismpath/examples/`, `docs/guides/authoring.md` | `init`, `validate`, `test`, `graph`, `lint`, `context` |
| engineer | establish the interface once, calibrate for deployment, deliver | `contract` output, the kernels, CI, the pack and envelope | `contract`, `capability`, `compile`, `portable`, `lock`, `verify`, `plugins`, `ci-report`, `lsp`, `import`, `calibrate`, `label`, `annotate`, `kappa`, `centroids`, `swap keygen`, `swap envelope`, `swap pack` |
| operator | day to day: monitor, assess for policy mutation, author short lived changes | Mission Control (`prismpath/mission_control/`, `docs/guides/mission-control-api.md`), the PolicyHost | `run`, `resume`, `compose`, `swap swap`, `swap attest`, `trail`; see `docs/guides/operator.md` |
| evaluator | after the fact: was the decision right, and can it be proven | receipts, the audit trail, ledger anchors | `ledger` (anchor, upgrade, verify, export-request, relay-stamp, import-proofs, rfc3161), `swap verify`, `facet decode` |

`prismpath --help` prints the commands in these groups.

## 3. Where each part lives

| directory | what it is | persona |
|---|---|---|
| `prismpath/` | the Python reference: parser, predicates, engine, cause registry, static analysis and model checking, routing tiers, guard, signed pack and PolicyHost, audit log and ledgers, the CLI, Mission Control. Also the sprint and swarm machinery (`run_sprint.py`, `swarm_*.py`, `orchestrator.py`, `gates.py`): the fallback orchestration layer for an organisation without one of its own, not required by the format | all |
| `prismpath/portable/` | the JS kernel and the frozen conformance corpus every kernel is judged by | engineer |
| `prismpath-rs/`, `prismpath-go/` | the P0 kernel in Rust and Go | engineer |
| `prismpath-hw/` | the C target `interp.c`, the `.ppt` compiler `ppt_compile.py`, `TABLE_FORMAT.md`, the fabric RTL, the MCU firmware for four ISAs, the mesh demos | engineer, operator |
| `prismpath-ebpf/` | the interpreter as XDP and TC programs in the Linux kernel, the loader, receipt sealing, the decision delta demo | engineer, evaluator |
| `adapters/telemetry/` | Facet, the reference: Figueroa quantization, Zeckendorf wire, self heal, epochs, concentrator, receipts, spiral | engineer |
| `prismpath-telemetry-rs/`, `prismpath-preflight/`, `prismpath-reflect-bindings/`, `integrations/vector/`, `integrations/wireshark/` | Facet in Rust, the adoption gate, type bindings, the Vector codec, the dissector | engineer, operator |
| `prismpath-hotswap-rs/` | the signed pack and PolicyHost natively | operator |
| `adapters/fusion/` | one Level M flow joining N decision sources | process owner |
| `adapters/compliance/` | the GRC adjudication adapter: machine checkable controls, evidence typed verdicts, OSCAL | process owner, evaluator |
| `integrations/zarf/`, `integrations/uds/`, `integrations/cpp/` | signed policy delivery, and embedding the C target | engineer |
| `formal/` | the Lean 4 development proving Figueroa quantization within its declared domain | evaluator |
| `prismpath/comparisons/` | the pre registered comparison against OPA, Cedar, Cerbos, OpenFGA, Openlane, and the routing head to head | evaluator |
| `docs/research/` | the papers and the evidence ledger, `supporting-evidence.md`, every claim with its row | evaluator |
| `tools/` | the gates: `arch_guard.py` (boundary), `ledger_lint.py`, `arith_lint.py`, `docs_health.py`, `export_clean.py` (the public mirror) | engineer |

## 4. Conformance topology: the same idea, implemented many times, kept in agreement

Every row below is one concept with more than one implementation. The reference is the one the
corpus is generated from; the rest earn their place by passing that corpus. The last column says what
runs on every push.

### The Level M table interpreter

| implementation | where | judged by | in CI |
|---|---|---|---|
| Python engine (reference of record, `SPEC.md`) | `prismpath/engine.py`, `predicates.py` | generates `prismpath/portable/conformance/` | yes |
| JS kernel | `prismpath/portable/prismpath.mjs` | `run_vectors.mjs` | yes |
| Rust kernel | `prismpath-rs/` | `src/bin/conformance.rs`, 1079/1079 predicates, 27/27 flows | yes |
| Go kernel | `prismpath-go/` | `conformance_test.go` | no |
| C target (the reference for the `.ppt` execution semantics the substrates follow) | `prismpath-hw/interp.c` | `prismpath-hw/run_vectors.py`, `make cert` | yes |
| fabric RTL | `prismpath-hw/rtl/ppt_interp.sv` | cocotb gate `prismpath-hw/tb/`, then silicon certification, ledger rows #73 onward | yes (simulation) |
| eBPF/XDP | `prismpath-ebpf/*.bpf.c` | `cert_corpus.py` and the loader's certify, 124/124 in kernel | yes |
| MCU firmware, four ISAs | `prismpath-hw/avr/`, `rp2350/`, `esp/` | `certify_uno.py`, `certify_rp2350.py`, `certify_esp32.py`, board attached | no (hardware) |

Two references, deliberately: the Python engine is the reference for the flow language, and the C
target is the reference for the compiled image's execution, because the substrates are ports of
`interp.c` against `TABLE_FORMAT.md`. The frozen corpus is what both are judged by.

### Facet: quantizer, wire, spiral

| implementation | where | judged by | in CI |
|---|---|---|---|
| Python (reference of record, `PROTOCOL.md`) | `adapters/telemetry/` | generates `adapters/telemetry/conformance/` | yes |
| Rust | `prismpath-telemetry-rs/` | parity tests against the same corpora, bit for bit wire | yes |
| Lean model | `formal/FQ/` | proofs plus 623 evaluated bridge checks against the corpora | no (local gate) |
| C and RTL Zeckendorf codec | `prismpath-hw/codec-bench/`, `rtl/zeck_*.sv` | codec bench testbenches, silicon round trips, ledger row #118 | yes (simulation) |
| the Rust value model difference | `prismpath-preflight/` | documented: a non numeric string on a numeric field is 0 in Rust and an error in Python, surfaced as a finding | yes |

### Signed packs and the PolicyHost

| implementation | where | judged by | in CI |
|---|---|---|---|
| Python (reference) | `prismpath/policy_pack.py`, `policy_host.py` | `prismpath/portable/conformance/hotswap.json`, `crypto_agility.json`, `crypto_migration.json` | yes |
| Rust | `prismpath-hotswap-rs/` | a pack signed on either runtime verifies on the other | no |
| MCU | `prismpath-hw/mesh/` (monocypher) | the mesh recertification and the field walk, rows #136 | no (hardware) |
| kernel receipt sealing | `prismpath-ebpf/seal_receipts.c` | the unified trail rows #132 to #135 | yes |

### The cause code registry

One registry, `prismpath/causes.py`, spec `docs/design/spec-cause-codes.md`. The byte is emitted by
the Python engine (routing band), the pack verifier (authority and envelope bands), the fabric's
CAUSE register (row #129), the receipt stream on the wire (row #130), and the kernel loader on a hot
swap migration (row #131). The registry is append only and its hash rides the receipts.

## 5. How a change moves through the four people

1. The process owner edits the flow and runs `validate` and `test`; the change is a diff in a
   Markdown file with fixtures beside it.
2. The engineer's interface does not change unless a field did: `contract` says so, `capability` says
   which targets the flow still reaches, `compile` and the pack and envelope carry the signed image.
3. The operator swaps the pack in; the PolicyHost verifies the signature, the envelope, and the
   version floor, flips atomically, and writes one audit event either way. A short lived change is
   written as policy semantics with an `on timeout` edge back to the baseline rather than as pack
   expiry; the pack names the policy of record it overrides (`--overlay-of`) and `attest` shows it.
   `trail` is the operator's read side of the receipts. See `docs/guides/operator.md`.
4. The evaluator reads the receipts: every decision with its cause, Merkle rooted, anchored to a
   timestamp a third party can verify without trusting the emitter.

## 6. Where to read next

`docs/decoder-ring.md` for every term and an index of every document, module, kernel, and command.
`PROTOCOL.md` for Facet. `SPEC.md` for the flow format and Level M. `prismpath-hw/TABLE_FORMAT.md`
for the image. `docs/design/spec-secure-hotswap.md` for the swap. `docs/research/supporting-evidence.md`
for the row behind any number on this page.
