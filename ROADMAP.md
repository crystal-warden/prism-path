# PrismPath Project Roadmap & Future Vision

**Last Updated:** August 2026  
**Status:** Active Public Roadmap  

PrismPath is an open-source framework that treats **agent workflows as data**. Our roadmap balances core format stabilization, high-performance edge execution, formal verification, and expanding ecosystem adapters.

---

## 🗺️ Vision & Guiding Principles

1. **The Flow is Data, Not Code**: Process logic remains in readable, diffable, static Markdown files; never hidden inside imperative Python callbacks.
2. **Logic Where Logic Exists, Intent Where It Doesn't**: Free, exact `when` predicates handle logic; models handle semantic judgment only on low-margin doubt.
3. **Safety Through Decidability**: Expand static analysis (`prismpath validate`) toward formal verification and zero-false-positive safety guarantees.
4. **Zero-Dependency Edge Portability**: Pure P0 flows run on lightweight, non-ML kernels (JavaScript, Rust, Go, WebAssembly); and the Level M fragment is deliberately shaped to go further, down to devices where no framework runtime exists at all; the shape has now been demonstrated all the way down to an FPGA (Phase 6, first target).

---

## 🎯 Release Milestones

### Phase 1: Core Specification & Multi-Language Kernels (Complete)

- [x] **Spec Version 1 (Draft)**: Normative definition of grammar, edge tiers, sandbox predicates, engine contracts, and portability levels ([`SPEC.md`](SPEC.md)).
- [x] **Frozen Conformance Vectors**: 1,079 predicate cases and 27 engine fixtures checked deterministically across implementations ([`portable/conformance/`](prismpath/portable/conformance/README.md)).
- [x] **JavaScript Portable Kernel**: Dependency-free ES module (`prismpath/portable/prismpath.mjs`) and interactive browser playground ([`portable/playground.html`](prismpath/portable/playground.html)).
- [x] **Reference Rust Kernel (`prismpath-rs`)**: Certified conformant core kernel running natively on ARM64 and x86_64.
- [x] **Go Portable Kernel (`prismpath-go`)**: Lightweight dependency-free Go runtime passing 100% of conformance vectors.

### Phase 2: Static Analysis, Formal Verification & Developer Tooling (Complete)

- [x] **Static Validator (`prismpath validate`)**: Decidable compile-time checks for cycles, deadlocks, unreachable nodes, and shadowed edges.
- [x] **Cross-Flow Type Contracts**: Compile-time checking of `@emits(...)` and `@expect(...)` variables across `@spawn` composition trees.
- [x] **Formal Model Checking (`prismpath verify`)**: Reachability and invariant guarantees (*"State X can never be reached under condition Y"*) via bounded model checking; exact with concrete witnesses over the Level M match action fragment (per-edge membership now reported), sound over-approximation outside it, UNREACHABLE proven for all bounds.
- [x] **Language Server Protocol (`prismpath lsp`)**: Real-time diagnostics, completion, hover, symbols, and a Mermaid graph request over stdio; stdlib only, for Neovim, JetBrains (LSP4IJ), VS Code, and any LSP editor ([`prismpath/editor/README.md`](prismpath/editor/README.md)).
- [x] **Sub-flow Composition Harness Improvements**: Fan-out debugging + live composition trees (`composer.fanout_tree`) in Mission Control's Flows tab; every child's stop state, gate-aware join progress, nested fan-outs, child_error surfacing.
- [ ] **Deploy-Kernel Test Action**: a sibling GitHub action (`actions/test-<kernel>`) asserting a flow's `.tests.md` fixtures on the exact portable kernel (JS/Rust/Go) a deployment ships; "test what you run". Prerequisite: a general fixture runner per kernel.

### Phase 3: Attestation, Compliance & Enterprise Emitters (Complete)

- [x] **Git Flow-Ledger (`ledger.py`)**: Gate-green proof-commits on dedicated orphan refs (`refs/prismpath/runs/*`).
- [x] **Air-Gap Attestation Suite (`ledger_airgap.py`)**: Provenance manifests, human-override tracking, and OpenTimestamps / RFC-3161 anchoring.
- [x] **NIST SP 800-171 Reference Adapter**: Dual catalog support (Rev 2 & official NIST OSCAL Rev 3) with schema-validated **OSCAL AR/POA&M** and **CycloneDX 1.6** emission.
- [x] **SOC Triage Adapter Refinements**: Production SIEM integrations; a `SIEMSource` ingestion port with Elasticsearch/OpenSearch (env-configured, TLS-verified), Wazuh, and NDJSON file sources (Splunk best-effort) + systemd poller units; and automatic prefilter cache tuning (`prefilter.tune`, a Wilson-bound risk-certified operating point derived from the deployment's own adjudication history).
- [x] **Third-Party Connector SDK**: `BaseConnector` covering all six hexagonal ports (Ingestion, Retrieval, Adjudicator, Action/Sink, Attestation, Deferral) + `PayloadFlattener` schema-flattening middleware + the one-line plugin-registry pattern; the SOC adapter is the migration proof.

### Phase 4: Documentation & Repo-Surface Hardening (Complete)

- [x] **Doc-accuracy pass**: every root + package doc audited (see the per-doc audit trail); dead links, placeholder URLs, path-casing, and rename artifacts fixed; every relative link verified to resolve.
- [x] **Security posture updated for shipped attestation**: SECURITY.md's ledger exclusion is now conditional on anchoring; anchoring/attestation forgery is an in-scope reporting class.
- [x] **De-fusing the game-dev origin**: the roblox gate plugin removed; the sprint control plane genericized end to end (the game-flavored council/dice subsystem was later removed entirely).
- [x] **Brand-residue sweep (mdflow → prismpath)**: including the functional `ledger_ots` ref/trailer mismatch that silently emptied `prismpath ledger anchor`, the seven `research/` scripts, and the compliance tooling paths.
- [x] **Contract relocation**: the app-architecture coder contract lives with the prompt assets (`prismpath/nudges/`), resolved CWD-independently.

### Phase 5: Guard Hardening (Planned)

- [ ] **Roleplay-framing detector (deferral-only)**: a locked prototype layer targeting the
  *framing*, not the intent behind it. The bypass measurement's standing result is that
  fiction-framed intent defeats every configuration; but the framing wrapper itself ("pretend
  you are…", "in a story where…") has a stable semantic signature even when the wrapped intent is
  disguised, because the framing *is* the attack mechanism. Implementation is the existing
  centroid machinery pointed at a roleplay-framing corpus: shrunk prototypes, pinned in the
  lockfile (P1, deterministic, bit-for-bit reproducible), cosine-gated. Two hard constraints:
  it may only trigger **deferral** (human review), never a block; the dominant false-positive
  population is learners legitimately writing story-flavored flows, and the guard grammar has no
  verb for permitting to preserve; and **no claim ships before measurement**: a new stratum in
  the pre registered protocol ([bypass-measurement](docs/research/bypass-measurement.md)) reporting
  both the detection rate on framed attacks and the benign-collision rate on innocent creative
  framings, published either way. If the benign-collision bound can't be held, the honest,
  publishable result is that it can't.
- [ ] **Low-discrepancy probe generation for the embedder fingerprint**: the lockfile's drift
  fingerprint probes the embedder and checks cosines; probe *selection* is a coverage problem;
  probes should spread evenly over the embedding sphere so drift anywhere gets caught, not
  cluster where random draws happen to land. Swap random probes for a quasi-random low-discrepancy
  sequence (Sobol, or the R_d golden-ratio generalization; the same aperiodic-coverage mathematics
  as Fermat's spiral, lifted to high dimension). Small, self-contained, and strengthens the
  fingerprint's guarantee from "probably notices drift" toward "notices drift anywhere".

### Phase 6: Edge, Embedded & IoT Compilation (First hardware target delivered; remainder planned)

*Status, honestly: the first target now exists (built, measured, and running on silicon) in
[`prismpath-hw/`](prismpath-hw/README.md), a top-level target directory beside `prismpath-rs/`
and `prismpath-go/`. It was built off to the side and landed here only after clearing the
repo's own gates. What remains unbuilt is listed below, unchecked. The reason this phase was listed before it existed still
holds: the load-bearing design choices were made **for** it, and it is the ground competing
frameworks structurally cannot reach; a Python-runtime orchestrator has no move here at any
price.*

The Level M match action fragment (SPEC §4.3) is not an analysis convenience; it is a
**compilation target**. Each atom is a `(field, operator, constant)` row, ordered deterministic
edges are a priority encoder, `visits`/`error_count` are registers; a Level M flow *is* a
match action table, and tables run where interpreters cannot: microcontrollers, smart sensors,
PLC-adjacent industrial controllers, NICs, in kernel packet paths. The pieces this phase would
build, in rough order of reach:

- [x] **The FPGA target (delivered 2026-08-06/07, [`prismpath-hw/`](prismpath-hw/README.md))**:
  a Level M flow compiles to a binary table image (PPT v1) interpreted by **one fixed circuit**;
  never re-synthesized per flow. Certified on a **declared subset** of the frozen vectors
  (the C target 124/1,079 predicate + 6/27 engine, and the eBPF target 124/124 in kernel on the same subset, re certified 2026-08-12 on aarch64 + x86_64; the RTL 114/1,067, its re-sweep to 124/1,079 pending a hardware retest; zero divergence, every exclusion machine readable; the
  vectors-as-referee pattern, one level down; deliberately *not* claimed as full SPEC §8
  conformance). C target and RTL agree bit-for-bit with the Python reference, including a
  7,436-sample live-sensor replay. On a Zynq-7020: timing clean at 50 MHz, **1,064 LUTs (2.0%
  of the part)**, WCET **100 to 420 ns per routing decision**, and 2,985 live sensor samples routed
  in fabric; `wazuh_triage`, the production SOC flow, is a 302-byte image. Evidence hashes are
  OTS-anchored in the repo. (Ledger rows #72 to #76.)
- [ ] **`prismpath compile --target c-table`**: the in-repo integration step: fold the
  `prismpath-hw/` compiler + C interpreter into this repo's CLI as the reference embedded
  target; no allocator, no OS assumptions. The frozen conformance vectors are the certification
  suite, exactly as they were for the Go kernel: a target is conformant when it passes the
  vectors, not when its author says so.
- [ ] **WASM micro-target**: the same table interpreter compiled to a few-KB WASM module, for edge
  runtimes (Cloudflare Workers, embedded WASM hosts) where even the JS kernel is too much.
- [ ] **In-kernel / in-network targets (exploratory)**: XDP/eBPF and P4 emission for flows that are
  packet- or event-shaped; routing decisions at line rate, authored as Markdown, verified by
  `prismpath verify` before they ever touch a device.
- [ ] **The guard's statutory floor on device**: the safety layer is already P0-deterministic by
  design; compiled alongside a Level M flow it becomes safety enforcement that runs *on the
  sensor*, with no cloud round-trip to fail or intercept; deferral degrades to fail-closed when
  the uplink is down.
- [ ] **Field-provenance story for constrained emitters**: `@emits`/`@field_only` map naturally to
  devices whose workers are ADCs and comparators, not LLMs; the port contract already anticipates
  a hardware target driving it.

What made this credible before it existed was that every prerequisite was already load-bearing
elsewhere: decidability (the model checker), per-edge Level M membership reporting
(`prismpath verify --level-m`), dependency-free kernels as proof the spec re-implements cleanly,
and frozen vectors as the referee. The first leg is now built and measured; the fragment runs
as a 136-byte table in FPGA fabric with a provable 100 to 420 ns decision bound at 2% of a $65-class
part; and the certification pattern worked exactly as this section predicted: the vectors
refereed the hardware the same way they refereed the Go kernel, and the target's first act was
to surface a real classifier bug (ledger row #76). The remaining legs above are unbuilt; the
runway to them just got shorter.

---

## 🤝 Community & Contributions

We welcome contributions across all areas!
* **First Contributions**: Add a static lint rule or expand test fixture tables in [`gallery/`](prismpath/gallery/README.md).
* **Adapters**: Build a domain adapter following the 6 Hexagonal Ports (**Ingestion, Retrieval, Adjudicator, Action/Sink, Attestation, Deferral**).
* **Governance**: Submit an RFC issue for proposed extensions to annotations or predicate grammar.

For details on contributing, read [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
