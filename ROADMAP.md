# PrismPath Project Roadmap & Future Vision

**Last Updated:** August 2026  
**Status:** Active Public Roadmap  

PrismPath is an open-source framework that treats **agent workflows as data**. Our roadmap balances core format stabilization, high-performance edge execution, formal verification, and expanding ecosystem adapters.

---

## 🗺️ Vision & Guiding Principles

1. **The Flow is Data, Not Code**: Process logic remains in readable, diffable, static Markdown files—never hidden inside imperative Python callbacks.
2. **Logic Where Logic Exists, Intent Where It Doesn't**: Free, exact `when` predicates handle logic; models handle semantic judgment only on low-margin doubt.
3. **Safety Through Decidability**: Expand static analysis (`prismpath validate`) toward formal verification and zero-false-positive safety guarantees.
4. **Zero-Dependency Edge Portability**: Pure P0 flows compile to lightweight, non-ML targets (JavaScript, WebAssembly, Rust).

---

## 🎯 Release Milestones

### Phase 1: Core Specification & Multi-Language Kernels (Current)

- [x] **Spec Version 1 (Draft)**: Normative definition of grammar, edge tiers, sandbox predicates, engine contracts, and portability levels ([`SPEC.md`](SPEC.md)).
- [x] **Frozen Conformance Vectors**: 1,067 predicate cases and 27 engine fixtures checked deterministically across implementations ([`portable/conformance/`](prismpath/portable/conformance/README.md)).
- [x] **JavaScript Portable Kernel**: Dependency-free ES module (`portable/prismpath.mjs`) and interactive browser playground ([`portable/playground.html`](prismpath/portable/playground.html)).
- [x] **Reference Rust Kernel (`prismpath-rs`)**: Certified conformant core kernel running natively on ARM64 and x86_64.
- [x] **Go Portable Kernel (`prismpath-go`)**: Lightweight dependency-free Go runtime passing 100% of conformance vectors.

### Phase 2: Static Analysis, Formal Verification & Developer Tooling

- [x] **Static Validator (`prismpath validate`)**: Decidable compile-time checks for cycles, deadlocks, unreachable nodes, and shadowed edges.
- [x] **Cross-Flow Type Contracts**: Compile-time checking of `@emits(...)` and `@expect(...)` variables across `@spawn` composition trees.
- [ ] **Formal Model Checking**: Verify reachability and invariant guarantees (*"State X can never be reached under condition Y"*) using bounded model checking over Level M match-action fragments.
- [ ] **Language Server Protocol (LSP)**: Real-time diagnostics, autocompletion, and graph previews for VS Code, Neovim, and JetBrains IDEs.
- [ ] **Sub-flow Composition Harness Improvements**: Enhanced fan-out debugging and live state visualization in Mission Control.

### Phase 3: Attestation, Compliance & Enterprise Emitters

- [x] **Git Flow-Ledger (`ledger.py`)**: Gate-green proof-commits on dedicated orphan refs (`refs/prismpath/runs/*`).
- [x] **Air-Gap Attestation Suite (`ledger_airgap.py`)**: Provenance manifests, human-override tracking, and OpenTimestamps / RFC-3161 anchoring.
- [x] **NIST SP 800-171 Reference Adapter**: Dual catalog support (Rev 2 & official NIST OSCAL Rev 3) with schema-validated **OSCAL AR/POA&M** and **CycloneDX 1.6** emission.
- [ ] **SOC Triage Adapter Refinements**: Production SIEM integrations and automatic prefilter cache tuning.
- [ ] **Third-Party Connector SDK**: Streamlined base classes and schema-flattening middleware for enterprise connectors.

---

## 🤝 Community & Contributions

We welcome contributions across all areas!
* **First Contributions**: Add a static lint rule or expand test fixture tables in [`gallery/`](prismpath/gallery/README.md).
* **Adapters**: Build a domain adapter following the 6 Hexagonal Ports (**Ingestion, Retrieval, Adjudicator, Action/Sink, Attestation, Deferral**).
* **Governance**: Submit an RFC issue for proposed extensions to annotations or predicate grammar.

For details on contributing, read [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
