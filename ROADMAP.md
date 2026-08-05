# PrismPath Project Roadmap & Future Vision

**Last Updated:** August 2026  
**Status:** Active Public Roadmap  

PrismPath is an open-source framework that treats **agent workflows as data**. Our roadmap balances core format stabilization, high-performance edge execution, formal verification, and expanding ecosystem adapters.

---

## 🗺️ Vision & Guiding Principles

1. **The Flow is Data, Not Code**: Process logic remains in readable, diffable, static Markdown files—never hidden inside imperative Python callbacks.
2. **Logic Where Logic Exists, Intent Where It Doesn't**: Free, exact `when` predicates handle logic; models handle semantic judgment only on low-margin doubt.
3. **Safety Through Decidability**: Expand static analysis (`prismpath validate`) toward formal verification and zero-false-positive safety guarantees.
4. **Zero-Dependency Edge Portability**: Pure P0 flows run on lightweight, non-ML kernels (JavaScript, Rust, Go, WebAssembly).

---

## 🎯 Release Milestones

### Phase 1: Core Specification & Multi-Language Kernels (Complete)

- [x] **Spec Version 1 (Draft)**: Normative definition of grammar, edge tiers, sandbox predicates, engine contracts, and portability levels ([`SPEC.md`](SPEC.md)).
- [x] **Frozen Conformance Vectors**: 1,067 predicate cases and 27 engine fixtures checked deterministically across implementations ([`portable/conformance/`](prismpath/portable/conformance/README.md)).
- [x] **JavaScript Portable Kernel**: Dependency-free ES module (`prismpath/portable/prismpath.mjs`) and interactive browser playground ([`portable/playground.html`](prismpath/portable/playground.html)).
- [x] **Reference Rust Kernel (`prismpath-rs`)**: Certified conformant core kernel running natively on ARM64 and x86_64.
- [x] **Go Portable Kernel (`prismpath-go`)**: Lightweight dependency-free Go runtime passing 100% of conformance vectors.

### Phase 2: Static Analysis, Formal Verification & Developer Tooling (Complete)

- [x] **Static Validator (`prismpath validate`)**: Decidable compile-time checks for cycles, deadlocks, unreachable nodes, and shadowed edges.
- [x] **Cross-Flow Type Contracts**: Compile-time checking of `@emits(...)` and `@expect(...)` variables across `@spawn` composition trees.
- [x] **Formal Model Checking (`prismpath verify`)**: Reachability and invariant guarantees (*"State X can never be reached under condition Y"*) via bounded model checking — exact with concrete witnesses over the Level M match-action fragment (per-edge membership now reported), sound over-approximation outside it, UNREACHABLE proven for all bounds.
- [x] **Language Server Protocol (`prismpath lsp`)**: Real-time diagnostics, completion, hover, symbols, and a Mermaid graph request over stdio — stdlib only, for Neovim, JetBrains (LSP4IJ), VS Code, and any LSP editor ([`prismpath/editor/README.md`](prismpath/editor/README.md)).
- [x] **Sub-flow Composition Harness Improvements**: Fan-out debugging + live composition trees (`composer.fanout_tree`) in Mission Control's Flows tab — every child's stop state, gate-aware join progress, nested fan-outs, child_error surfacing.
- [ ] **Deploy-Kernel Test Action**: a sibling GitHub action (`actions/test-<kernel>`) asserting a flow's `.tests.md` fixtures on the exact portable kernel (JS/Rust/Go) a deployment ships — "test what you run". Prerequisite: a general fixture runner per kernel.

### Phase 3: Attestation, Compliance & Enterprise Emitters (Complete)

- [x] **Git Flow-Ledger (`ledger.py`)**: Gate-green proof-commits on dedicated orphan refs (`refs/prismpath/runs/*`).
- [x] **Air-Gap Attestation Suite (`ledger_airgap.py`)**: Provenance manifests, human-override tracking, and OpenTimestamps / RFC-3161 anchoring.
- [x] **NIST SP 800-171 Reference Adapter**: Dual catalog support (Rev 2 & official NIST OSCAL Rev 3) with schema-validated **OSCAL AR/POA&M** and **CycloneDX 1.6** emission.
- [x] **SOC Triage Adapter Refinements**: Production SIEM integrations — a `SIEMSource` ingestion port with Elasticsearch/OpenSearch (env-configured, TLS-verified), Wazuh, and NDJSON file sources (Splunk best-effort) + systemd poller units — and automatic prefilter cache tuning (`prefilter.tune`, a Wilson-bound risk-certified operating point derived from the deployment's own adjudication history).
- [x] **Third-Party Connector SDK**: `BaseConnector` covering all six hexagonal ports (Ingestion, Retrieval, Adjudicator, Action/Sink, Attestation, Deferral) + `PayloadFlattener` schema-flattening middleware + the one-line plugin-registry pattern; the SOC adapter is the migration proof.

### Phase 4: Documentation & Repo-Surface Hardening (Complete)

- [x] **Doc-accuracy pass**: every root + package doc audited (see the per-doc audit trail); dead links, placeholder URLs, path-casing, and rename artifacts fixed; every relative link verified to resolve.
- [x] **Security posture updated for shipped attestation**: SECURITY.md's ledger exclusion is now conditional on anchoring; anchoring/attestation forgery is an in-scope reporting class.
- [x] **De-fusing the game-dev origin**: the roblox gate plugin removed; the sprint control plane genericized end to end (council deliberation stays as a general capability).
- [x] **Brand-residue sweep (mdflow → prismpath)**: including the functional `ledger_ots` ref/trailer mismatch that silently emptied `prismpath ledger anchor`, the seven `research/` scripts, and the compliance tooling paths.
- [x] **Contract relocation**: the app-architecture coder contract lives with the prompt assets (`prismpath/nudges/`), resolved CWD-independently.

### Phase 5: Guard Hardening (Planned)

- [ ] **Roleplay-framing detector (deferral-only)**: a locked prototype layer targeting the
  *framing*, not the intent behind it. The bypass measurement's standing result is that
  fiction-framed intent defeats every configuration — but the framing wrapper itself ("pretend
  you are…", "in a story where…") has a stable semantic signature even when the wrapped intent is
  disguised, because the framing *is* the attack mechanism. Implementation is the existing
  centroid machinery pointed at a roleplay-framing corpus: shrunk prototypes, pinned in the
  lockfile (P1, deterministic, bit-for-bit reproducible), cosine-gated. Two hard constraints:
  it may only trigger **deferral** (human review), never a block — the dominant false-positive
  population is learners legitimately writing story-flavored flows, and the guard grammar has no
  verb for permitting to preserve; and **no claim ships before measurement** — a new stratum in
  the pre-registered protocol ([bypass-measurement](docs/research/bypass-measurement.md)) reporting
  both the detection rate on framed attacks and the benign-collision rate on innocent creative
  framings, published either way. If the benign-collision bound can't be held, the honest,
  publishable result is that it can't.
- [ ] **Low-discrepancy probe generation for the embedder fingerprint**: the lockfile's drift
  fingerprint probes the embedder and checks cosines; probe *selection* is a coverage problem —
  probes should spread evenly over the embedding sphere so drift anywhere gets caught, not
  cluster where random draws happen to land. Swap random probes for a quasi-random low-discrepancy
  sequence (Sobol, or the R_d golden-ratio generalization — the same aperiodic-coverage mathematics
  as Fermat's spiral, lifted to high dimension). Small, self-contained, and strengthens the
  fingerprint's guarantee from "probably notices drift" toward "notices drift anywhere".

---

## 🤝 Community & Contributions

We welcome contributions across all areas!
* **First Contributions**: Add a static lint rule or expand test fixture tables in [`gallery/`](prismpath/gallery/README.md).
* **Adapters**: Build a domain adapter following the 6 Hexagonal Ports (**Ingestion, Retrieval, Adjudicator, Action/Sink, Attestation, Deferral**).
* **Governance**: Submit an RFC issue for proposed extensions to annotations or predicate grammar.

For details on contributing, read [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
