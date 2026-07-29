# PrismPath Technical Summary

## 1. The Engine

**What is PrismPath and its core capabilities?**
PrismPath is an agent workflow framework that treats control flow as declarative data rather than imperative code. A workflow is defined entirely within a single Markdown document, where headings (`##`) represent nodes and bulleted list items (`-> target: condition`) represent edges. This allows the process graph to be read, diffed, linted, tested, locked, and proven without executing arbitrary Python routing callbacks. 

Core capabilities include:
*   **The Routing Spectrum**: Nodes are evaluated using deterministic edges (safe predicates matching against structured outputs) first. If no deterministic edge matches, it falls back to semantic edges (natural language conditions), which are routed using an embedding similarity check and optionally escalated to a 1-shot LLM (Hybrid Routing) only on low confidence.
*   **Static Analysis**: Workflows are statically validated (`prismpath validate` / `prismpath lint`) before execution to catch undefined targets, unsafe predicates, unbounded cycles, and unreachable terminals.
*   **Durable Execution & State**: Runs can be checkpointed and resumed, supporting timeouts, event-driven resumption, and human-in-the-loop (HITL) suspension (`needs_human`). State growth is deterministically bounded using `@state_bound`.
*   **Reproducible Routing**: The `prismpath lock` command generates a lockfile containing the condition embeddings, making semantic routing bit-reproducible across machines.
*   **Sub-flow Composition**: Fan-out capabilities (`@spawn`) allow spawning parallel durable child runs with join policies (e.g., `all_done`, `quorum`).
*   **Portable Subset**: Flows with only decidable edges (P0 tier) can run in a dependency-free JavaScript kernel (`portable/prismpath.mjs`) in a browser or edge appliance without an ML runtime.

**Who is it for?**
*   **Platform/SRE Teams**: Looking for bit-reproducible routing, static analysis, and native observability (OTel spans).
*   **Security & Compliance Auditors**: Requiring tamper-evident proofs, ledger-backed decisions, and human-gated containment.
*   **Process Owners / PMs**: Domain experts who want to author and manage the workflows visually (via Markdown and Mermaid diagrams) without writing Python.
*   **Researchers**: Evaluating routing efficiency, hybrid thresholds, and framework specifications.

**Creative ways to apply its capabilities:**
*   **Edge IoT Content Moderation**: Deploying the P0 (portable) subset to edge network appliances where simple deterministic rules handle 99% of traffic locally, and edge cases are emitted to a central server.
*   **Automated PR Architecture Reviews**: Using fan-out (`@spawn`) to parallelize code-review tasks per file. Deterministic edges immediately reject CI failures, while semantic edges judge code for "architectural alignment," pausing via `needs_human` if the model confidence is low.
*   **Customer Support Triage**: A prefilter cache could memorize solutions to recurring tickets, saving LLM costs. Semantic routing could identify "angry" customer sentiment and route them to retention specialists, while routine questions hit automated sub-flows.

---

## 2. Capabilities Developed

The framework is decoupled into a domain-agnostic core (the "onion center") and domain-specific adapters that interface via six strict ports (Ingestion, Retrieval, Adjudicator, Action/Sink, Attestation, and Deferral). 

**Domain Adapters:**
*   **SOC Adapter (Blue-Team Triage)**:
    *   *Ingestion*: Pulls Wazuh alerts (SIEM).
    *   *Retrieval*: Uses detection knowledge and a prefilter corpus.
    *   *Routing*: Routes by MITRE ATT&CK tactics.
    *   *Adjudicator*: Issues a verdict of `contain`, `watch`, or `ignore`. Uses a `PrefilterCache` to auto-resolve ~59% of repetitive alerts without an LLM call.
    *   *Sink*: Outputs the finding and stages containment (human-gated).
*   **Compliance Adapter (NIST SP 800-171)**:
    *   *Ingestion*: Takes a control assessment request (control ID + evidence bundle).
    *   *Retrieval*: Dual catalog support (NIST 800-171 Rev 2 and Rev 3, runtime-selectable). Includes a Translation layer that converts unmet objectives into missing-evidence requests.
    *   *Routing*: Routes family-agnostically by assessment-method profile (technical, procedural, operational). 
    *   *Adjudicator*: Determines status as `met`, `partially-met`, or `not-met`. Implements an escalation-default prior ("a control is NOT MET unless the evidence positively demonstrates each objective").
    *   *Sink*: Emits a partial SPRS system-level rollup score and standardized compliance artifacts.

**Standards Emitted:**
The Compliance Sink natively emits dual standards bound with cryptographic provenance:
*   **OSCAL 1.1.3 (NIST-native)**: Assessment Results (AR) and Plan of Action & Milestones (POA&M).
*   **CycloneDX 1.6 Attestations**: OWASP supply-chain format with conformance mapping.

**Cross-Cutting Framework Capabilities:**
*   **Attestation & Proofs**: Uses the git Flow-Ledger to write gate-green proof commits (`SPRINT_LEDGER=1`). Employs a tamper-evident air-gapped attestation tier (`ledger_airgap.provenance_manifest`) anchored via OpenTimestamps and RFC-3161. Overrides are handled via superseding commits to retain the original AI decision.
*   **Testing Methodology**: Robust multi-layered testing standard including deterministic matrices, negative validation, adversarial attestation-tampering, property-based hypothesis testing, opt-in live model testing, and held-out efficacy testing (using an independent model for blind evaluations).

---

## 3. Gaps & Limitations

Based on the documentation, the following limitations and caveats stand out:

*   **Flat Adjudication Schemas Required**: The LLM local adjudicator (gemma) destabilizes and truncates output when tasked with nested object arrays. Consequently, determination schemas must be kept rigidly flat (e.g., enums + array of strings).
*   **Cost of Semantic Routing**: Semantic routing always incurs the cost of at least an embedding generation. PrismPath is not suitable if sub-millisecond routing over semantic conditions is required globally.
*   **Linear Pipelines**: The framework adds overhead for linear pipelines with no branching; it is explicitly not designed to replace simple sequential scripts.
*   **State Growth**: Long-lived runs will accumulate state indefinitely unless explicitly bounded by the author using the `@state_bound(transcript=N)` annotation.
*   **Prefilter Applicability**: The `PrefilterCache` is highly situational. It only yields benefits if one node heavily dominates costs, inputs genuinely recur, and the required context is entirely contained within the embedded document.
*   **Community Data Caveat**: The NIST 800-171 Rev 2 catalog provided is a community transcription, as NIST retired the official machine-readable data. Users must manually verify it against official DoD PDFs before actual assessment use.
*   **Not a Hosted Platform**: PrismPath explicitly positions itself as a format and kernel, omitting any SaaS infrastructure or exhaustive connector catalogs, leaving integration heavy-lifting to the users.
