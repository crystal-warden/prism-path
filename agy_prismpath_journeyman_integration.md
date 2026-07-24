# PrismPath & Journeyman: Declarative Compliance and Edge Orchestration

**Author**: Frontier AI Agent (agy)  
**Date**: July 24, 2026  
**Target File**: `agy_prismpath_journeyman_integration.md`

This paper reviews **PrismPath** and **Journeyman**, analyzing their architecture, target use cases, and technical synergy. It details how the Journeyman device-adaptive tutor project integrates the PrismPath declarative capability manifest, evaluates the strengths of this design, identifies architectural gaps where PrismPath requires support, and highlights portions of the framework that remain unutilized in Journeyman.

---

## 1. Project Definitions & Use Cases

### PrismPath: Declarative Agent Workflow Framework

**PrismPath** is a framework that models agent execution and control flow as declarative data (Markdown files) rather than imperative code. Nodes represent execution steps (labeled headings), and edges represent transitions defined by deterministic predicates (safe conditions) or semantic routes (natural language similarity check with LLM fallback).

- **Primary Use Case**: Orchestrating complex multi-agent pipelines (such as automated Blue-Team SOC alert triage or compliance auditing) requiring audit trails, cryptographic attestation (OSCAL/CycloneDX), dynamic fallback routing, and static analysis (cycle/unreachable detection).
- **Deployment Vector**: Runs on a Python-native core or compiles down into a lightweight, dependency-free JavaScript kernel (`portable/prismpath.mjs`) utilizing quantized float16 similarity vectors for edge and browser environments.

### Journeyman: Local-First AI Learning Environment

**Journeyman** is a local-first, device-adaptive IDE and AI learning environment. It features a VSCode-style four-panel workspace: an eReader book panel, a guided path checklist, a custom Rust IDE with static compile check utilities, a sandboxed interactive terminal, and a local AI mentor chat.

- **Primary Use Case**: Providing a secure, offline learning environment for programming languages (such as Rust) on highly constrained devices (with a "floor tier" target of 8 GB RAM, no GPU, and low-spec CPUs).
- **Deployment Vector**: Packaged as a native cross-platform Tauri desktop shell wrapping a Rust-native backend and a local `llama-server` sidecar, accompanied by a Vite + React frontend webview.

---

## 2. How Journeyman Utilizes PrismPath

Journeyman incorporates the core mental models and assets of PrismPath to govern its adaptive rendering, guided instruction, and deterministic compliance:

### A. The Knowledge-Graph Capability Manifest

Journeyman's engine (`tutor_engine.py` / `capability_resolver.py`) uses a declarative schema derived from PrismPath's hexagonal ports. The [capability_manifest.yaml](file:///home/cwadmin/cwprojects/journeyman/manifest/capability_manifest.yaml) defines hardware requirements as nodes and links them to capabilities (features) and obligations (always-on compliance conditions) via typed edges:

- **Capabilities**: Unlocked adaptively by probing the system's VRAM, RAM, and CPU core counts (e.g., `book_reader`, `terminal`, `ide_syntax` are active on the 8 GB floor, while `fim_autocomplete` and `agentic_mentor` are locked).
- **Obligations**: Remain active globally independent of hardware specifications, enforcing AI-disclosure chips, GDPR/CCPA data purges, WCAG 2.2 AA accessibility structures, and safety filters.

### B. The Guided Path Curriculum

The **Guided Path** curriculum operates as a linear, deterministic state walk modeled on the PrismPath P0 execution spec. The step-by-step progress checklist (e.g., compile code, check diagnostic, run test) corresponds to transition predicates evaluated locally in the webview, checking off goals based on terminal standard out events (such as tracking when a user types `cargo run` or successfully builds a file).

### C. Grounded RAG & Safety Prefilters (Hexagonal Ports)

The Chat Mentor integrates the PrismPath dual-sided safety filter paradigm:

1.  **Ingestion & Retrieval Ports**: The user's query is analyzed via keyword-scoring against chapter content. If the RAG toggle is active, relevant snippets are retrieved and injected as context in the system prompt.
2.  **Deterministic Prefilter (P0 Guardrail)**: User input is audited against `PROHIBITED_WORDS` before contacting the LLM. If blocked, a static safety refusal is returned without querying the sidecar.
3.  **Adjudication & Sink Ports**: The LLM sidecar generates the response, which is scanned for blocklisted words prior to rendering.

---

## 3. Strengths of PrismPath in this Use Case

- **Offline Portability on Constrained Hardware**: PrismPath’s focus on light, local executions matches the Journeyman floor tier. By compiling flows to JavaScript and utilizing quantized float16 similarity vector lookups, the client runs without a Python or ML dependency, preserving memory space on budget 8 GB RAM laptops.
- **Deterministic Safety Guarantees**: Journeyman must guarantee safety filters run at tier P0 (independent of model intelligence) because weak local models are highly prone to jailbreaks. PrismPath's hybrid routing model (deterministic predicates checked before semantic fallbacks) guarantees that safety filters cannot be bypassed by model hallucinations.
- **Static Auditability and Compliance**: The strict regulatory obligations of Journeyman (such as the EU AI Act, California SB 942, and Texas HB 149) require traceable logs. PrismPath's ledger-backed Flow-Ledger commits and native OSCAL/CycloneDX attestation outputs provide automated compliance logging.

---

## 4. Gaps & Areas Where PrismPath Falls Short

- **Lack of Native Rust/Tauri Runtime**: Journeyman is built as a compiled Rust application via Tauri for native execution. PrismPath's core is Python-based, and its portable compiler only outputs JavaScript. To interpret the capability manifest and guided path on the native Rust side, Journeyman must duplicate resolver logic in Rust or delegate it to the frontend JS webview. A native `prismpath-rs` interpreter would bridge this gap.
- **No Native Device Telemetry Hooks**: PrismPath requires input payloads to be fed into its hexagonal Ingestion ports. It lacks native hooks to query system resources (RAM, VRAM, GPU cores). To resolve the manifest, Journeyman has to write custom Python/Rust system-probing telemetry code to populate the resolver inputs.
- **State Modelling for Fast Interactive Loops**: PrismPath is designed for step-by-step agent transitions (nodes with clear inputs/outputs). It is ill-suited to model high-frequency interactive events, such as tracking character changes in the IDE editor, caret line-and-column positions, or mouse resizing drag events, which require custom React event hooks.

---

## 5. Unutilized Portions of PrismPath in Journeyman

- **Parallel Spawn and Join Policies (`@spawn`)**: Journeyman's guided path is a single-user, sequential walk. It does not use PrismPath's parallel child execution capabilities, join policies (`all_done`, `quorum`), or fan-out capabilities.
- **Semantic LLM-based Routing Fallbacks**: The floor tier disables LLM-based routing classification due to CPU latency and resource constraints. It relies solely on P0 deterministic routes (lesson completion checkboxes and basic keyword matches), leaving the framework's semantic embedding similarity classifiers unused.
- **Prefilter Adjudication Cache**: Since user queries in a tutoring session are highly variable, exploratory, and context-dependent, the `PrefilterCache` (which caches exact semantic hits to avoid LLM calls) is disabled, routing all safe chats directly to the `llama-server`.
