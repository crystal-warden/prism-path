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

## 2. How Journeyman Relates to PrismPath — blueprint, not yet a runtime dependency

**Honest current status:** Journeyman today runs **no PrismPath code**. `prismpath-rs` is not referenced by Journeyman's Tauri backend, and nothing in the frontend or the `capability_resolver` engine imports PrismPath. What Journeyman uses is PrismPath's **architecture and vocabulary as a blueprint** — the pieces below are standalone implementations built _in the shape of_ PrismPath, not integrations of it. (The one concrete live integration worth building is the tutor mentor as a PrismPath **adapter** — see §4.)

### A. The capability manifest (PrismPath-shaped, standalone)

Journeyman's `capability_resolver.py` reads [capability_manifest.yaml](file:///home/cwadmin/cwprojects/journeyman/manifest/capability_manifest.yaml), a knowledge-graph document modelled on PrismPath's hexagonal thinking — capabilities and always-on compliance obligations as typed nodes/edges, tagged with PrismPath tier labels (P0/P1/P2). It is _inspired by_, but does not execute through, the PrismPath engine.

- **Capabilities**: unlocked by probing VRAM/RAM/CPU (`book_reader`, `terminal`, `ide_syntax` active on the 8 GB floor; `fim_autocomplete`, `agentic_mentor` locked).
- **Obligations**: hardware-independent — AI-disclosure, GDPR/CCPA purge, WCAG 2.2 AA, safety filters.

### B. The Guided Path (P0-_style_, hand-coded)

The Guided Path is a linear deterministic checklist advanced by terminal-stdout events — the _pattern_ of a PrismPath P0 flow (deterministic transitions, no LLM), implemented directly in the React webview rather than run through a PrismPath flow or lockfile.

### C. The dual-sided safety filter (P0-_discipline_, hand-coded)

The Chat Mentor applies a deterministic blocklist to **both** user input (before the LLM call) and model output (before render), following PrismPath's principle that safety gating must be deterministic and independent of model judgement. It is hand-coded in `useMentor.ts` — it does **not** route through PrismPath's ingestion/adjudicator/sink ports.

---

## 3. Strengths of PrismPath in this Use Case

- **Offline Portability on Constrained Hardware**: PrismPath’s focus on light, local executions matches the Journeyman floor tier. By compiling flows to JavaScript and utilizing quantized float16 similarity vector lookups, the client runs without a Python or ML dependency, preserving memory space on budget 8 GB RAM laptops.
- **Deterministic Safety Guarantees**: Journeyman must guarantee safety filters run at tier P0 (independent of model intelligence) because weak local models are highly prone to jailbreaks. PrismPath's hybrid routing model (deterministic predicates checked before semantic fallbacks) guarantees that safety filters cannot be bypassed by model hallucinations.
- **Static Auditability and Compliance**: The strict regulatory obligations of Journeyman (such as the EU AI Act, California SB 942, and Texas HB 149) require traceable logs. PrismPath's ledger-backed Flow-Ledger commits and native OSCAL/CycloneDX attestation outputs provide automated compliance logging.

## 4. Prototyped Support — built, but not yet integrated

These were scaffolded during the sprint. They are **prototypes for a possible future integration, not live capabilities** — none is wired into Journeyman today. Each should be treated as speculative until a concrete need (a real tutor adapter) exists.

- **`prismpath-rs` (native P0 interpreter)**: a competent, dependency-light Rust crate that evaluates P0 flow graphs. _Caveats_: it is a **second** implementation of PrismPath's evaluator (a drift risk against the Python source of truth), its flow schema is **not verified** against PrismPath's actual compiled-flow format, and it is **not referenced by Journeyman's Tauri backend**. Park until a concrete need exists.
- **`SystemTelemetry` connector**: probes CPU/RAM/VRAM. _Caveat_: this **duplicates** the hardware probing `capability_resolver.py` already performs; it targets PrismPath's ingestion port, which Journeyman does not currently use.
- **Zustand high-frequency store (Journeyman)**: isolates resizer/caret/keystroke state from React re-renders — a genuine, working frontend performance optimization. It is **unrelated to PrismPath** and is listed here only because it shipped in the same sprint.

**The integration actually worth building next:** the tutor mentor as a PrismPath **adapter** (`adapters/tutor/`) — a pedagogy-routed, escalation-default adjudicator with attestation and human deferral, conforming to `adapters/ADAPTER_GUIDE.md`. That is the path that makes Journeyman a real PrismPath _consumer_, rather than reimplementing the engine.

---

## 5. Unutilized Portions of PrismPath in Journeyman

- **Parallel Spawn and Join Policies (`@spawn`)**: Journeyman's guided path is a single-user, sequential walk. It does not use PrismPath's parallel child execution capabilities, join policies (`all_done`, `quorum`), or fan-out capabilities.
- **Semantic LLM-based Routing Fallbacks**: The floor tier disables LLM-based routing classification due to CPU latency and resource constraints. It relies solely on P0 deterministic routes (lesson completion checkboxes and basic keyword matches), leaving the framework's semantic embedding similarity classifiers unused.
- **Prefilter Adjudication Cache**: Since user queries in a tutoring session are highly variable, exploratory, and context-dependent, the `PrefilterCache` (which caches exact semantic hits to avoid LLM calls) is disabled, routing all safe chats directly to the `llama-server`.
