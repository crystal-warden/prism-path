# PrismPath Engineering Kanban Board

Based on our architectural rebuttals and technical solutions, here are the concrete, actionable tasks that need to be added to our backlog/Kanban board.

---

## 🚀 Epic: Developer Experience & Connector Ecosystem

### Task 1: Design and Implement the PrismPath Connector SDK
*   **Priority**: High
*   **Description**: Create a Python SDK that abstracts the hexagonal port layout (`Ingestion`, `Action/Sink`, `Retrieval`, etc.) behind a clean, subclassable developer API. Developers should be able to create a connector by inheriting from a base class and implementing simple execution methods, without needing to manually hook into the core engine architecture.
*   **Acceptance Criteria**:
    * [x] Shipped a `BaseConnector` class that automatically registers with the `prismpath.plugins` registry.
    * [x] Abstracted standard schema validation and error-boundary logic into the base class.
    * [x] Created a template repository/generator (e.g., `prismpath-connector template`) for new connectors.

### Task 2: Implement Nested-to-Flat Payload Translation Middleware
*   **Priority**: High
*   **Description**: Build a reusable middleware utility inside the connector SDK to handle data flattening. This utility will translate nested, complex enterprise API responses (e.g., Jira, ServiceNow) into flat schemas that local LLM guided-decoders can process without OOMing or truncating.
*   **Acceptance Criteria**:
    * [x] Added a declarative mapper tool (e.g., jsonpath-based flattening rules) inside the SDK.
    * [x] Provided pre-configured adapters for common nested data types (dates, list of objects to delimited strings).
    * [x] Verified zero LLM degradation when passing the flattened data to local Gemma models.

---

## 🛡️ Epic: Static Analysis, Safety, and CI

### Task 3: Deepen Type-Contract Enforcement in Static Analysis
*   **Priority**: Medium
*   **Description**: Enhance `prismpath validate` and `contract.py` to perform strict compile-time type-safety checks across flow boundaries. The validator should ensure that variables declared in `@emits` in upstream nodes match the types evaluated by downstream `when` predicates, flagging issues before runtime execution.
*   **Acceptance Criteria**:
    * [x] Static validation flags mismatches (e.g., node emits `status: str` but edge checks `when status > 5`).
    * [x] Extends checks to cross-flow `@spawn` and `@expect` parameters.
    * [x] Shipped as part of the GitHub Action and pre-commit hook validator.

---

## 📊 Epic: Observability & Non-Technical Interface

### Task 4: Interactive Graph Renderer for Mission Control UI
*   **Priority**: Medium
*   **Description**: Build a web-based, interactive process visualizer for the Mission Control dashboard. It should parse the Markdown file and render it as a visual decision flowchart. This will allow non-technical PMs and process owners to review and understand complex flows without having to read raw Markdown or variables.
*   **Acceptance Criteria**:
    * [x] Renders nodes and edges dynamically, color-coded by tier (deterministic, semantic, error, event).
    * [x] Highlights the active path and current node during a live execution walk.
    * [x] Allows clicking on nodes to view their Markdown instructions and emitted variables.

---

## 🔌 Epic: Portability & Edge Deployment

### Task 5: Portability Verification & Verification Tooling
*   **Priority**: Low
*   **Description**: Build CLI tools to help users package and compile locked flows for the P1 and P0 portability tiers. The tool should confirm that all reachable edges compile correctly without ML dependencies and bundle the condition vectors into a single distributable artifact (`flow.lock` + `.mjs` script).
*   **Acceptance Criteria**:
    * [x] Shipped `prismpath compile --tier p1` CLI command.
    * [x] Generates an optimized, single-file bundle ready for edge environment deployments (Node/Browser).
    * [x] Includes vector compression for embedded locks to minimize bundle sizes.

---

## 📊 Task: Adversarial agentic benchmark (testbed #3 for the win/lose comparison)
*   **Priority**: Medium (positioning / sales credibility)
*   **Context**: The Journeyman kernel comparison (2026-08-01) showed PrismPath's WINS on
    deterministic routing + portability + certified locked routing + dual-cert. A credible comparison
    must also show where PrismPath LOSES. Journeyman is a biased testbed (plays to PrismPath's niche);
    `routing_bench` covers the neutral routing-accuracy axis. The missing piece is an ADVERSARIAL
    testbed on the axis PrismPath is designed to lose.
*   **Description**: A small benchmark of agentic tasks — tool-use, multi-step reasoning, dynamic
    branching — scoring PrismPath vs LangGraph vs CrewAI where PrismPath is EXPECTED to lose (it is a
    constrained routing kernel, not an agent framework), plus a state-machine-richness scenario where
    it loses to XState. langgraph/crewai are installed in `.venv`; the gemma endpoint is up.
*   **Acceptance**: a scored table (task-completion / expressiveness) published alongside the wins, so
    the comparison leads with the loss and is therefore believed. See `DIRECTION.md` (3-testbed methodology).
