# Integrating Frontier AI Agents & LLMs with PrismPath

**Document Location:** `docs/guides/frontier-agent-integration.md`  
**Target Audience:** AI Architects, Platform Engineers, and Workflow Developers  

---

## Executive Summary

PrismPath is designed around a clean separation of concerns: **the control flow is a declarative Markdown document, while node execution is handed to worker agents.**

This architecture pairs the **determinism, auditability, and safety of PrismPath** with the **reasoning, code editing, and problem-solving power of Frontier AI Agents** (e.g., Claude Code, OpenAI o1/o3, Gemini CLI, Ollama, Aider, or custom REST/CLI agents).

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     PrismPath (Declarative Supervisor)                   │
│  • Reads Markdown SOPs   • Static analysis (validate)  • Flow-Ledger    │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
          Node Instruction (prose)   │   Structured Outcome (JSON)
          + State Context            ▼   {"status": "success", "text": "..."}
┌────────────────────────────────────┴────────────────────────────────────┐
│                    Frontier AI Agent / Worker Backend                    │
│  • Any CLI, API, or LLM   • Code editing   • Complex reasoning          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 1. The Architectural Division: Supervisor vs. Worker

| Domain | Handled By | Why This Split Matters |
| :--- | :--- | :--- |
| **Control Flow & Routing** | **PrismPath (Kernel)** | 100% deterministic, statically checkable (`prismpath validate`), $0 cost for `when` logic, bit-reproducible routing. |
| **Node Execution & Reasoning** | **Frontier Agent (Worker)** | Unconstrained problem solving, multi-file code editing, complex RAG adjudication, natural-language generation. |
| **Safety & Audit** | **Flow-Ledger (PrismPath)** | Cryptographic Merkle logs record every routing decision, worker outcome, and human override. |

---

## 2. Five Core Integration Patterns

### Pattern A: Any CLI as a Worker (`prismpath.cli_worker`)

The most decoupled worker pattern uses processes. PrismPath’s [`cli_worker.py`](../../prismpath/cli_worker.py) can invoke **any command-line program** as a worker — an AI-agent CLI, or your own Go/Rust/JS/Python project — passing node instructions on `stdin` and parsing JSON/stdout. For a runnable, four-language walkthrough of wiring in your own program, see [Run any program as a worker](workers.md).

```python
from prismpath.parser import parse_file
from prismpath.engine import run
from prismpath.cli_worker import cli_agent

# Use any CLI agent backend (Claude Code, Gemini CLI, Aider, custom scripts)
agent = cli_agent(["claude", "-p"])

# Run the flow—the CLI handles node execution, PrismPath handles routing
res = run(parse_file("workflow.md"), agent)
```

* **Outcome Contract**: If the CLI prints JSON (`{"text": "...", "tests_pass": true}`), PrismPath exposes those fields directly to safe `when` AST predicates (`-> done: when tests_pass`).
* **Error-Tier Recovery**: If a CLI agent exits non-zero or times out, PrismPath catches it on the `on error` tier (`-> retry: on error when error_count < 3`), providing a deterministic retry budget managed by edges rather than custom code wrappers.

---

### Pattern B: API & Local LLM Backends

For REST APIs or local inference servers (vLLM, LM Studio, Ollama, OpenAI-compatible endpoints):

```python
from prismpath.parser import parse_file
from prismpath.engine import run

def api_agent(node_name: str, instruction: str, state: dict) -> dict:
    # Query any HTTP endpoint or local LLM server
    response = call_llm_api(model="gpt-4o", prompt=instruction, context=state)
    return {"text": response.text, "category": response.category}

res = run(parse_file("support_triage.md"), api_agent)
```

---

### Pattern C: Frontier Auto-Unblock in Build Loops (`run_sprint.py`)

In automated build or CI/CD loops, workflows can use a two-tier agent strategy:
1. **Tier 1 (Fast/Local Worker)**: A small, fast local model or script attempts routine code generation against strict build/test gates.
2. **Tier 2 (Frontier Agent Escalation)**: If Tier 1 fails N times with the same error, PrismPath’s control plane escalates to a **Frontier Agent**:
   - PrismPath packages the full error context, file diffs, and execution logs.
   - The Frontier Agent receives the context, diagnoses the root cause, applies the complex fix, and hands execution back to PrismPath to re-run the gate.

---

### Pattern D: Sub-Flow Parallel Swarms (`@spawn`)

For large-scale tasks (e.g., auditing 100 compliance controls or reviewing 50 pull request files in parallel):

```markdown
## fanout_review
Process each changed file in parallel.
@spawn(child="review_one.md", over="pr_files", join="all_done")
-> summarize: on event all_done
```

1. PrismPath parses `@spawn` and initializes 50 parallel durable child runs.
2. Each child run invokes a worker agent instance to process a single item independently.
3. Once all worker instances complete, PrismPath delivers the `all_done` event and advances the parent flow.

---

### Pattern E: Human-in-the-Loop (HITL) Suspension & Co-Pilots

When a workflow reaches a high-risk policy threshold (`-> manager_approval: when amount > 50000`) or low-confidence ambiguity:
1. PrismPath suspends execution as `needs_human` and generates an evidence packet ([`checkpoint.py`](../../prismpath/checkpoint.py)).
2. An agent or chat UI consumes the evidence packet and presents a structured review interface to a human operator.
3. Once the human provides sign-off, the application resumes execution via `resume --choose <target>`, recording a tamper-evident audit log in the **Flow-Ledger** ([`ledger.py`](../../prismpath/ledger.py)).

---

## 3. Benefits of the Dual Architecture

| Single-Agent System (No PrismPath) | PrismPath + Frontier Agent |
| :--- | :--- |
| Agent might drift outside process bounds or hallucinate unapproved steps. | **PrismPath static analyzer (`validate`)** guarantees topology and type safety before execution. |
| Token costs scale rapidly as the agent re-evaluates routine routing decisions. | **Deterministic `when` predicates** handle routine routing for $0 in <1ms; model budget is spent only on node execution. |
| Hard to audit why an agent took a specific branch in production. | **Git Flow-Ledger** records an unalterable, tamper-evident Merkle proof of every decision and human override. |

---

## Related Documentation

* [`SPEC.md`](../../SPEC.md) — Normative format specification (grammar, edge tiers, predicate language).
* [`docs/guides/authoring.md`](authoring.md) — Complete guide to authoring Markdown flows.
* [`docs/design/architecture.md`](../design/architecture.md) — Engine architecture, control plane, and plugin seams.
