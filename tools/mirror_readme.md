# PrismPath

[![PyPI](https://img.shields.io/pypi/v/prismpath.svg)](https://pypi.org/project/prismpath/)
&nbsp;[![license: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/crystal-warden/prismpath/blob/main/LICENSE)

**Control flow as data, not code.** Deterministic, diffable AI agent workflows written entirely in
Markdown. One file is the graph: each `## heading` is a step, each `-> target: condition` an edge. A
routing spectrum decides every transition at the cheapest tier that can, so you pay for a model only
where meaning genuinely requires one.

- 📄 **Markdown is the graph:** no Python DAG boilerplate. A routing change is a prose diff.
- ⚡ **A spectrum, not one LLM call:** a free `when` predicate, then embeddings, then an LLM only on
  doubt, plus `on error` and `on event` fences.
- 🔒 **Provable, not hopeful:** `prismpath validate` compiles the flow and checks reachability with no
  model; a per flow lockfile pins semantic routing bit for bit; the same signed table runs everywhere.

## The whole idea in one file

```markdown
---
name: support_triage
start: classify
---

## classify
Read the ticket. Emit `category`, `amount`, and `sentiment`.
-> human_review: when category == "billing_dispute" and amount > 500
-> billing: when category in ("billing", "billing_dispute")
-> outage: when category == "outage"
-> retention: when sentiment == "angry"
-> general: else

## human_review
A person decides. High value billing disputes are never auto routed.

## billing
The standard billing queue.

## outage
Page the on-call engineer.

## retention
Route to a retention specialist.

## general
The general support queue.
```

`-> t: when <expr>` is a free deterministic edge (first true wins, in document order); a bare
`-> t: <natural language>` escalates to embeddings, then to a one shot LLM only on doubt; `else` is the
fallthrough.

## Quickstart

```bash
pip install prismpath
prismpath init                 # scaffolds flow.md + flow.tests.md
prismpath validate flow.md     # does it compile? no model
prismpath test flow.md         # does it route as written? no model
```

To run the flow end to end (the starter has a semantic edge), add the embeddings extra, then point it
at a worker:

```bash
pip install 'prismpath[embeddings]'   # ~90 MB, on your machine, no cloud, no API key
prismpath run flow.md                 # mock worker by default; --agent ollama:llama3.2 for a real LLM
```

## vs LangGraph / CrewAI

|  | PrismPath | LangGraph / CrewAI |
|---|---|---|
| Definition | inert Markdown | Python / TypeScript code |
| Routing cost | deterministic → embedding → LLM on doubt | a full LLM call, or your own code |
| Validation | compile time, no model | runtime failure |
| Portability | one table on Python, JS, Rust, Go, C, eBPF, an FPGA, and four MCU ISAs | Python runtime |
| Auditability | git diffable + content addressed ledger | logs or a database |

The four baselines are
[real, runnable implementations](https://github.com/crystal-warden/prismpath/blob/main/prismpath/comparisons/README.md),
not a strawman.

## Going deeper

- [The ten-minute tour](https://github.com/crystal-warden/prismpath/blob/main/docs/guides/tour.md) of the
  whole engine.
- **It runs all the way down.** The same Level M table compiles to a Linux kernel XDP program and an FPGA
  fabric, certified against the same frozen vectors. Those substrates, the decidability proofs, the Facet
  wire protocol, and an evidence ledger timestamped to Bitcoin live in the research repo:
  **[crystal-warden/prism-path](https://github.com/crystal-warden/prism-path)**.

Apache-2.0 ([LICENSE](https://github.com/crystal-warden/prismpath/blob/main/LICENSE),
[NOTICE](https://github.com/crystal-warden/prismpath/blob/main/NOTICE)). Fork it and ship it, including
inside a proprietary product: retain LICENSE and NOTICE, mark changed files. No user-facing attribution
required.
