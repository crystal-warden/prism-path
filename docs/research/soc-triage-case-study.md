# PrismPath Use Case · Out-of-Band, AI-Reasoning Blue-Team SOC Triage

*A concrete, measured use case for **PrismPath** (markdown-as-graph workflow engine): a local-LLM
Security Operations Center triage playbook running live over a real Wazuh SIEM, out of band from a
production firewall. Includes the benchmarks and capacity metrics captured to date. Written 2026-07-10.*

---

## 0. TL;DR

A SOC alert-triage procedure is a decision graph: *observe → enrich → decide → contain-or-not →
verify → report*. PrismPath lets you write that graph **as one markdown file** where each `## heading`
is a step (its prose is the agent instruction) and each `-> target: when <predicate>` is an edge.
We authored the blue-team playbook `prismpath/flows/wazuh_triage.md` this way, backed it with an agent adapter
(`wazuh_triage_agent.py`) that reasons via a locally-served Gemma-4-31B, and ran it live against the
homelab Wazuh hub. The payoff PrismPath specifically provides:

- **Auditable control flow**: routing is deterministic `when` predicates over a structured verdict,
  not hidden model whim. You can read the flow file and know exactly how any alert will be handled.
- **Machine-enforced guardrails via gates**: the firewall "never auto-apply" rule is not a hope;
  the `verify_staged` gate makes *"a PENDING draft exists on disk"* the definition of done.
- **A pluggable escalation-reduction gate**: the `vector_prefilter` node auto-resolves near identical
  alerts before the LLM runs (the demand lever).
- **A natural home for a two-model fabric**: the same `when` predicates express the fast-path/slow-path
  escalation rule for a cheap 7B + smart 31B tiering (the supply lever).

---

## 1. Why SOC triage is a good fit for PrismPath

SOC playbooks are already written as runbooks; ordered steps with branch conditions ("if the source
is external AND the login succeeded, contain; else watch"). Three properties make PrismPath a better host
for them than a hand-coded state machine or an opaque agent loop:

1. **The playbook IS the artifact.** Analysts and auditors read `wazuh_triage.md` directly; no
   translation between "the documented procedure" and "the code that runs." The flow file lives in
   git; Wazuh FIM can watch the flows directory; the playbook can be hash-checked before each run.
2. **Judgment is isolated to one node.** Only `classify` calls the LLM. Every other transition is a
   safe, inspectable predicate. This bounds where non-determinism can enter and makes the expensive
   step (LLM inference) explicit and measurable.
3. **"Done" is enforceable, not asserted.** A containment step that claims success is not trusted; a
   gate re-checks the world. For security automation touching a firewall, that distinction is the
   whole ballgame.

---

## 2. The flow · `prismpath/flows/wazuh_triage.md` (annotated)

```
observe → enrich → vector_prefilter → classify → stage_containment → verify_staged → report → end
                        │                 │              (gate) ────────┴─ escalate_human
                        ├─ contain/watch/benign (cache hit, LLM skipped)
                        └─ classify → watchlist / benign
```

- **observe**: pull the highest-priority unprocessed alert from the Wazuh indexer; summarize agent,
  rule, level, source. `-> idle: when no_alert` / `-> enrich: when always`.
- **enrich**: gather context (related alerts from same agent in 24h, how often this rule fires,
  prior history for the source IP) into a short brief.
- **vector_prefilter**: embed the alert, cosine-match against the corpus of alerts the LLM already
  adjudicated; if near identical to a high-confidence prior verdict, **reuse it and skip the LLM
  entirely**. `-> stage_containment: when cached_action == "contain"` (etc.), else `-> classify`.
  *(This is the demand lever; see §4.)*
- **classify**: the one LLM node. Returns a **structured verdict** (threat class, active-threat flag,
  confidence 0..1, recommended action) enforced by vLLM `response_format=json_schema`. Routing:
  `-> stage_containment: when rule_level >= 12`, `-> stage_containment: when recommended_action == "contain"`,
  `-> watchlist: when recommended_action == "watch"`, `-> benign: when recommended_action == "ignore"`.
- **stage_containment**: draft an OPNsense block rule with a full reasoning chain to the staging dir.
  **NEVER applies anything.** Staging the draft is the only permitted action.
- **verify_staged**: **the gate.** Confirm the draft exists on disk, is non-empty, carries the
  reasoning chain and a PENDING marker. `-> report: when staged_ok` / `-> escalate_human: when not staged_ok`.
- **watchlist / benign**: record for recurrence / learn the benign pattern (feeds alert-fatigue control).
- **report**: write the triage report (alert, context, decision path, action taken) and mark the
  alert processed.

---

## 3. How each PrismPath primitive was used (the specific utilization)

| PrismPath primitive | How this use case uses it |
|---|---|
| **markdown node = agent step** | Each `##` heading's prose is the analyst instruction for that step; the adapter maps the node name to a Python handler (`observe`, `enrich`, `classify`, …). |
| **`-> target: when <predicate>`** | All control flow. Predicates run in PrismPath's **safe AST evaluator** (no calls/attribute access/subscripts) over fields the node returns: e.g. `rule_level >= 12`, `cached_action == "contain"`, `recommended_action == "ignore"`, `staged_ok`. Deterministic and readable. |
| **Structured output → predicate fields** | `classify` returns a JSON object (VERDICT_SCHEMA: `threat_class` enum, `is_active_threat`, `confidence`, `recommended_action` ∈ {contain,watch,ignore}) enforced at the vLLM layer. Those exact fields are what the `when` edges test: the model's judgment becomes machine-routable without parsing prose. |
| **Gate = definition of done** | `verify_staged` is a gate: the staged file on disk (with PENDING marker + reasoning) is the DoD, not the model's claim of success. This is how the **"never touch the firewall directly" guardrail is machine enforced** rather than merely followed. |
| **Pluggable pre-filter node** | `vector_prefilter` is a gate-shaped escalation reducer: bge-small embedding + cosine match against a growing corpus of adjudicated verdicts. On a confident hit, the LLM is skipped. Now a first class PrismPath component: `prismpath.prefilter.PrefilterCache` (generic, pluggable embedder); this flow's adapter supplies the wazuh-specific document/key mapping and corpus seeding (`python wazuh_triage_agent.py seed`). |
| **Learning loop** | `classify` appends each fresh adjudicated verdict back into the pre-filter corpus, so the next near identical alert auto-resolves. The demand lever compounds over time. |
| **Routing spectrum (embed / hybrid / LLM-on-doubt)** | Semantic edges (where a predicate can't decide) use PrismPath's HybridRouter: embed-first, escalate to the LLM only within a confidence margin. Measured accuracy in §4. |
| **`visits` + escalation** | Recurrence on the watchlist and repeated staging failures escalate to a human note: alert-fatigue and dead-end control built into the graph. |

**Where the two-model supply lever plugs in (proven, not yet wired):** the fast-path/slow-path
escalation rule is *itself* just `when` predicates on the `classify` node; route to the cheap 7B by
default, and `-> escalate_gemma: when rule_level >= 10 or recommended_action == "contain" or is_active_threat`.
PrismPath expresses the tiering natively; §4 has the measured routing rule.

---

## 4. Benchmarks & metrics captured (the evidence)

### 4a. PrismPath routing accuracy (first-party, served Gemma)
- Embedding router: **0.82** accuracy on the `bugfix` flow (17 cases) vs **0.76** lexical baseline.
- **Hybrid frontier** (embed-first, LLM within margin δ), measured against served Gemma:
  δ=0.05 → **0.94 acc @ 19% LLM-call rate**; δ=0.20 → **1.00 acc @ 69% LLM rate**. Frontier is
  non-monotone; the margin has a blind spot for *confident* errors (documented limitation).
- Harness: `eval_hybrid_served.py`, `eval_routing.py`.

### 4b. LLM reasoning capacity (the binding ceiling)
- Gemma-4-31B (NVFP4, vLLM, `127.0.0.1:8888`): **~10.2 tok/s warm single stream**; triage knee
  **~1.11 classifications/sec**.
- Capacity: **~17 to 171 client networks per box**, depending on escalation rate (the master lever).
- Portfolio note: a 31B model sustaining ~10 tok/s single stream is only possible because NVFP4 runs
  on the GB10 (Grace-Blackwell) **native FP4 tensor cores**.

### 4c. Demand lever · vector pre-filter (`vector_prefilter` node)
- **~59% of alerts auto-resolve** at similarity threshold 0.97 → **~2.4× clients/box** before the LLM
  tier is touched. Embedder is pluggable (bge-small now; ET-BERT vectors can join for network flows).
- Scoping note: matching is over the **stable alert fields** (description/agent/srcip/mitre/rule),
  deliberately excluding the volatile 24-hour context; comparable vectors and cache stability, at
  the cost of context-sensitivity in reuse. The two-threshold gate (similarity + stored confidence)
  bounds what a reuse can do; containment always still passes the human-approval gate.

### 4d. Supply lever · two-model fabric (benchmarked 2026-07-10, then torn down)
- Stood up Qwen2.5-Coder-7B-AWQ alongside Gemma, memory-budgeted (`--gpu-memory-utilization 0.12`,
  ~11.5 GB). Coexisted safely: 92 GB / 128 GB used, commit 0.62 (the earlier OOM was 1.1).
- **Speed: 7B 43 tok/s vs 31B 10 tok/s = 4.2×/token, 4.6× end to end.**
- **Verdict-quality A/B** (20 alerts = 10 real Wazuh + 10 crafted; faithful prompt + VERDICT_SCHEMA):
  containment-decision agreement **80%**, clear-malicious verdict agreement **86%**, 7B systematically
  paranoid (**12 over-calls / 1 under-call**), ground-truth accuracy 7B 50% / Gemma 80%.
- **7B is not trustworthy standalone** (1 dangerous under-call; a level-10 SSH brute-force it called
  `watch`). **Routing rule that drives escaped under-calls to 0:** escalate to Gemma if
  `rule.level >= 10` OR 7B says `contain` OR `is_active_threat`; let the 7B auto-handle only
  `level < 10` + `{ignore, watch}` + not-active. Net **~2× aggregate** supply gain at a realistic
  escalation rate; **stacks with the ~2.4× demand lever ≈ ~5× combined.**
- Detail retained in an internal lab log. Decision: torn down (Gemma isn't saturated at
  homelab scale); recipe + numbers retained for re-instantiation at real multi-client scale.

### 4e. Layer-2 detector that feeds this pipeline · ET-BERT (encrypted-traffic)
- Corpus v2: **47,812 malicious flows, 66 families, 2016 to 2026** (internal corpus).
- **Cross-family leave-one-out recall@0.95: macro 0.224 / micro 0.256** (generalization to unseen
  families; real, modest): temporal holdout (≤2023 → 2024 to 26) **0.333**; ROC-AUC **0.831**.
- False positives: **live span0 TCP 0.0%**, held out benign TCP 2.1%, DNS 84% (known collision →
  TCP-only guard). Wired to Wazuh rules **100230/100231** (level 10, MITRE T1071); confirmed firing.
- Verdict: a **partial-recall sieve; a complement to signature/behavioral detection, not a replacement.**

### 4f. Indexer/storage ceiling (measured + fixed 2026-07-10)
- 307 B/alert-doc, 3.6 docs/sec live. Binding tier was **JVM heap (1 GB, already at 26 shards)**;
  **raised to 8.6 GB**; added **90-day ISM retention** (was unbounded). Result: storage is **not** the
  binding capacity tier; the LLM stays the ceiling.

---

## 5. The 3-layer detection architecture this triage sits in

1. **L1; signatures/rules:** Wazuh 4.14.6 (decoders, custom rules, CDB threat lists, vuln detection),
   Suricata IDS (OPNsense), Zeek NSM, Technitium DNS telemetry + encrypted-DNS enforcement.
2. **L2; vector / encrypted-traffic:** ET-BERT cosine detection over mirrored traffic (out of band via
   gretap span), FP-safe, feeds Wazuh (§4e).
3. **L3; reasoning:** this PrismPath triage playbook; a local LLM adjudicates L1/L2 alerts, stages
   (never applies) containment, learns benign patterns.

All of it runs **out of band** on the GB10; blocking only ever happens back at OPNsense, and only after
a human approves a staged draft.

---

## 6. Reproduce / where things live (repo-relative)
- Flow: `prismpath/flows/wazuh_triage.md`  ·  Adapter: `adapters/soc/wazuh_triage_agent.py`
  (a Connector SDK consumer; `WazuhTriageConnector`; SIEM ingestion behind the
  `adapters/soc/siem.py` port: Wazuh/Elastic/OpenSearch, NDJSON files for air-gap/replay)
- Engine/routing: `prismpath/{engine,router,predicates,parser}.py`  ·  Gates: `prismpath/gates.py`
- Pre-filter: `prismpath/prefilter.py` (generic `PrefilterCache` + risk controlled `tune()`; seeding
  lives in the adapter: `python wazuh_triage_agent.py seed | info | labels`)
  (+ `adapters/soc/measure_prefilter.py`)  ·  Routing evals: `prismpath/eval_hybrid_served.py`
- Supply-lever A/B and the L2 detector live in internal lab repos (numbers reproduced in §4d/§4e).
- Staged firewall drafts (never applied) and runtime state live outside the repo (`~/cw-staging/`).
- Reasoning model: `model-gemma` container, `gemma4` @ `127.0.0.1:8888`.

---

## 7. Consulting framing

This is a reference/portfolio build for a **specialty security + local-AI consultancy** (the specialist
MSPs subcontract for the hard 20%). The saleable qualities on display: **measured** (every claim has a
number, including the negative results), **non-disruptive** (out of band, staged/reversible, no outage),
and **honest** (a partial-recall detector is called partial; an unsaturated optimization is deferred, not
shipped). The methodology is the open asset; the tuned, applied implementation is the paid engagement.
