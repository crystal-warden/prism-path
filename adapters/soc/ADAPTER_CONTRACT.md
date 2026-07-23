# SOC adapter — the port contract

Conforms to [../ADAPTER_GUIDE.md](../ADAPTER_GUIDE.md). NO SOC vocabulary (wazuh, ATT&CK, containment,
et-bert…) lives in the `prismpath/` core — `tools/arch_guard.py` Signal-1 guards that (SOC nouns are
registered in `arch_guard.config.json`). This adapter turns SIEM alerts into escalation-default,
human-gated triage decisions.

## The six ports (SOC mapping)

| Port | SOC implementation |
|---|---|
| **Ingestion** | `wazuh_triage_agent._search` — read the next batch of alerts from the Wazuh indexer (auth at runtime, never at import; never a sudo prompt on load). `alert_document` / `alert_key` normalize an alert into a document + a stable key. |
| **Retrieval** | detection knowledge (MITRE technique framing in the flow) + the **prefilter corpus** of prior verdicts, injected as decision criteria (one-directional; the dilution rule). |
| **cheap gate** | `PrefilterCache` (`prismpath.prefilter`) — a near-identical prior verdict (cosine ≥ 0.97, confidence ≥ 0.8) auto-resolves and **skips the LLM**; a miss adjudicates then `learn()`s. Measured ~59% auto-resolve → ~2.4× capacity. Opt-in, use-as-needed (§4.7 of the guide). |
| **Adjudicator** | the decomposed flow routes by **MITRE ATT&CK tactic** into per-tactic escalation-default nodes; each recommends `contain` / `watch` / `ignore` with a structured verdict. |
| **Action / Sink** | a finding record + a **STAGED** containment action written to disk — **never applied.** A human approves every action (Mode 1, report-only). |
| **Attestation** | the Flow-Ledger: each triaged unit is a `@checkpoint` proof-commit; `_flow_hash(FLOW)` is the `policy_hash` so editing the map rotates the attestation. |
| **Deferral** | human-gated containment is the review queue; staged actions await sign-off. |

## Rules (adapter-specific, on top of the guide's invariants)
- **Escalation-default = watch, not benign.** In every adjudicator the `-> watchlist: when always`
  fallback is the conservative default: an alert is never dismissed as benign unless benign is positively
  shown. (Compare compliance's `not-met` default.)
- **Containment is staged, never applied.** No active response from the adapter; a report a human acts on.
- **The prefilter is a cost lever, not a classifier** — it reuses a *prior human/LLM verdict* on a
  near-identical alert; novelty always escalates to the LLM.
- **Structured verdict fields drive routing** — the agent returns `{recommended_action, text, …}` so the
  deterministic `when recommended_action == "contain"` edges fire before any semantic routing.

## Runtime
`wazuh_triage_agent.py` loads `flows/wazuh_triage.md` (override with `TRIAGE_FLOW`), runs the ledgered
loop with a `HybridRouter`, and writes findings + staged actions. Live operation needs the Wazuh hub, a
served model at `:8888`, and the ET-BERT flow embedder. Tests cover the map + module surface offline;
live adjudication is opt-in (`-m live`).
