# SOC triage adapter — blue-team alert triage

A PrismPath **domain adapter** (the first reference adapter; the compliance adapter was modeled on it).
It turns live Wazuh/SIEM alerts into **escalation-default, human-gated** triage decisions. Conforms to
the [adapter standard](../ADAPTER_GUIDE.md); the port boundary is in `ADAPTER_CONTRACT.md`.

Runs against the published `prismpath` core (`import prismpath`). **Containment is always STAGED, never
applied** — a human approves every action.

## File map

| file | role |
|---|---|
| `wazuh_triage_agent.py` | the adapter: Ingestion (Wazuh search), Retrieval (detection knowledge), the **prefilter** cheap-gate, the per-tactic Adjudicator agent, Sink (finding + staged containment), Attestation (Flow-Ledger `@checkpoint`) |
| `measure_prefilter.py` | escalation-reduction measurement for the vector prefilter (static + streaming self-learning rates) |
| `flows/wazuh_triage.md` | the triage map (prefilter → signature gate → adjudicate → stage/watch/benign) |
| `flows/wazuh_triage_decomposed.md` | the decomposed map: route by **MITRE ATT&CK tactic** into per-tactic escalation-default adjudicators |
| `tests/` | deterministic flow-structure tests; live-SIEM adjudication is opt-in |

## How it maps the six ports (see ADAPTER_CONTRACT.md)
Ingestion = Wazuh indexer search · Retrieval = detection knowledge + the prefilter corpus ·
**cheap gate** = `PrefilterCache` (≈59% auto-resolve, measured) · Adjudicator = per-tactic decision
(`contain`/`watch`/`ignore`) · Sink = finding + **staged** containment · Attestation = Flow-Ledger.

## Quick start
```bash
PP=~/cwprojects/prismpath/.venv/bin/python
$PP -m prismpath.cli validate flows/wazuh_triage_decomposed.md   # the map compiles
$PP -m pytest tests -q                                           # deterministic flow-structure tests
# live (needs the Wazuh hub + served model):
python wazuh_triage_agent.py seed        # seed/inspect the prefilter corpus
TRIAGE_FLOW=flows/wazuh_triage.md python wazuh_triage_agent.py   # one triage pass (report-only, Mode 1)
```

> Live operation needs the Wazuh indexer (auth via `sudo`, read at runtime), a served model at
> `:8888`, and the ET-BERT flow embedder for the Layer-2 signal. See
> `../../prismpath/PRISMPATH_USECASE_blue_team_soc_triage.md` for the measured deployment.

> **Flows are symlinks** to the canonical engine-reference flows in `prismpath/flows/` (the SOC
> triage flow is also a shipped engine example: the portability P0 claim + contract-derivation test
> reference it). The adapter references them so the agent + tests resolve locally.
