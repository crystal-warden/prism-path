# SOC triage adapter · blue-team alert triage

A PrismPath **domain adapter** (the first reference adapter; the compliance adapter was modeled on it).
It turns live Wazuh/SIEM alerts into **escalation default, human-gated** triage decisions. Conforms to
the [adapter standard](../ADAPTER_GUIDE.md); the port boundary is in `ADAPTER_CONTRACT.md`.

Runs against the published `prismpath` core (`import prismpath`). **Containment is always STAGED, never
applied**: a human approves every action.

## File map

| file | role |
|---|---|
| `wazuh_triage_agent.py` | the adapter: a **Connector SDK** consumer (`WazuhTriageConnector`): Retrieval (detection knowledge), the **prefilter** cheap-gate, the per-tactic Adjudicator agent, Sink (finding + staged containment), Attestation (Flow-Ledger `@checkpoint`); `labels` emits adjudication history for `prefilter tune` |
| `siem.py` | the **SIEM ingestion port**: `ElasticSource` (any Elasticsearch/OpenSearch indexer, env-configured, TLS verified by default), `WazuhSource`, `NDJSONFileSource` (air-gap/replay), `SplunkSource` (best-effort): selected by `SIEM_KIND` |
| `measure_prefilter.py` | escalation-reduction measurement for the vector prefilter (static + streaming self-learning rates) |
| `flows/wazuh_triage.md` | the triage map (prefilter → signature gate → adjudicate → stage/watch/benign) |
| `flows/wazuh_triage_decomposed.md` | the decomposed map: route by **MITRE ATT&CK tactic** into per-tactic escalation default adjudicators |
| `tests/` | deterministic flow-structure tests; live-SIEM adjudication is opt-in |

## How it maps the six ports (see ADAPTER_CONTRACT.md)
Ingestion = the `siem.py` SIEMSource port · Retrieval = detection knowledge + the prefilter corpus ·
**cheap gate** = `PrefilterCache` (≈59% auto-resolve, measured) · Adjudicator = per-tactic decision
(`contain`/`watch`/`ignore`) · Sink = finding + **staged** containment · Attestation = Flow-Ledger.

## Quick start
```bash
# from this directory, with the repo's package installed (pip install -e ../..)
python -m prismpath.cli validate flows/wazuh_triage_decomposed.md   # the map compiles
python -m pytest tests -q                                           # deterministic tests (stubbed HTTP)
# live (needs a reachable SIEM + served model):
python wazuh_triage_agent.py seed        # seed/inspect the prefilter corpus
TRIAGE_FLOW=flows/wazuh_triage.md python wazuh_triage_agent.py   # one triage pass (report-only, Mode 1)
```

> Live operation needs a SIEM behind the `siem.py` port (`SIEM_KIND`; credentials via
> `SIEM_USER`/`SIEM_PASSWORD`, TLS verified by default; the legacy Wazuh install-tar extraction is
> the opt-in fallback), a served model at `PRISMPATH_LLM_ENDPOINT`, and the ET-BERT flow embedder
> for the Layer-2 signal. `deploy/systemd/cw-triage.*` runs it on a timer. See
> `../../prismpath/PRISMPATH_USECASE_blue_team_soc_triage.md` for the measured deployment.

> **Flows are symlinks** to the canonical engine-reference flows in `prismpath/flows/` (the SOC
> triage flow is also a shipped engine example: the portability P0 claim + contract-derivation test
> reference it). The adapter references them so the agent + tests resolve locally.
