# Fusion adapter · the port contract

Conforms to [../ADAPTER_GUIDE.md](../ADAPTER_GUIDE.md). NO fusion vocabulary (dev_mg, soc_action,
fusion_triage, coincident_critical…) lives in the `prismpath/` core; `tools/arch_guard.py` Signal-1
guards that (fusion nouns are registered in `arch_guard.config.json`). This adapter joins two verdict
streams (a physical posture (IMU) and a cyber triage verdict (SIEM)) into one decidable,
provable fusion decision.

## The six ports (fusion mapping) · v1 scope, honestly

v1 is **not** a full six-port connector; it is the decidable join + its evidence machinery. The ports
map as follows, with the unimplemented ones named rather than hand-waved:

| Port | Fusion implementation (v1) |
|---|---|
| **Ingestion** | two upstreams: the SOC adapter's SIEM source (`adapters/soc/siem.py`, read only) for alerts, and the sensor bridge's NDJSON reading stream (`prismpath-hw/bridge/field_bridge.py` schema) for physical posture. `projection.py` normalizes both into one fused reading. |
| **Adjudicator** | **the Level M flow itself** (`flows/fusion_triage.md`): fully deterministic, no LLM in the decision path. That is the point: the fusion verdict is a proof, not a judgment. |
| **Action / Sink** | aggregate artifacts only: the frozen tessellation (`conformance/`), the dated census (`evidence/`), and bench results (`bench/`). No live action; report-only. |
| **Attestation** | `evidence/SHA256SUMS` + OpenTimestamps anchor (the telemetry adapter's content-anchor pattern). |
| **Retrieval** | N/A in v1 (no knowledge injection: the flow routes on fields alone). |
| **Deferral** | N/A in v1; the live coincident-capture follow-on adds the human-review path for coincident verdicts. |

## Rules (adapter-specific, on top of the guide's invariants)

- **Every threshold is a real operational boundary.** 150 / 500 / 2500 dev_mg are the sensor bridge's
  own DEADBAND / MOVE_DEV / SHAKE_DEV constants (×1000); 7 and 12 are the SIEM's own triage floor and
  containment line (the wazuh_triage flow's edges). No constant exists to shape the decision space.
- **Escalation-default at the join.** Coincidence of physical disturbance and a containment-grade cyber
  verdict is the worst case and is checked first; "all quiet" must be shown on both axes (`else` last).
- **Two cyber paths, one field.** `soc_action` is fed either by the decidable projection of
  `rule_level` (the census path; no LLM, labeled as such) or by a real adjudicator verdict (the SOC
  adapter's LLM path). Both produce the same field contract; artifacts always state which path fed them.
- **Aggregates only in committed artifacts.** Nothing committed may contain raw alert content, agent
  names, hostnames, or IPs; a privacy regression test enforces this on the census artifact.
- **The census pairing is labeled.** Month-scale census pairings are `assume_still` (baseline posture,
  cyber axis fully real) and `independence_expected` (marginals measured, joint modeled). Neither is
  time coincident; the live capture follow-on is the only true joint.

## Runtime

Offline by default: tests run on fixtures and the frozen corpus. Live paths (`census.py --live`,
`bench/bandwidth.py --live`) read the local SIEM indexer read only and are opt-in, mirroring the SOC
adapter's `-m live` convention. Cross-adapter imports (telemetry codec modules, soc SIEM client) use
the repo's self-rooted `sys.path` idiom; this adapter modifies neither.
