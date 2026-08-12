# Fusion adapter — cyber-physical decision fusion

One decidable Level M flow that joins a **physical** verdict stream (IMU posture from the sensor
bridge) with a **cyber** verdict stream (SIEM triage) and proves every fused decision. The decision
space is spiral-tessellated (Tier 6) and censused against a real month-scale alert backlog; the
bandwidth story (raw alert JSON vs the decision-code wire) is measured, with the codec's own
overhead counted.

## File map

| File | Role |
|---|---|
| [ADAPTER_CONTRACT.md](ADAPTER_CONTRACT.md) | port mapping + v1 scope honesty |
| [flows/fusion_triage.md](flows/fusion_triage.md) | THE flow — 4 fusion fields, 7 verdicts, every threshold a real operational boundary |
| [projection.py](projection.py) | decidable cyber projection (`rule_level` → `soc_action`) + IMU reading normalization + the fused-reading contract |
| [gen_fusion_spiral.py](gen_fusion_spiral.py) | freezes the Tier-6 tessellation + boundary probes → `conformance/spiral_fusion.json` |
| [census.py](census.py) | band-population census over the live SIEM backlog + real IMU sessions → `evidence/census_YYYY-MM.json` (aggregates only) |
| [bench/bandwidth.py](bench/bandwidth.py) | measured bandwidth: raw-JSON baselines vs decision-code streams (+ Merkle/epoch overhead, loss scenario) |
| [conformance/](conformance/) | frozen integer tessellation (a mapping bug flips a frozen entry → test RED) |
| [evidence/](evidence/) | dated census artifacts + `SHA256SUMS`(+`.ots`) content anchor |
| [fixtures/](fixtures/) | synthetic NDJSON fixtures for offline CI (fake names/IPs; byte numbers never published) |
| [tests/](tests/) | offline suite; live paths opt-in via `-m live` |

## Quickstart

```sh
# offline (no SIEM, no sensor needed)
python -m pytest adapters/fusion -q                    # the suite
python adapters/fusion/gen_fusion_spiral.py            # regenerate the frozen tessellation (must be byte-identical)

# live (local SIEM indexer, read-only; opt-in)
python adapters/fusion/census.py --live --min-level 7
python adapters/fusion/bench/bandwidth.py --live --max-docs 2000   # smoke, then drop --max-docs
```

## Dependencies (read-only, unmodified)

- `adapters/telemetry/` modules — quantizer / wire / packed / selfheal / epochs / decode / spiral
  (the codec and the Tier-6 packing; imported via the repo's self-rooted `sys.path` idiom).
- `adapters/soc/siem.py` — the SIEM source + alert normalization for the live paths.
- `prismpath-hw/bridge/field_bridge.py` — schema + threshold provenance for the physical fields;
  `prismpath-hw/evidence/mac_bridge_*.ndjson` — real recorded IMU sessions (the physical marginal).

## Honesty notes

- The month-scale census is **not time-coincident** — pairings are labeled (`assume_still`,
  `independence_expected`); the live coincident capture is a separate follow-on and the only true joint.
- The census cyber verdict is the **decidable projection** of `rule_level`, not an LLM verdict; the
  real-adjudicator path feeds the same field and is exercised separately.
- Committed artifacts are **aggregates only** (no alert content, hostnames, agent names, or IPs),
  enforced by a privacy regression test.
