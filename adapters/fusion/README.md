# Fusion adapter · the decision fusion plane

One decidable Level M flow that joins any N decision sources into a single provable fused decision and
carries it over the Facet wire. The v1 worked example joins a **physical** verdict stream (IMU posture
from the sensor bridge) with a **cyber** verdict stream (alert triage), and proves every fused decision.
The decision space is spiral tessellated (Tier 6) and censused against a real month scale alert backlog;
the bandwidth story is measured **two ways**: payload (raw alert JSON vs the decision code) and **on the
wire** (per packet transport framing counted, across three transmission strategies, with an optional
measured encryption layer); every overhead byte counted.

## File map

| File | Role |
|---|---|
| [ADAPTER_CONTRACT.md](ADAPTER_CONTRACT.md) | port mapping + v1 scope honesty |
| [flows/fusion_triage.md](flows/fusion_triage.md) | THE flow: 4 fusion fields, 7 verdicts, every threshold a real operational boundary |
| [projection.py](projection.py) | decidable cyber projection (`rule_level` to `soc_action`) + IMU reading normalization + the fused reading contract (the join every source normalizes into) |
| [gen_fusion_spiral.py](gen_fusion_spiral.py) | freezes the Tier 6 tessellation + boundary probes to `conformance/spiral_fusion.json` |
| [census.py](census.py) | band population census over an alert level backlog + real IMU sessions to `evidence/census_YYYY-MM.json` (aggregates only) |
| [bench/bandwidth.py](bench/bandwidth.py) | **payload** bandwidth: raw JSON baselines vs decision code streams (+ Merkle/epoch overhead, loss scenario) |
| [bench/otlp_baseline.py](bench/otlp_baseline.py) | the **Facet** baseline: the same fused decision as a real OTLP LogRecord vs the decision codec, bytes per decision |
| [bench/wire.py](bench/wire.py) | **wire** bandwidth: 3 transmission strategies (stream / batch / MTU fill + latency cap knob) with per packet IP/TCP/TLS framing counted, ours vs minimal JSON ±zstd, + a measured AEAD+ECDHE confidentiality layer to `wire_{siem,imu}.{md,json}` |
| [conformance/](conformance/) | frozen integer tessellation (a mapping bug flips a frozen entry to test RED) |
| [evidence/](evidence/) | dated census artifacts + `SHA256SUMS`(+`.ots`) content anchor |
| [fixtures/](fixtures/) | synthetic NDJSON fixtures for offline CI (fake names/IPs; byte numbers never published) |
| [tests/](tests/) | offline suite |

## Quickstart

Everything runs offline: the suite, the census, and the benches all read fixtures and the frozen corpus,
so no external source is needed.

```sh
python -m pytest adapters/fusion -q                           # the suite
python adapters/fusion/gen_fusion_spiral.py                   # regenerate the frozen tessellation (must be byte-identical)
python adapters/fusion/census.py                              # band census over the fixture backlog
python adapters/fusion/bench/otlp_baseline.py                 # the Facet baseline (OTLP vs the decision codec)
python adapters/fusion/bench/bandwidth.py --from-ndjson adapters/fusion/fixtures/alerts_synth.ndjson
python adapters/fusion/bench/wire.py --imu                    # steady sensor corpus, on disk
python adapters/fusion/bench/wire.py --from-fixture           # synthetic bursty stream
```

## Dependencies (read only, unmodified)

- `adapters/telemetry/` modules: quantizer / wire / packed / selfheal / epochs / decode / spiral
  (the codec and the Tier 6 packing; imported via the repo's self-rooted `sys.path` idiom).
- `prismpath-hw/bridge/field_bridge.py`: schema + threshold provenance for the physical fields;
  `prismpath-hw/evidence/mac_bridge_*.ndjson`: real recorded IMU sessions (the physical marginal).

A live decision source is an external connector, not a dependency of the join: any source that emits
the reading contract in `projection.py` slots in. The v1 SIEM source connector was one such example
and is archived.

## Honesty notes

- The month scale census is **not time coincident**: pairings are labeled (`assume_still`,
  `independence_expected`); the live coincident capture is a separate follow-on and the only true joint.
- The census cyber verdict is the **decidable projection** of `rule_level`, not an adjudicator verdict;
  any adjudicator path feeds the same field through `soc_action_from_verdict` and is exercised separately.
- Committed artifacts are **aggregates only** (no alert content, hostnames, agent names, or IPs),
  enforced by a privacy regression test.
- **Payload ratios are not wire ratios.** The headline `bandwidth.py` numbers (e.g. 1,992× vs raw
  alert JSON) count per alert *content*; `wire.py` measures the wire with per packet framing counted,
  where the self framing win is a *batching* property; ~45× vs uncompressed batched JSON and a wash
  vs zstd batched JSON (won there on tamper evidence, streamability, and decidability, not raw size).
  The encryption layer (AEAD + ECDHE) adds ~0.035 B/decision when batched, and is redundant over
  TCP+TLS (its value is TLS less transports). Single stream (N=1) baseline; the multi source scaling
  claim is a stated hypothesis, not yet measured. See supporting-evidence rows #84 and #86.
