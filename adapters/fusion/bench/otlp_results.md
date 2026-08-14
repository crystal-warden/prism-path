# OTLP baseline — the industry-standard telemetry wire vs the decision codec

The bandwidth story, measured against **OpenTelemetry (OTLP)** — the wire real observability
pipelines speak — not just JSON. Records are genuine `opentelemetry.proto` `LogRecord`s (they
round-trip). n = 64,484 representative fused decisions; batched the way OTLP ships
(ResourceLogs/ScopeLogs amortized over 4096-record epochs).

| encoding | B / decision | note |
|---|---:|---|
| **OTLP faithful** (4 decision fields as attributes) | **101.372** | industry-standard telemetry envelope |
| OTLP faithful + zstd-19 (batched) | 7.162 | |
| OTLP faithful + gzip-9 (batched) | 9.279 | |
| B2 — minimal 4-field JSON | 68 | (from results.json) |
| **O1 — the decision wire (per-field)** | **1.5** | self-framing, tamper-evident |
| OTLP minimal (band only) | 39.905 | vs O2 band stream |

**Headline:** the decision wire is **67.6× smaller than OTLP-protobuf** per
decision, and **4.8× smaller than zstd-compressed batched OTLP**.

**Precision note:** the recorded ratios use O1 rounded to 1.5 B/decision (as `otlp_results.json`
states). The exact measured O1 is **1.516** B/alert (`results.json`, ledger #84), which gives
**66.9×** and **4.7×**; the exact O2 (0.516) gives **77.3×** against OTLP-minimal rather than 79.8×.
The conservative exact figures are the ones to quote under hostile review.

**Why OTLP is this size (honest):** OTLP is a general telemetry *envelope*, not a decision codec.
Every record carries two per-record wall-clock timestamps (fixed64), typed attribute values, and
repeated string keys — so it is ~100 B/record and actually **larger
than minimal JSON** (1.49× B2) for this payload. Compression
recovers the repeated keys but not the per-record timestamps. The decision codec's advantage over
OTLP is therefore structural (it ships the decision, not a timestamped attribute bag), the same
distinction the wire-mode analysis (#86) draws against JSON: we win on self-framing per-reading
streamability, tamper-evidence, and decidability — and here, unlike against zstd-batched JSON, also
decisively on raw size.

**Honest scope:** decision-sufficient telemetry, not a lossless log record — OTLP carries a
general event; our wire carries the routed decision. Representative population (wire cost is
field-shape-invariant, #84). OTLP metrics (Sum/Gauge) would differ in constant overhead; the log
signal is the apples-to-apples one for a discrete routed decision.
