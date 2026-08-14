# OTLP baseline · the industry standard telemetry wire vs the decision codec

The bandwidth story, measured against **OpenTelemetry (OTLP)**, the wire real observability
pipelines speak, not just JSON. Records are genuine `opentelemetry.proto` `LogRecord`s (they
round trip). n = 64,484 representative fused decisions; batched the way OTLP ships
(ResourceLogs/ScopeLogs amortized over 4096 record epochs).

| encoding | B / decision | note |
|---|---:|---|
| **OTLP faithful** (4 decision fields as attributes) | **101.372** | industry standard telemetry envelope |
| OTLP faithful + zstd-19 (batched) | 7.162 | |
| OTLP faithful + gzip-9 (batched) | 9.279 | |
| B2: minimal 4 field JSON | 68 | (from results.json) |
| **O1: the decision wire (per field)** | **1.516** | frames itself, tamper evident |
| OTLP minimal (band only) | 39.905 | vs O2 band stream |

**Headline:** the decision wire is **66.9× smaller than OTLP protobuf** per
decision, and **4.7× smaller than zstd compressed batched OTLP**.
O1 and O2 here count their integrity apparatus (Merkle epoch roots + ACK channel), the same
convention as the #84 headline; every ratio divides by the exact measured cost, not a rounded one.

**Why OTLP is this size (honest):** OTLP is a general telemetry *envelope*, not a decision codec.
Every record carries two per record wall clock timestamps (fixed64), typed attribute values, and
repeated string keys; so it is ~100 B/record and actually **larger
than minimal JSON** (1.49× B2) for this payload. Compression
recovers the repeated keys but not the per record timestamps. The decision codec's advantage over
OTLP is therefore structural (it ships the decision, not a timestamped attribute bag), the same
distinction the wire mode analysis (#86) draws against JSON: we win on self framing per reading
streamability, tamper evidence, and decidability; and here, unlike against zstd batched JSON, also
decisively on raw size.

**Honest scope:** decision sufficient telemetry, not a lossless log record; OTLP carries a
general event; our wire carries the routed decision. Representative population (wire cost is
field shape invariant, #84). OTLP metrics (Sum/Gauge) would differ in constant overhead; the log
signal is the apples to apples one for a discrete routed decision.
