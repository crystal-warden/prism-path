# The walker's reading, two ways: Facet vs a standard telemetry pipeline

The demo's carried sensor makes one reading: a motion band. Here is what it costs to move that
reading to a decision over the industry standard pipeline, and what it cost on this bench tonight.
Every number below is measured, and each one names its source.

## The wire

| | standard pipeline | this demo (Facet) |
|---|---|---|
| One reading on the wire | 68 B minimal JSON, or 101.4 B as OTLP protobuf, 39.9 B OTLP band-only (measured, genuine opentelemetry.proto records, n=64,484) | **3 B** self-framed Facet frame (the bridge console logged every one tonight: `frame 3B -> fabric`) |
| Compressed, batched | 7.2 B/decision (OTLP + zstd-19 over 4096-record batches) | 1.5 B/decision amortized with Merkle integrity included (measured, evidence #84) |
| Ratio | | **66.9x smaller than OTLP**, 4.7x smaller than zstd-batched OTLP, 13x smaller than the band-only OTLP record |

The gap is structural, not a compression trick. OTLP ships a timestamped attribute bag with string
keys; Facet ships the decision. Compression recovers the repeated keys but never the envelope.

## The pipeline

| | standard pipeline | this demo (Facet) |
|---|---|---|
| Transport | WiFi + TCP + TLS + MQTT/HTTP broker | ESP-NOW broadcast, one radio hop |
| Who decodes | a JSON/protobuf parser: megabytes of library code, heap allocation, unbounded parse time | a shift register in the FPGA fabric: the frame decoded with no processor on the wire |
| Who decides | a rules engine or consumer service: Turing complete, undecidable in general, no timing bound | a Level M interpreter in silicon: decidable by construction, worst case **11 cycles, signed into the policy and witnessed on the pins** (16,009 evaluations measured, max 9) |
| Smallest device that can participate | something that can run a TLS stack and a parser | anything that can shift bits: proven tonight on an ESP32, a Zynq fabric, and (same policy, same bytes) a Linux kernel eBPF program |
| Integrity | bolt-on: sign the payload, trust the broker, trust the parser | the wire is tamper evident by construction (Merkle epochs), and every decision writes a receipt bound to the signed policy hash |
| What arrives | data, to be interpreted later by code someone must audit | a decision, made by a rule someone signed |

## What that meant on this bench tonight

The walker broadcast its motion at 5 Hz. Total decision traffic on the air: **15 bytes per
second.** The same stream as faithful OTLP records: ~507 B/s before transport overhead, plus a
broker, a parser, and a rules engine that no one can bound or prove. The fabric decoded every
frame, held the band in a resident register under a signed hysteresis policy, and wrote 166
receipt lines you can check against the video.

Honest scope: Facet carries decision sufficient telemetry, not a lossless event log. If you need
the full sensor trace, you keep a reservoir at the edge; the wire carries what the decision needs.
That is the design, not a limitation discovered later.

Sources: `adapters/fusion/bench/otlp_results.md` (OTLP/JSON measurements, genuine protobuf,
round-tripped); evidence #84 (wire cost, integrity apparatus included); the WCET witness
(`hyst-cert/evidence/wcet_rewitness_hyst_band.log`); the walker receipt
(`hyst-cert/evidence/walker_beat.log`); the bridge console (tonight's session).
