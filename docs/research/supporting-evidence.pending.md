# Supporting Evidence · STAGING (pending rows)

*Append boundary for ledger overhauls (see `LEDGER_STANDARDS.md` §6). While a docs session overhauls
`supporting-evidence.md`, the **dev session appends new evidence rows here**, starting at the next
free number, instead of editing the main ledger. On merge, the docs session folds these into the
ledger with correct formatting and clears this file.*

*Format each row exactly per `LEDGER_STANDARDS.md` §1 (Claim / Method / Result + Honest scope /
Provenance) with a month granularity date. Next free number: **#106**.*

---

<!-- new rows go below this line -->

### #104 — the Facet codec measured on bare metal: the C Zeckendorf encoder verified and timed on all four MCU instruction sets (August 2026)

**Claim:** the wire encoder (Zeckendorf coding plus byte packing, the front half of Phase C2) runs on the same four MCU instruction sets that decide policies, byte identical to the Python reference, at microsecond scale on the 32 bit cores and under 2 ms worst case on the 8 bit floor tier. The FQ paper's §5.5 cost model for the codec on constrained hardware is now a measurement.

**Method:** `prismpath-hw/codec-bench/`. A portable C encoder (`zeck.h`: 78 entry u64 Fibonacci table F2..F79 covering the full 2^53 domain, 624 bytes of constant data, greedy subtraction, MSB first bit accumulator matching `packed.pack(bits, 8)`); `gen_bench_data.py` generates 64 four field events per workload WITH their expected wire bytes from the Python reference (typical: wire ints 1..6, 2.281 B/event; stress: a 1,000 cell codebook, wire ints 1..1001, 7.062 B/event); every target verifies all 128 rows byte for byte on device before timing, and a mismatch halts the bench. Timing: Uno R3 via Timer1 (64 us tick, 2,048 events per window), ESP32 via esp_timer, RP2350 via time_us_64 (65,536 events each), the RP2350 building both ISAs from one source file. Compiled -Os throughout.

**Result:** typical / stress ns per event: **ATmega328P 16 MHz: 462,718 / 1,756,625** (~7,400 cycles typical); **Xtensa LX6 240 MHz: 9,283 / 27,902**; **Cortex-M33 150 MHz: 5,338 / 14,870**; **Hazard3 RISC-V 150 MHz: 4,645 / 13,690** (~700 cycles typical). All four verified 128/128 corpus rows before timing. Bring up found and fixed an AVR RAM hazard: the corpus and table initially landed in `.data` (1,980 of the part's 2,048 bytes), starving the stack; moved to PROGMEM (`.data` 124 bytes). **Honest scope:** encoder only (on device decode unmeasured); a wall clock microbenchmark on one board per ISA at -Os, not a cycle exact WCET; the u64 table is the general implementation and a small symbol table would be faster; Merkle/SHA-256 stays literature cited; the FPGA shift register codec remains the unbuilt half of C2. Staged here, not yet OTS anchored. Provenance: `prismpath-hw/codec-bench/` (`zeck.h`, `bench_core.h`, `gen_bench_data.py`, `avr_bench.c`, `esp32/`, `rp2350/`, `results.md`); boards Uno R3, ESP-WROOM-32, Pico 2 W; avr-gcc, ESP-IDF v5.4, pico-sdk.

### #105 — million decision soak: two native codec Vector pipelines run continuously for over a day with zero errors and ~1.8 MB of total wire (August 2026)

**Claim:** the Facet codec compiled into Vector sustains continuous production shaped operation: two independent encode/decode pipelines ran unattended for 31 and 27 hours, decoding 1,043,442 decisions between them with zero bad lines, zero decode errors, zero log errors, and flat memory, while the total wire traffic for the entire run was ~1.8 MB.

**Method:** `integrations/vector/soak/`. Two two instance pipelines (edge: stdin json -> socket sink `encoding.codec = "facet"`; aggregator: socket source `decoding.codec = "facet"` with `route_node` -> console json), the committed `vector.toml`/`vector_edge.toml` pattern with policy and port swapped per soak; fed at ~5 events/s each by the committed feeders. Soak A: `fusion_triage.md` (4 fields). Soak B: `big_values.md` (3 fields, thresholds spanning 10^2 to 10^12, 5% of events spiking to 10^13..10^15, past 2^53). Durations from the decoded events' own timestamps; wire cost measured by replaying a 1,000 event decoded sample through prismpath-preflight (quantization is idempotent on representatives, so the sample's framed bytes are the wire's).

**Result:** soak A: 556,477 decisions in 30 h 57 m, 2.000 B/event framed, ~1.11 MB total wire. Soak B: 486,965 decisions in 27 h 05 m, 1.466 B/event framed, ~0.71 MB total wire; route distribution baseline 36.32% / throttle 17.72% / elevated 16.40% / slow_path 14.97% / degraded 7.64% / exfil_alert 3.75% / watch 3.21%, matching the same distribution sampled at one sixth of the run within a tenth of a point per route. Memory per Vector instance 56 MB and flat across the full run (debug builds). Combined: 1,043,442 decisions, zero errors of any kind. **Honest scope:** loopback TCP on one host, not a real link; ~5 events/s per pipeline is a soak cadence, not a throughput ceiling (the codec's per event cost is measured elsewhere: #104 on MCUs, 132 to 182 ns in kernel for evaluation); soak A's route node is the uniform intake hop, so its distribution is intentionally degenerate and discrimination is carried by soak B; decoded outputs carry representatives, not originals, by design; debug build binaries, so the flat 56 MB is an upper bound story, not a size claim. Staged here, not yet OTS anchored. Provenance: `integrations/vector/soak/` (`RESULTS.md`, `big_values.md`, `feeder_fusion.py`, `feeder_big_values.py`); fork branch `facet-codec` build of Vector 0.57.0; `prismpath-rs 0.1.0` / `prismpath-telemetry-rs` on crates.io.
