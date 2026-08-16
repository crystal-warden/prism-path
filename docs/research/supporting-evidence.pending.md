# Supporting Evidence · STAGING (pending rows)

*Append boundary for ledger overhauls (see `LEDGER_STANDARDS.md` §6). While a docs session overhauls
`supporting-evidence.md`, the **dev session appends new evidence rows here**, starting at the next
free number, instead of editing the main ledger. On merge, the docs session folds these into the
ledger with correct formatting and clears this file.*

*Format each row exactly per `LEDGER_STANDARDS.md` §1 (Claim / Method / Result + Honest scope /
Provenance) with a month granularity date. Next free number: **#105**.*

---

<!-- new rows go below this line -->

### #104 — the Facet codec measured on bare metal: the C Zeckendorf encoder verified and timed on all four MCU instruction sets (August 2026)

**Claim:** the wire encoder (Zeckendorf coding plus byte packing, the front half of Phase C2) runs on the same four MCU instruction sets that decide policies, byte identical to the Python reference, at microsecond scale on the 32 bit cores and under 2 ms worst case on the 8 bit floor tier. The FQ paper's §5.5 cost model for the codec on constrained hardware is now a measurement.

**Method:** `prismpath-hw/codec-bench/`. A portable C encoder (`zeck.h`: 78 entry u64 Fibonacci table F2..F79 covering the full 2^53 domain, 624 bytes of constant data, greedy subtraction, MSB first bit accumulator matching `packed.pack(bits, 8)`); `gen_bench_data.py` generates 64 four field events per workload WITH their expected wire bytes from the Python reference (typical: wire ints 1..6, 2.281 B/event; stress: a 1,000 cell codebook, wire ints 1..1001, 7.062 B/event); every target verifies all 128 rows byte for byte on device before timing, and a mismatch halts the bench. Timing: Uno R3 via Timer1 (64 us tick, 2,048 events per window), ESP32 via esp_timer, RP2350 via time_us_64 (65,536 events each), the RP2350 building both ISAs from one source file. Compiled -Os throughout.

**Result:** typical / stress ns per event: **ATmega328P 16 MHz: 462,718 / 1,756,625** (~7,400 cycles typical); **Xtensa LX6 240 MHz: 9,283 / 27,902**; **Cortex-M33 150 MHz: 5,338 / 14,870**; **Hazard3 RISC-V 150 MHz: 4,645 / 13,690** (~700 cycles typical). All four verified 128/128 corpus rows before timing. Bring up found and fixed an AVR RAM hazard: the corpus and table initially landed in `.data` (1,980 of the part's 2,048 bytes), starving the stack; moved to PROGMEM (`.data` 124 bytes). **Honest scope:** encoder only (on device decode unmeasured); a wall clock microbenchmark on one board per ISA at -Os, not a cycle exact WCET; the u64 table is the general implementation and a small symbol table would be faster; Merkle/SHA-256 stays literature cited; the FPGA shift register codec remains the unbuilt half of C2. Staged here, not yet OTS anchored. Provenance: `prismpath-hw/codec-bench/` (`zeck.h`, `bench_core.h`, `gen_bench_data.py`, `avr_bench.c`, `esp32/`, `rp2350/`, `results.md`); boards Uno R3, ESP-WROOM-32, Pico 2 W; avr-gcc, ESP-IDF v5.4, pico-sdk.
