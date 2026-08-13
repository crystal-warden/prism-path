# Supporting Evidence — STAGING (pending rows)

*Append-boundary for the ledger overhaul (see `LEDGER_STANDARDS.md` §6). While the docs session
overhauls `supporting-evidence.md` (#1–#96), the **dev session appends new evidence rows here**,
starting at the next free number, instead of editing the main ledger. On merge, the docs session
folds these into the ledger with correct formatting and clears this file.*

*Format each row exactly per `LEDGER_STANDARDS.md` §1 (Claim / Method / Result + Honest scope /
Provenance) with a month-granularity date. Next free number: **#97**.*

---

<!-- new rows go below this line -->

### #97 — the RP2350 cross-ISA substrate: one signed table, byte-identical decisions on the ARM Cortex-M33 AND the RISC-V Hazard3 cores of the same chip, 124/124 each (August 2026)

**Claim:** the same certified `.ppt` images every other substrate holds are decided byte-identically by a Raspberry Pi Pico 2 (RP2350) on BOTH of its instruction-set architectures — the ARM Cortex-M33 core and the Hazard3 RISC-V core — from ONE source file, each certifying 124/124 on the declared subset. This is cross-ISA conformance on a single chip, a dimension no other substrate on the ladder covers (the language kernels are cross-language on one ISA; this is one source across two ISAs of one die).

**Method:** `prismpath-hw/rp2350/ppt_rp2350.c` is a byte-exact copy of `interp.c` / `ppt_uno.c`'s evaluator core (typed-comparator atoms over the field register file, RPN edge programs with the five boolean opcodes, first-true-edge priority encoder); only the I/O layer differs from the AVR (#92) — native USB-CDC via the Pico SDK instead of the AVR UART. The ISA identifier is chosen by the compiler (`#if defined(__riscv)`), so the SAME source self-identifies as `rp2350-arm` or `rp2350-riscv`. Built twice from one CMake project: `-DPICO_PLATFORM=rp2350-arm-s` (Ubuntu gcc-arm-none-eabi 13.2) and `-DPICO_PLATFORM=rp2350-riscv` (the Raspberry Pi `riscv32-unknown-elf` newlib toolchain, gcc 15.2 — Ubuntu's own riscv gcc lacks newlib's `nosys.specs`). Certified with `certify_rp2350.py`: the EXACT contract of `run_vectors.cert_predicates` with the subprocess replaced by the USB-CDC wire — each in-subset predicate compiled by the UNTOUCHED compiler, streamed ('L'), the registers from the UNTOUCHED `encode_regs` streamed ('V'), the board's verdict checked against the frozen expectation; exclusions by the same machine-readable reasons.

**Result:** **ARM Cortex-M33: 124/124 pass, FAIL 0; RISC-V Hazard3: 124/124 pass, FAIL 0** — both against corpus v2 (1,079), both with all **955 exclusions itemized under byte-identical reasons** (281 field-vs-field + 251 disallowed + 141 constant-only + 119 string-ordering + 114 non-literal-collection + 36 substring + 11 non-scalar + 1 nested + 1 float). USB-CDC eval round-trip: ARM 146/298/1594 µs, RISC-V 139/345/1576 µs (min/median/max) — wire-dominated, an order of magnitude under the AVR's 38400-baud serial; the point is the decision executes ON the MCU core, on each ISA, from the same signed bytes. **Honest scope:** predicate/single-hop decisions only — engine-vector (multi-hop) replay and the visits bank are the same declared non-goals as the AVR tier (#92). Provenance: `prismpath-hw/rp2350/` (`ppt_rp2350.c`, `CMakeLists.txt`, `Makefile`, `certify_rp2350.py`, `cert_rp2350_arm.json`, `cert_rp2350_riscv.json`); Pico SDK 2.1.1; RPi riscv-toolchain v2.3.0-0 (gcc 15.2, newlib).
