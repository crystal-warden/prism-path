# Supporting Evidence · STAGING (pending rows)

*Append boundary for ledger overhauls (see `LEDGER_STANDARDS.md` §6). While a docs session overhauls
`supporting-evidence.md`, the **dev session appends new evidence rows here**, starting at the next
free number, instead of editing the main ledger. On merge, the docs session folds these into the
ledger with correct formatting and clears this file.*

*Format each row exactly per `LEDGER_STANDARDS.md` §1 (Claim / Method / Result + Honest scope /
Provenance) with a month granularity date. Next free number: **#113**.*

---

<!-- new rows go below this line -->

### #109 — the interpreter's per-evaluate WCET is a closed-form function of the table counts, calibrated cycle exact on the RTL (August 2026)

**Claim:** the fabric interpreter's per-evaluate worst case is an exact structural function of the loaded table's counts: per node, the sum across its edges of `2 + max(prog_words, 1)` cycles, plus 2; equivalently `2E + P + 2` for compiler emitted policies (E the node's edge count, P its total program words). Timing depends on the counts only, never on atom or program contents; there is no micro architecture to make the bound an over approximation.

**Method:** a cocotb/Verilator calibration bench loads five policies spanning 2 to 6 edges and 2 to 15 program words at the start node, including two shape probes that separate the coefficients (a deep single edge conjunction; a wide six edge fan out); an empty context forces the worst case walk (every edge tried, no early match); start to done cycles are counted on the RTL and the residual against `2E + P` must be one constant across all five.

**Result:** the residual is a flat 2 with spread 0, so `N = 2E + P + 2` exactly; the earlier measured 5 to 21 cycles are instances of this formula. Examples at the shipped 50 MHz clock: a one cut, two edge policy evaluates in 8 cycles (160 ns); a five edge fusion policy with 15 program words in 27 cycles (540 ns). **Honest scope:** single evaluate (one node); multi hop flows multiply by hop count, bounded by `max_steps`. The calibration bench and its policies are off-repo lab artifacts; the measurement table is reproduced in the in-repo evidence JSON, and the same accounting is enforced in-repo by `policy_pack.wcet_cycles` (#110) and encoded in the formal harness (#111).

**Provenance:** `prismpath-hw/rtl/ppt_interp.sv` (the DUT, in-repo), `prismpath-hw/evidence/wcet_formal_2026-08-20.json` (measurement table), `prismpath/prismpath/policy_pack.py` (`wcet_cycles`).

### #110 — per-policy WCET travels signed with the policy: `wcet_cycles` in the pack manifest, recomputed at verify (August 2026)

**Claim:** every signed policy pack now carries its own worst case evaluate bound, tamper evident twice over: the value sits under the Ed25519 signature over the canonical manifest, and `verify_pack` independently recomputes it from the image bytes at load time, so a pack whose stated bound disagrees with its own image fails verification even under a valid signature. A timing claim is no longer a datasheet sentence; it is part of the authorized artifact.

**Method:** `policy_pack.build_manifest` computes `wcet_cycles` from the image with the #109 formula in its exact per edge form (`sum(2 + max(p, 1)) + 2`, max over nodes) and stamps it into the manifest; `verify_pack` recomputes and rejects on mismatch; packs signed before the field existed verify unchanged (the check applies only when the field is present). The full policy pack suite is re-run.

**Result:** 22/22 policy pack tests pass; shipped packs verify with recomputed bounds equal to their stamped bounds; the secure hotswap spec §3.1 documents the field, the formula, and the optionality rule. **Honest scope:** the bound is the hardware tier's evaluate in cycles; converting to time requires the shipped clock, which is stated with its timing reports, not inside the manifest. Software tiers verify the field but do not enforce timing.

**Provenance:** `prismpath/prismpath/policy_pack.py`, `prismpath/prismpath/tests/test_policy_pack.py`, `docs/design/spec-secure-hotswap.md` §3.1.

### #111 — the universal WCET envelope, formally attacked: the bound corrected to `3E + P`, base case proven, unbounded induction honestly open (August 2026)

**Claim:** over ALL count valid tables at the synthesized caps (48 edges, 256 program words), the adversarial worst case evaluate is `3E + P` plus framing, i.e. `3·48 + 256 + 8 = 408` cycles (8.16 us at 50 MHz), not the `2E + P` the measurements suggested: a zero word edge still costs one evaluate cycle, so a table with its words piled onto one edge and zero word edges elsewhere exceeds the measured formula. Compiler emitted policies (every edge at least one word) keep `2E + P + 2`. This correction was produced by the formal campaign; no amount of measurement on real policies would have found it, because the compiler cannot emit the adversarial shape.

**Method:** a SymbiYosys harness under `ifdef FORMAL` in the interpreter RTL (compiled out of simulation and synthesis; the conformance gate re-ran green with it in place: 124 predicate + 6 engine vectors, 2,985 sample replay, 0 mismatches). A watchdog asserts `done` within `N_MAX` cycles of an accepted `start`; validity assumptions mirror `validate_image` exactly (total edges and program words within caps, per node edge ranges in bounds, no table load mid evaluate, matching the load then start protocol); the invariant is `cycles + R <= N_MAX` where R is a combinational ranking function (worst case cycles remaining, computed from the FSM state and the count arrays) hand designed to decrease every watched cycle. Engines: smtbmc with boolector, yices, z3, and the `--stbv` encoding; abc pdr with and without a `cutpoint` data abstraction on the match stack (sound: timing is count only); pono mbic3 on an array free mapping.

**Result:** the campaign surfaced and fixed **seven** induction counterexamples, one of them the `3E + P` formula correction now reflected in `wcet_cycles` (#110). The invariant's **base case is proven** (smtbmc yices, seconds: no reachable state violates the 408 cycle bound under the stated assumptions), and bounded model checking is clean through step 275 of a worst case evaluate with zero counterexamples. **Honest scope:** the UNBOUNDED induction step remains open. All counterexamples are eliminated (induction clears the shallow steps); the final step 0 query, which carries the ranking function's 48 term gated sum on both sides of a single transition, exceeded what the open solver portfolio closes within 30 minute budgets. The harness is complete and in-repo; an interpolation capable prover would likely close it as is (MathSAT is research licensed, so that is a deliberate decision, not a download). Until closed, the universal claim is stated as base case proven plus BMC evidenced, never as fully proven.

**Provenance:** `prismpath-hw/rtl/ppt_interp.sv` (the `ifdef FORMAL` block), `prismpath-hw/tb/wcet/ppt_wcet.sby`, `prismpath-hw/evidence/wcet_formal_2026-08-20.json` (calibration table, assumption list, solver matrix); OSS CAD Suite linux arm64 20260819 (Yosys 0.68, SymbiYosys, boolector, yices, z3, abc, pono).

### #112 — the interpreter ports to a second FPGA family on a fully open toolchain: ECP5 closes timing at 31.6 MHz, cycle bounds unchanged (August 2026)

**Claim:** the interpreter RTL is target neutral in practice, not just by inspection: the exact conformance certified and WCET instrumented `ppt_interp.sv` (unmodified, the #109/#111 file) synthesizes and closes timing for a second FPGA family, Lattice ECP5, using a fully open toolchain (Yosys + nextpnr, no vendor tools anywhere in the flow). Cycle domain guarantees (#109, #111) carry to the new target unchanged by construction; only the time conversion moves with the closed clock.

**Method:** `synth_ecp5` in Yosys on the unmodified RTL, then nextpnr-ecp5 place and route for the LFE5U-85F (CABGA381, the ULX3S class part) with a 25 MHz constraint; a 50 MHz probe run records where the family's fabric gives out. The iCE40 path (`synth_ice40`) was attempted for the lowest cost boards. Toolchain pinned: OSS CAD Suite linux arm64 20260819 (Yosys 0.68, nextpnr 0.11.1); the two reproduction commands are in the evidence JSON.

**Result:** ECP5 synthesis is clean with **zero block RAM** (1,611 LUT4, 400 FF, 168 distributed RAM cells, 71 carry); place and route closes at **25 MHz with Fmax 31.60 MHz**, about 3% of the 85F (2,801/83,640 comb cells), so the design also fits the smallest parts of the family. The 50 MHz probe fails: the ECP5 fabric does not reach the Artix-7 clock, and the critical path is the same single cycle atom path the 100 MHz pipeline backlog item targets. Cycle bounds are unchanged: the universal envelope is 408 cycles = 12.9 us at Fmax (vs 8.16 us at the Zynq-7020's 50 MHz); a one cut policy is 8 cycles = 253 ns. **Honest scope:** this is toolchain level portability (synthesizes, places, routes, closes timing), NOT certification on second silicon; that requires the frozen corpus run on a physical ECP5 board. The iCE40 attempt is a real negative: with no distributed RAM in the mapping, the async read table arrays balloon to 9,583 LUT4s, over both UP5K and HX8K budgets at the 48/256 caps; the lowest cost boards are out without a sync read memory re-architecture. Time domain numbers are per target and stated only with that target's timing result, exactly the discipline #110 encodes by stamping cycles, not nanoseconds.

**Provenance:** `prismpath-hw/rtl/ppt_interp.sv` (unmodified, byte identical to #109/#111), `prismpath-hw/evidence/openflow_port_2026-08-20.json` (full cell tables, utilization, timing, reproduction commands, toolchain pin).
