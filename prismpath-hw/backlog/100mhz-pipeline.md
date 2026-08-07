# Backlog: 100 MHz fabric clock — overlap program fetch and atom evaluation

*Status: deferred by design (2026-08-06). v0 shipped at 50 MHz with a working prototype the
same night; this is the measured, well-scoped upgrade. Labels if this lands on GitHub:
`enhancement`, `rtl`, `help-wanted`, `good first FPGA issue`.*

## Current state (measured, Vivado 2023.2, xc7z020clg400-1)

- v0 (`rtl/ppt_interp.sv`) evaluates one program word per cycle, fully combinationally:
  in `S_RUN`, the cycle does **prog-word fetch → atom-row lookup → field-register read →
  32-bit signed compare → stack write**, all between two clock edges.
- At 100 MHz that path misses by **5.23 ns** (WNS −5.230, 18 failing endpoints).
- Shipped at **50 MHz**: WNS +1.623, timing clean. Evaluate latency 5–21 cycles on
  `incident_severity` ⇒ **100–420 ns worst case**.
- Resources: 1,064 LUTs (2.0%), 995 FFs, 0.5 BRAM tile — area is not a constraint.

## The upgrade

Split `S_RUN` into a classic two-stage overlap:

- **Stage F**: fetch `prog[paddr]` and register the addressed atom row
  (`atom_field/op/ty/val`) — everything indexed by the program word.
- **Stage E**: field-register read, comparison, stack operation — everything that consumes
  the registered atom row.

There are **no hazards to resolve**: within an edge program the program counter advances
unconditionally (no branches), and stage E's stack write never feeds stage F's address
computation. So words stream through the pipe back-to-back — cycle count grows by only
~1 fill cycle per edge program, while the critical path halves. Expected result:
**~6–23 cycles at 100 MHz ⇒ roughly 60–230 ns worst case** — a true ~2× latency win, not
a wash.

Scope: `rtl/ppt_interp.sv` only (the `S_RUN` state and the `atom_true` function's inputs);
roughly 30 lines. The AXI wrapper, compiler, image format, and testbenches are untouched.

Related-but-separate (do not bundle): infer true block RAM for the table memories instead
of register arrays — a resource-shape question, worthless until a flow outgrows LUTRAM.

## Acceptance gates (the definition of done — all must hold)

1. `make -C tb` — RTL conformance: **114 predicate + 6 engine vectors, zero divergence**
   (the frozen corpus is the spec; any drift is a regression, not a tradeoff).
2. `make -C tb` sensor replay: **7,436 samples, zero mismatches**, and record the new
   min–max cycle counts in the day log.
3. `make -C tb/axi` — AXI replay still green.
4. `vivado/build_overlay.tcl` with `PCW_FPGA0_PERIPHERAL_FREQMHZ {100}`: **WNS ≥ 0**,
   zero failing endpoints; commit the new `timing.rpt`/`utilization.rpt`.
5. README latency/clock numbers updated — never state a bound the reports don't back.

## Why it matters (SBIR framing)

The headline moves from "sub-microsecond" to **"sub-quarter-microsecond worst-case policy
decisions, formally bounded"** — for ~an afternoon of RTL. WCET at 100 MHz on a $65-class
part is the number that makes the software-framework comparison unanswerable, and the
2%-of-die area figure means the claim scales to the SU35P Sentinel target with room for
the entire cryptographic stack beside it.
