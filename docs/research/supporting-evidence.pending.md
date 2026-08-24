# Supporting Evidence · STAGING (pending rows)

*Append boundary for ledger overhauls (see `LEDGER_STANDARDS.md` §6). While a docs session overhauls
`supporting-evidence.md`, the **dev session appends new evidence rows here**, starting at the next
free number, instead of editing the main ledger. On merge, the docs session folds these into the
ledger with correct formatting and clears this file.*

*Format each row exactly per `LEDGER_STANDARDS.md` §1 (Claim / Method / Result + Honest scope /
Provenance) with a month granularity date. Next free number: **#123**.*

---

<!-- new rows go below this line -->

### #122 — DRAFT (evidence freeze pending): the signed WCET bound holds on silicon AND tracks the signed policy — LA2016 witnesses demo_input <=11 and demo_binary <=8 cycles on the pins (August 2026)

**Claim:** the per-policy WCET bound the authority signs is honored on the physical fabric pins, and it **tracks the signed policy** — swap the signed rule and the signed timing envelope swaps with it, and the silicon honors whichever is loaded, measured on the pins across the full input range. This is the third independent WCET witness (beside the CI theorem prover Z3/BMC and the RTL simulation), extended here to show the witness follows a hot-swap.

**Method:** a Kingst LA2016 logic analyzer taps the interpreter's own pins on Pmod JB — `wcet_tap = {fsm_start, core_done, core_busy, clk_fwd}` (JB1=W14=clk, JB2=Y14=busy, JB3=T11=done, JB4=T10=start, JB5=GND), sampled at 200 MSa/s = 4 samples/cycle on the 50 MHz fabric clock. Two independent per-evaluation cycle counts that must agree: (a) clk rising edges while `busy` is high (drift immune), (b) `busy` pulse width / samples-per-cycle (boundary stable). The method-agreement tolerance was corrected 3/4 -> 1.0 cycle to match the instrument's async 4-samples/cycle resolution (edge-count jitters +/-1 vs the stable width; 3/4 was tighter than the hardware can resolve; `la_wcet_check.py` commit `999b5e9`). Two SIGNED policies were loaded live on the tapped `ppt_datapath` overlay via `dp_load.py` and witnessed in turn: `demo_input` (3-band, signed `wcet_cycles=11`) then `demo_binary` (2-band, signed `wcet_cycles=8`). `sweep_wcet.py` drove repeated free-run captures across a manual pot sweep so the witness reached every branch (the sigrok build rejected `--trigger`; free-run still resolves complete busy windows for a max-cycle measurement).

**Result:** **WCET-ON-PINS PASS for both signed policies.** `demo_input`: worst-case busy window = **9 cycles** (deterministic width) with edge-count <=10, inside the signed **11**-cycle bound, over 9,644 evaluations on silicon. `demo_binary`: global max **7 cycles** across **23,886 evaluations** (branch-coverage histogram spanning the input range: counts at 2/3/4/5/6/7 cycles, peak at 6), inside the signed **8**-cycle bound. The witness **tracks the signed policy**: the same physical instrument, on the same bitstream, reports a different measured envelope for each loaded signed table — a different signed bound, both honored on the pins. **Honest scope:** one board, one bench session; captures were free-run (no hardware trigger); the edge-count method carries +/-1 async-sampling jitter at 4 samples/cycle (the width measure is the authoritative count). **EVIDENCE FREEZE PENDING (owner-gated):** today's `.sr` captures went to `/tmp` on gx10 and are NOT yet frozen — this row is a DRAFT and finalizes only after a clean re-capture on the tapped overlay is saved to `prismpath-hw/wcet-pins/evidence/` with a SHA256SUMS; the tap RTL change (`ppt_datapath.sv` `wcet_tap`) is re-certified 124/124 decision parity but not yet committed (owner-gated, see [[fpga-changes-need-hardware-retest]]); the wcet-pins tooling lives in the no-remote demo bench `~/cwprojects/prismpath-hw`.

**Provenance:** `prismpath-hw/wcet-pins/{la_wcet_check.py (commit 999b5e9), sweep_wcet.py, README.md}` (demo bench, no remote); the tap in `prismpath-hw/rtl/ppt_datapath.sv` (`wcet_tap`) + `datapath.xdc`; board Digilent Arty Z7-20 (Zynq-7020) + Kingst LA2016 on Pmod JB; signed policies `demo_input` (`wcet=11`) and `demo_binary` (`wcet=8`), Ed25519 authority key_id `d519348f`. Companion to the original single-policy witness [[wcet-on-pins-witness]] and the fabric hot-swap row #117. **Freeze the evidence before folding.**

---
