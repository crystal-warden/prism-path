# A3 and A7 hardware legs, runbook

*What is left of Group A that needs hardware attached. Everything else in Group A has run.*

## State at the end of the software session

| leg | status | evidence |
|---|---|---|
| host Python | 23/23 | results/prismpath/evidence/A3/a3_vectors.json (python_target) |
| C target | 23/23, 0 disagreements with Python | same file (c_target, c_out) |
| kernel aarch64 (this host) | 23/23 in kernel | results/prismpath/evidence/A3/kernel_aarch64_gx10.log |
| kernel x86_64 (Protectli) | 23/23 in kernel, object rebuilt there | results/prismpath/evidence/A3/kernel_x86_64_protectli.log |
| ESP32 Xtensa | pending, no board attached | |
| RP2350 ARM and RISC-V | 23/23 each, one Pico 2 W flashed twice | results/prismpath/evidence/A3/mcu_ppt-rp2350_*.json |
| Zynq-7020 fabric | 23/23 on the resident finale overlay (attach, PS path) and 23/23 again on the tapped datapath overlay | results/prismpath/evidence/A3/fabric_finale_attach.log, fabric_datapath_run.log |
| LA2016 WCET on pins for these two images (A7) | PASS, network_admission 34 of 35 cycles over 224 evaluations, sensor_interlock 23 of 24 over 216 | results/prismpath/evidence/A7/pins_*.json |

The corpus is `results/prismpath/evidence/A3/a3.packets.bin` (23 records) with the two compiled
images beside it (`network_admission.ppt` 224 B and `sensor_interlock.ppt` 160 B; sha256 prefixes in
a3_vectors.json). PrismPath's A3 result files are written by `groupa/a3.py` only after an MCU leg
runs; the pre registered NATIVE criterion needs host plus kernel plus MCU.

## MCU legs

The existing certification scripts take the frozen predicate corpus; for A3 they need to take the
a3 vectors instead. Each script's contract is the same: stream a table with `L`, stream the
`encode_regs` payload with `V`, read back matched edge and target, compare with the expectation.

1. Plug in the board; confirm the port: `ls /dev/ttyUSB* /dev/ttyACM*`.
2. ESP32 (`prismpath-hw/esp/certify_esp32.py`) or RP2350 (`prismpath-hw/rp2350/certify_rp2350.py`,
   built once per ISA with `make arm` and `make riscv`): add a `--vectors` option that reads
   a3_vectors.json plus the two `.ppt` images and replays each record (table, regs payload from
   `ppt_compile.encode_regs(img, ctx, 0)`, expected target). Do not change the on device firmware;
   the wire protocol is unchanged.
3. Record the per vector target the board returns beside python_target and c_target; 23/23 equal is
   the pass. Save the run log under results/prismpath/evidence/A3/mcu_<ident>.log.
4. Then `python -m prismpath.comparisons.groupa.a3 --write-prismpath` (to be added: it should read the
   MCU logs and write the 23 A3 result files for prismpath with the per substrate targets in
   `measurements`, grade NATIVE only if every leg agrees).

## Fabric leg

Via the Protectli jump to the Arty Z7-20 (see memory: fpga-board-access). `prismpath-hw/fabric_corpus_cert.py`
loads each unique table into BRAM and evaluates on silicon; feed it the a3 records the same way as
the MCU scripts (a `--vectors` option). Quiesce any resident auto mode design first (`quiesce_zeck.py`
pattern, hwh derived addresses, never a blind MMIO probe).

## A7 pins witness

Taken 2026-09-09, both images PASS. The signed bound for each image is in the A7 result notes
(`wcet_cycles` from the compiled image; network_admission 35 cycles, sensor_interlock 24). The witness
followed ledger #122/#123 with the comparison corpus as the stimulus: the tapped `ppt_datapath.bit` was
loaded once on the board by `groupa/a3_fabric_run.py` (which also repeated the A3 leg, 23/23), then
`groupa/a7_sweep_only.py <policy> <seconds>` attached to the resident overlay without reconfiguring and
swept that policy's corpus readings continuously through the PS evaluate path, while on gx10
`groupa/a7_pins.py --policy <id> --bound <wcet> --iters 30` took 30 free run captures on Pmod JB with
the LA2016 (200 MSa/s, threshold passed to sigrok as the range literal `1.4-1.4`) and measured every
busy window with `la_wcet_check.measure` (edge count and width methods, 0 disagreements). Longest
windows: 34 cycles against the signed 35 (224 evaluations) and 23 against 24 (216 evaluations). One
process drives the fabric at a time; when a second driver was started by mistake for 37 seconds the
board survived, but kill by PID at once. `groupa/a7.py` reads `pins_<policy>.json` and grades NATIVE
on PASS, WITH-WORK when the file is absent, NOT on FAIL, so the grade is data driven.

The board's boot demo service (`prismpath-finale.service`) is disabled for this work, because it
configures the PL at boot and spends the one configuration budgeted per power cycle. Re enable it
when the board should self start the demo again.

## OPA WebAssembly on an MCU (the comparator attempt)

Module facts are recorded (results/opa/evidence/A3/wasm_module_facts.json). The attempt named for the
hardware session: WAMR (wasm-micro-runtime) on ESP-IDF on an ESP32-S3 with PSRAM, loading
policy.wasm, providing the 7 OPA imports, and calling the OPA wasm ABI (`opa_eval_ctx_new`,
`opa_json_parse`, `opa_eval`) for one scenario input. Record: whether it links, RAM at load, whether
the evaluation completes, and the decision. On the ESP-WROOM-32 the numbers in the notes say it
does not fit; measure rather than assert if a WROOM is what is attached.
