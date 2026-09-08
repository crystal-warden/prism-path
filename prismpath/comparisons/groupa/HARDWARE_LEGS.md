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
| RP2350 ARM and RISC-V | pending, no board attached | |
| Zynq-7020 fabric | pending, board via the Protectli jump | |
| LA2016 WCET on pins for these two images (A7) | pending, analyzer and board | |

The corpus is `results/prismpath/evidence/A3/a3.packets.bin` (23 records) with the two compiled
images beside it (`network_admission.ppt` 168 B and `sensor_interlock.ppt`; sha256 prefixes in
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

The signed bound for each image is already in the A7 result notes (`wcet_cycles` from the compiled
image; network_admission is 35 cycles, 700 ns at 50 MHz). The pins witness follows ledger #122/#123:
load the signed pack with `dp_load.py`, tap Pmod JB with the LA2016 at 200 MSa/s, sweep every scenario
input, and check the maximum busy window against the signed bound with `la_wcet_check.py`. Freeze the
verdict record to results/prismpath/evidence/A7/. If the witness cannot be taken, `groupa/a7.py`'s
PrismPath grade drops to WITH-WORK per its own notes.

## OPA WebAssembly on an MCU (the comparator attempt)

Module facts are recorded (results/opa/evidence/A3/wasm_module_facts.json). The attempt named for the
hardware session: WAMR (wasm-micro-runtime) on ESP-IDF on an ESP32-S3 with PSRAM, loading
policy.wasm, providing the 7 OPA imports, and calling the OPA wasm ABI (`opa_eval_ctx_new`,
`opa_json_parse`, `opa_eval`) for one scenario input. Record: whether it links, RAM at load, whether
the evaluation completes, and the decision. On the ESP-WROOM-32 the numbers in the notes say it
does not fit; measure rather than assert if a WROOM is what is attached.
