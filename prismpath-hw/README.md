# prismpath-hw — the FPGA sprint workspace

*A top-level target directory of the PrismPath repo, beside `prismpath-rs/` and
`prismpath-go/` — built off to the side during the FPGA sprint and landed after clearing the
repo's gates. The claim, delivered and measured: a **fixed circuit** routes any conformant
Level M flow loaded as a **BRAM table image** — the flow stays data all the way down to
silicon.*

## Layout

| file | role |
|---|---|
| [TABLE_FORMAT.md](TABLE_FORMAT.md) | PPT v1 image format + the declared v0 subset + engine-parity semantics |
| [ppt_compile.py](ppt_compile.py) | `compile --target table`: condition/flow → binary image + JSON debug view |
| [interp.c](interp.c) | the C target — behavioral twin of the future RTL, same images |
| [run_vectors.py](run_vectors.py) | certification: frozen conformance corpus → C target, subset-filtered with reasons |
| [compile_flows.py](compile_flows.py) | sweep every repo flow; images land in `build/flows/` |

```sh
make            # build the C interpreter
make cert       # certify against the conformance vectors  (THE day-1 gate)
python3 -W ignore compile_flows.py
```

## Day log

**Day 1 (2026-08-06).**
- PPT v1 format designed and frozen enough to build against (see TABLE_FORMAT.md).
- Compiler + C reference interpreter written; **certification green**: 114/114 in-subset
  predicate vectors, 6/6 in-subset engine vectors, byte-identical recompiles gated
  (the reproducible-compile leg of the demo proof stack).
- Chain desugar (SPEC §4.3 SHOULD) + host-tier skipping + reachable-only compilation widen
  the subset honestly; every excluded vector carries a machine-readable reason.
- Repo sweep: **8 of 23 flow files table-compile**, headline `wazuh_triage` = **302 bytes**
  (5 fields, 9 atoms, 12 nodes, 19 edges); sensor-demo `incident_severity` = 136 bytes.
  (Plan memo said 9/25 — accounting difference to reconcile, likely file-set definition.)
- Found + flagged upstream: `model_check._atom_reason` accepts `is`/`is not` as Level M while
  the evaluator rejects them (classifier/evaluator disagreement; background task chip filed).
- Windows Vivado probe pending SSH bring-up (PYNQ chosen for the PS
  runtime — table hot-reload over MMIO is the demo's `make deploy` spine).

**Day 2 (2026-08-06, same evening).**
- **Demo #1 BANKED**: live BNO086 fields routed by the certified C table interpreter running
  the untouched 136-byte `incident_severity` image — the same bytes the fabric will hold.
  Path: sensor → MCP2221A → patched adafruit stack → `bridge/field_bridge.py` (Mac) → TCP
  over the network → `bridge/route_live.py` (GB10) → `interp eval` → severity decision.
- The banked run (session 5, `build/live_route_log.ndjson`): 167s quiescent `watch`, then a
  hand-swing climbing the ladder in document order — `sev3_ticket` → `sev2_oncall` →
  `sev1_page` (held 20.9s, error_rate 100, peak 7.2g, 34 shake events) → decay to `watch`.
- Bring-up burned down five real failure modes, each now defended: breadboard jumpers
  (→ Qwiic), transient-missing sampling (→ fast poll + peak-hold), silent library hangs
  (→ SIGALRM read watchdog), frozen report cache (→ staleness detector + GP0 hardware
  reset), and MCP2221A HID saturation (→ sensor pinned at the proven 20 Hz report rate).
  This is the reliability stack the live single-take demo will stand on.
- Field mapping (worker-as-ADC): shake spike → `data_at_risk`, sustained handling →
  `user_facing`, peak |accel−g| scaled → `error_rate`. All derived from the accelerometer
  alone — the BNO086's classifier/shake report channels wedge on this transport.

**Days 3–4 crux (2026-08-06, same night — three days early).**
- **THE gate: PASSED, first run.** `rtl/ppt_interp.sv` (fixed interpreter circuit: runtime
  load port, field register file, comparator atoms, per-edge stack machine, priority
  encoder, saturating visits bank) is **RTL CONFORMANT under Verilator + cocotb: 114
  predicate + 6 engine vectors, zero divergence** — the same counts as the C target, one
  DUT build, every image loaded as data. `make -C tb` reproduces it.
- **Sensor-log replay**: all **7,436 live samples** from the banked Day-2 session routed
  through the simulated fabric reproduce the C target's decisions exactly — spec (Python)
  → C → RTL, three implementations, one behavior, physical data.
- **First latency numbers**: evaluate = **5–21 cycles** on `incident_severity` — the
  provable-WCET story, now measured (see Day 5 for the shipped clock).
- Toolchain note: cocotb pinned to 1.9.2 (2.x requires Verilator ≥ 5.036; apt has 5.020).
- **AXI-Lite wrapper proven same night**: `rtl/ppt_axi.sv` (register map in the header) with
  532 sensor samples replayed through real AXI bus transactions in cocotb (`make -C tb/axi`),
  zero mismatches. Day-5 kit ready: `vivado/build_overlay.tcl` builds `ppt_overlay.bit+.hwh`
  on the synthesis machine (PS7 preset extracted from the proven Feb design — see script header).
- Board staging done: JTAG chain verified from Vivado 2023.2 over SSH (`arm_dap_0` +
  `xc7z020_1`), PYNQ-Z1 v3.1.1 flashed to the 119 GB SD card and boot files verified.

**Day 5 build (2026-08-06, same night — run remotely on the synthesis machine over SSH).**
- **`ppt_overlay.bit` + `.hwh` built and timing-clean**: Vivado 2023.2 batch, Zynq PS
  configured from the Feb design's extracted 471-parameter preset (`vivado/ps7_preset.tcl`),
  interpreter attached as an AXI-Lite module reference (plain-Verilog shim `ppt_axi_top.v` —
  BD module refs refuse an SV top). Artifacts at `vivado/build_overlay/` on the
  synthesis machine (the certified pair is committed under `evidence/`).
- **Fabric clock 50 MHz** (100 MHz missed by 5.23 ns — the single-cycle atom path: prog word
  → atom row → field register → 32-bit compare; v1 improvement: one pipeline stage). At
  50 MHz: WNS **+1.623 ns**, 0/4455 failing, hold clean.
- **WCET, shipped numbers**: evaluate = 5–21 cycles → **100–420 ns worst case** on
  `incident_severity`. Resources: **1,064 LUTs (2.0%)**, 995 FFs (0.9%), 300 LUTRAM,
  0.5 BRAM tile — the whole interpreter is two percent of the XC7Z020.
- Remaining before the gate "board answers a memory-mapped evaluate": physical bring-up
  (SD in, JP4→SD, Ethernet, first PYNQ boot) — `pynq/BOARD_BRINGUP.md` is the checklist;
  `pynq/ppt_pynq.py` (hot-reload fabric router) + `deploy.sh` are ready.

**Days 6–7 first light (2026-08-07, ~01:00 — calendar day two of the sprint).**
- **ALL SIX definition-of-done gates: closed.** The board answered: PYNQ booted (located
  via the serial console; the board opened a reverse SSH tunnel out to the GB10 across the
  network), the overlay loaded, MAGIC read `"PPT1"` from silicon,
  the 136-byte repo flow was written into fabric over AXI, and live BNO086 fields (sensor
  now on the GB10 via MCP2221A — kernel hid_mcp2221 driver unbound in favor of the proven
  Blinka path) routed to decisions **in fabric at ~128 µs round-trip** (Linux+Python+tunnel
  included; the fabric evaluate itself is the measured 5–21 cycles).
- Evidence: `build/fabric_route_log.session1.ndjson` (pulled from the board) — **2,985
  samples routed in fabric**, round-trip min/median/max **89/96/202 µs**, and a
  hand-run choreography executed by the circuit: 252s of `watch`, then
  `sev3_ticket → sev2_oncall → sev1_page` climbing in 0.3s, peak deviation 5.0 m/s²
  crossing the shake threshold, decay back to `watch`.
- Ops notes: PYNQ v3 needs `sudo` + the pynq-venv env sourced; run the server from a
  subdir (a `~/pynq` source folder shadows the package); `xilinx` has NOPASSWD sudo
  configured; a direct-routing firewall rule is possible, but until then a board-initiated
  reverse SSH tunnel is the path.

**Day update (2026-08-12, negative-integer literals).**
- The predicate front end learned signed integer literals (`when x >= -1282`) as a first-class
  match-action atom — one shared `predicates.fold_unary_signs`, mirrored into the JS/Rust/Go twins;
  a sign on a float or a field stays out of the language. The frozen corpus went **v1 → v2**
  (1,067 → 1,079 cases). The `.ppt` format needed no change: `val` was always a signed `i32` that
  `interp.c` and the RTL already compare signed.
- **C target re-certified**: `make cert` → **124/1,079 predicate + 6/6 engine, zero divergence** (the
  10 new in-subset vectors are the negative-integer cases, byte-identical to the reference).
- **Fabric**: a compiled `x >= -1282` table (96 B) deployed via a signed, envelope-checked swap
  decided the boundary live — -1283 → low, -1282 → high, 0 → high — byte-conformant at ~100 µs,
  proving the silicon needs no change.
- **eBPF re-certified same day**: 124/124 in-kernel (`BPF_PROG_TEST_RUN`, table-per-vector) on BOTH
  aarch64 and x86_64, with the hardened loader; drop_mask-survives-swap and over-`MAX_*`-rejection
  smokes green on a live attach. (Ledger #90.)
- **Not yet earned**: the full **RTL** re-sweep to 124/1,079 is held for a hardware retest; until
  then the RTL stands at its 114/1,067 sweep. (Ledger #89.)

## Backlog

- [100 MHz fabric clock](backlog/100mhz-pipeline.md) — overlap prog fetch / atom eval;
  ~2× latency win for ~30 lines of RTL, acceptance gates included. Deferred deliberately;
  PR-sized on purpose.
