# The FPGA Zeckendorf codec: the shift-register half of Phase C2

`README.md` describes the front half of C2: a portable C encoder measured byte-exact on four MCU ISAs.
This is the other half, the one that note called "the unbuilt half": the **native codec in the fabric**,
encode and decode, with no processor in the loop. It is built, simulated against the same reference the
MCU bench used, and synthesized for the Arty Z7-20. The on-silicon measurement is the last step and is
recorded at the bottom.

## The modules (`../rtl/`)

| module | role |
|---|---|
| `zeck_enc.sv` | bit-serial encoder: wire int `n` to F2..Fk bits + the self-framing terminator `1` |
| `zeck_dec.sv` | bit-serial decoder: the exact inverse, one wire int per code, `"11"` ends a code |
| `zeck_codec_core.sv` | wires `enc.out` straight into `dec.in`; a PEEK path and a self-test sweep |
| `zeck_codec_axi.sv` | AXI4-Lite face so the PS can start a run and read the tallies |
| `zeck_codec_top.v` | BD shim (the `s_axi_*` naming the ppt overlays use) |

Both enc and dec carry a 32 bit datapath with an F2..F46 ROM. Symbols are cell indices, small by
construction, so decode(encode(n)) == n holds across the whole symbol domain the wire ever sees.

**One silicon-only bug, caught by measuring.** The Fibonacci ROM was first written as an initial-block
loop `fib[j]=fib[j-1]+fib[j-2]`. That simulates correctly (sequential), but Vivado evaluates the RHS
against the un-updated array, so `fib[2..]` synthesized to 0. On the board the codec passed n=1,2
(which use the directly-assigned `fib[0]`,`fib[1]`) and failed from n=3 on. The table is now written out
as an explicit constant `localparam`. The pre-existing `zeck_enc.sv` carried the same latent bug; it had
never been synthesized, only simulated, which is exactly the "modeled not measured" gap this closes.

## Simulation conformance (`rtl-tb/`, cocotb + verilator)

Every test drives the same seed-42 corpus (64 typical + 64 stress events, four wire ints each) and the
same Python reference (`adapters/telemetry/zeckendorf.py` + `packed.py`) the MCU bench verified against.

| test | result |
|---|---|
| `test_zeck_enc.py` (existing) | encoder 128/128 events byte-identical to the reference wire |
| `test_zeck_dec.py` | decoder 128/128 events, 512 wire ints recovered exactly |
| `test_zeck_codec.py` | codec PEEK: fabric wire == reference AND decode == n for all probes; self-test sweep 300/300 round-trips, first_fail=0 |

```
make            # encoder
make -f Makefile.dec
make -f Makefile.codec
```

## Synthesis (Vivado 2023.2, xc7z020clg400-1, `vivado/build_overlay_zeck.tcl`)

PS7 + the codec's AXI slave, no board XDC (every pin is PS-side). Produces `ppt_zeck.bit` + `.hwh`.

- Clock: `clk_fpga_0` 50.000 MHz. **All user specified timing constraints are met.**
- Worst slack: WNS +11.868 ns, 0 failing endpoints (about 8 ns of the 20 ns period used, so the codec
  has generous headroom well past 50 MHz).
- Footprint: 962 LUTs (1.81%), 1004 FFs (0.94%), 0 BRAM, 0 DSP, 0 external IOB.

## Measuring it on silicon (`measure_zeck_codec.py`)

Loads the overlay and runs two checks on the physical fabric, then prints N/N:

1. **Self-test sweep** n=1..MAX entirely in the PL: decode(encode(n))==n, counted by the fabric.
2. **PEEK** of the seed-42 corpus values: the fabric's encoded wire bits must equal the reference AND
   the in-fabric decode must return n. The reference is inlined (no board deps) and cross-checked
   against `adapters/telemetry/zeckendorf.py` (0 mismatches over 1..2000).

```bash
# on the dev box: stage to the board
scp vivado/build_overlay_zeck/ppt_zeck.bit  xilinx@<board>:/home/xilinx/
scp codec-bench/measure_zeck_codec.py       xilinx@<board>:/home/xilinx/
# on the board:
sudo bash -c 'source /etc/profile.d/pynq_venv.sh; source /etc/profile.d/xrt_setup.sh; \
              source /etc/profile.d/boardname.sh; python3 /home/xilinx/measure_zeck_codec.py'
```

## On-silicon result (2026-08-22, Arty Z7-20, PYNQ)

Measured on the physical fabric with `measure_zeck_codec.py`:

```
[zeck] overlay up @ 0x40000000, MAGIC=ZCK1
[zeck] SELF-TEST on silicon: 1000000/1000000 round-trips decode(encode(n))==n  first_fail=0 err=0
[zeck] PEEK on silicon: wire 225/225 bit-exact vs reference; decode 225/225 == n
[zeck] === C2 MEASURED ON SILICON: PASS ===
```

- **1,000,000 / 1,000,000** in-fabric round-trips decode(encode(n))==n, first_fail=0.
- **225 / 225** corpus values: the fabric's encoded wire is bit-exact vs the reference, and the in-fabric
  decode returns n. (225 = the distinct wire ints in the seed-42 corpus the MCU bench used.)

C2's fabric codec is now **measured, not modeled**. The encoder was already benched byte-exact on four
MCU ISAs (`results.md`); the shift-register codec now runs and is verified on the Zynq PL itself, both
directions, no processor in the loop.
