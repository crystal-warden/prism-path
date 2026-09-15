# The RTL testbenches, one row each

*An index, not a walkthrough. Eight cocotb testbenches live in this directory and until now the only
way to learn what any of them claimed was to open its Makefile and its test module. The vocabulary is
[docs/DICTIONARY.md](../../docs/DICTIONARY.md); the image format every one of these modules executes is
[TABLE_FORMAT.md](../TABLE_FORMAT.md).*

## How to run one

Every Makefile here includes [gate.mk](gate.mk), and `gate` is the default target, so the command in
each row below runs the simulation **and judges it**. There is no longer a spelling of `make` in this
directory that runs a simulation without deciding whether it passed.

```sh
make -f Makefile.<name>          # the gate: run, then fail the build on any cocotb failure
make -f Makefile.<name> sim      # the simulation alone, for waveform work; see the warning below
```

You need `verilator` on the path and cocotb in the environment. From a checkout that uses the
repository's virtual environment, put its `bin` on `PATH` first.

**The warning that made gate.mk necessary.** `make sim` exits 0 even when a cocotb test fails: the
simulator finishes cleanly and cocotb records the failure in its results file, not in the exit code.
Almost every testbench Makefile in this repository once ended at `include Makefile.sim` with no gate,
so following the command printed in its own header gave a green build on broken hardware description.
Treat a bare `sim` as a rendering step and never as a pass or fail check.

Each gate writes `results.<name>.xml` and builds under `sim_build/<name>`, named per testbench so that
two testbenches in one directory cannot overwrite each other's evidence and a failure survives the next
run. The verdict is decided by [../tb/check_results.py](../tb/check_results.py), the same checker the
conformance gate uses, and a test that was renamed, skipped or never reached fails the gate rather than
passing quietly.

## The eight testbenches in this directory

| testbench | module under test | what it certifies | reference or corpus | scope | command | gates |
|---|---|---|---|---|---|---|
| `Makefile.ctrl` | `ctrl_in` | a bouncy button press yields exactly one debounced strobe, and switch inputs synchronize through cleanly | stimulus and expectations in `test_ctrl_in.py`; the debounce threshold is overridden to 8 for simulation speed | unit | `make -f Makefile.ctrl` | yes, test `debounce` |
| `Makefile.ctrlinterp` | `ppt_ctrl_interp` | a signed control table maps (profile, button) to an action, and the profile selects which of two baked modes is live, so one button means different things before and after a meta swap | expectations in `test_ppt_ctrl_interp.py`, against the baked control table in the module | unit | `make -f Makefile.ctrlinterp` | yes, test `ctrl_interp` |
| `Makefile.ctrlplane` | `ppt_ctrl_plane` composing `ppt_ctrl_interp` and `ppt_pack_loader` | pressing a button carries a signed policy through the loader and lands as the exact register writes the AXI face expects, with no processor in the loop, and the display only actions issue no writes at all | the expected write sequences are spelled out in `test_ppt_ctrl_plane.py` against the loader's mock pack | composition of two units | `make -f Makefile.ctrlplane` | yes, test `ctrl_plane` |
| `Makefile.fieldctrl` | `ppt_field_ctrl` | the control plane outputs shape the field and the LED correctly (source select, mute freeze, baseline bias, injection stepping, color override) and every one of those effects is gated off in the base profile | expectations in `test_ppt_field_ctrl.py` | unit | `make -f Makefile.fieldctrl` | yes, test `field_ctrl` |
| `Makefile.loader` | `ppt_pack_loader` | the fabric replays a baked policy's load writes onto the AXI slave in exactly the order and with exactly the values the processor would have written | the mock policies baked into the module's ROM, asserted against the sequences in `test_ppt_pack_loader.py` | unit, with a cocotb AXI write slave | `make -f Makefile.loader` | yes, test `loader` |
| `Makefile.receipt` | `ppt_receipt` through `uart_tx` and back through `uart_rx`, wired by the local `ppt_receipt_tb.sv` | every field of the 18 byte receipt record is faithful and the FNV-1a-32 digest chain is exact, so a passive off chip reader detects any altered or dropped receipt with no processor in the loop | five decisions driven by `test_ppt_receipt.py`, checked against an FNV-1a-32 chain the test computes in Python | unit plus its serial loopback | `make -f Makefile.receipt` | yes, test `receipts` |
| `Makefile.wmux` | `ppt_axi_wmux` | when the processor and the in fabric loader write at the same moment the loader wins first and the processor completes afterward, the choice held stable for a whole transaction, with no interleaving and no lost write | two mock masters and a mock slave in `test_ppt_axi_wmux.py` | unit | `make -f Makefile.wmux` | yes, test `wmux` |
| `Makefile.finale_hyst` | `ppt_datapath_finale`, the whole finale datapath: interpreter, AXI face, receipt path, codec, control plane, loader, write mux and field front end | the fabric native resident state machine settles on the same band the software references agreed on, at every event of a frozen corpus, and the stateless path on the same image is unchanged | the committed frozen corpus `../demo/flows/hyst_corpus.json`, 4,568 events across 41 streams, plus the `hyst_band` and `demo_input` policies and their signed manifests beside it | **full datapath**, the only one here | `make -f Makefile.finale_hyst` | yes, test `finale_hysteresis_corpus` |

Read the `scope` column first. Seven of the eight are unit testbenches: they instantiate one module,
drive its ports, and check its outputs against expectations written next to the stimulus in the test
file. `Makefile.finale_hyst` is different in kind. It instantiates the whole datapath, plays the
processor's role over the AXI face, replays the signed policy's exact load write sequence, mocks the
analog to digital converter over its debug port, and then lets the fabric free run exactly as silicon
does while it compares the resident band against a corpus committed to this repository. It is the only
testbench here that reads a corpus from a file, and therefore the only one whose claim is about
agreement with something outside the testbench.

That corpus is committed rather than fetched so that the gate runs from a clean checkout on any machine.
An external bench can still be pointed at through the `PRISMPATH_HW_BENCH` environment variable, but it
has to be asked for by name; it is no longer what the certification silently reads.

## The neighboring testbenches that share this gate

Two other directories hold cocotb testbenches. They are listed here because a reader looking for "every
testbench" should not have to find them by accident, and because
[gate.mk](gate.mk) is shared with one of them.

| testbench | module under test | what it certifies | reference or corpus | command | gates |
|---|---|---|---|---|---|
| `../tb/Makefile` | `ppt_interp` | the interpreter circuit reproduces the reference engine on every vector of the frozen conformance corpus, one fixed circuit with every policy loaded at run time as data | `prismpath/portable/conformance`, the same corpus and the same subset filter `run_vectors.py` applies to the C target | `make -C ../tb` | yes, its own gate rule, tests `conformance` and `sensor_log_replay` |
| `../codec-bench/rtl-tb/Makefile` | `zeck_enc` | the encoder reproduces the reference Zeckendorf encoding | the reference corpus generated from `prismpath.telemetry`, the same one the microcontroller bench used | `make -C ../codec-bench/rtl-tb` | yes, test `conformance` |
| `../codec-bench/rtl-tb/Makefile.dec` | `zeck_dec` | the decoder reproduces the reference decoding of that same corpus | as above | `make -C ../codec-bench/rtl-tb -f Makefile.dec` | yes, test `conformance` |
| `../codec-bench/rtl-tb/Makefile.codec` | `zeck_codec_core`, encoder wired to decoder | a value survives a round trip through the codec core | a sweep generated in the test | `make -C ../codec-bench/rtl-tb -f Makefile.codec` | yes, test `codec` |
| `../codec-bench/rtl-tb/Makefile.frame` | `zeck_frame_rx` over `zeck_dec` | the in fabric frame decoder recovers the band from a wire carrying a coded record, with the inter record gap parameterized for simulation | frames built in the test | `make -C ../codec-bench/rtl-tb -f Makefile.frame` | yes, test `frames` |

`../tb` carries its own gate rule rather than including `gate.mk`, for the historical reason that it was
the only gate that ever existed; its behavior is the same, and `check_results.py` lives there and is
what every other gate calls.

## Adding a testbench

Write the Makefile as the others are written, set `GATE_NAME` to one short word and `GATE_EXPECTED` to
the cocotb test names that must appear in the results, and `include gate.mk` **before**
`include Makefile.sim`. The order matters: cocotb's own fragment defaults the results file and the build
directory with `?=` and immediately writes rules whose targets expand them, so an override read
afterwards would move neither. `gate.mk` refuses to be included without both variables set, and it
names itself in the error.
