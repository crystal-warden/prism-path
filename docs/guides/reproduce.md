# Reproducing the formal and differential claims

`tools/reproduce.sh` reproduces PrismPath's formal proofs, differential harnesses, and frozen conformance suites from a fresh clone of the research repository. It runs the same commands that `.github/workflows/formal.yml` and `.github/workflows/ci.yml` execute in continuous integration, writes a step-by-step summary table with timings and the exact git commit hash to `.reproduce/REPRODUCE_REPORT.md`, and prints the table at the end of the run.

```bash
bash tools/reproduce.sh
```

To check that your machine has the required toolchains without building or running the suites:

```bash
bash tools/reproduce.sh --check-only
```

## Prerequisites

The script checks for these tools before starting and prints installation hints for anything missing:

- **Python 3.10+** with the `venv` module (`python3` or `$PYTHON`).
- **Rust toolchain** (`cargo` and `rustc`, 1.85+).
- **Lean 4 toolchain manager (`elan`)** with the toolchain pinned in `formal/lean-toolchain` (`leanprover/lean4:v4.33.1`).
- **Node.js** (`node`, v20+) for the JavaScript kernel and differential leg.
- **C compiler and Make** (`cc` and `make`) for the certified C table interpreter (`prismpath-hw/interp.c`, `prismpath-hw/ppt_eval.h`) and the userspace eBPF evaluator leg (`formal/diff/ebpf_batch.c`).
- **Go toolchain** (`go`, 1.22+) for the Go kernel conformance and differential leg.

## What is reproduced

1. **Isolated environment (`venv-install`)**: creates `.reproduce/venv` and installs the repository in editable mode along with `numpy`, `pytest`, and `cryptography`.
2. **Lean proofs and oracles (`lean-build`)**: fetches the Mathlib cache if needed and runs `cd formal && lake build`, compiling all proof modules (`formal/FQ` and `formal/Core`), evaluating every `#guard` bridge check against the frozen vectors, printing the axiom audit (`formal/FQ/Axioms.lean`), and building the `core-oracle` and `canon2-oracle` binaries.
3. **Core oracle smoke check (`core-oracle-smoke`)**: runs `.lake/build/bin/core-oracle` on the specification's example policy and readings (matching `.github/workflows/formal.yml`), verifying routing, range refusal, and `reading:not-canonical` refusal on non-canonical whitespace.
4. **Proof completeness check (`lean-no-sorry`)**: checks every `.lean` source file under `formal/FQ`, `formal/FQ.lean`, `formal/Core`, and `formal/Core.lean` for `sorry` or `admit` tactics and fails if any are present.
5. **Bridge vector regeneration (`lean-bridge-vectors`)**: runs `python formal/gen_vectors.py` and checks with `diff -q` that `formal/FQ/Vectors.lean` is byte-identical to a fresh generation from the frozen corpora.
6. **Differential harnesses (`differential-harnesses`)**: runs `PRISMPATH_REQUIRE_CORE_ORACLE=1 python -m pytest prismpath/tests/test_core_diff.py prismpath/tests/test_core_evidence.py -q`, driving `formal/diff/core_diff.py` across the compiled Lean oracle, Python reference, Rust port, JavaScript kernel, Go kernel, C table interpreter (`c-interp`), embedded C header (`c-hdr`), and userspace eBPF evaluator (`ebpf`), and verifying cross-language signed evidence runs (`formal/diff/core_evidence.py` and the Rust `core_evidence` verifier) with every receipt replayed through the oracle.
7. **Corpus consumer table check (`corpora-table-check`)**: runs `python tools/run_corpora.py --check` to verify that every frozen corpus under `prismpath/portable/conformance` and `prismpath/telemetry/conformance` has a valid consumer or explicit non-claim decision across all five implementations.
8. **All frozen corpora (`corpora-all`)**: runs `python tools/run_corpora.py`, executing every consumer test target across Python, Rust, JavaScript, Go, and the C hardware target (`make -C prismpath-hw cert`) with `PRISMPATH_REQUIRE_CROSS_LANGUAGE=1`.
9. **CI conformance and cross-language suites (`conformance-js`, `conformance-go`, `conformance-c-target`, `conformance-rust-cross-language`)**: runs the standalone JavaScript conformance runners and unit tests (`node --test` and `run_vectors.mjs`, `run_crypto_agility.mjs`, `test_portable_runners.py`, `test_conformance_vectors.py`), the Go kernel conformance suite (`cd prismpath-go && go test ./... -v`), the C target certification and lowered field-definition table checks (`make -C prismpath-hw cert` and `test_field_definitions_tables.py`), and the bidirectional Rust/Python cross-language host, pack, deferral store, and telemetry checks from `.github/workflows/ci.yml`.

## How long it takes

On a modern multi-core machine with a warm Mathlib cache (`lake exe cache get`), an end-to-end run takes **4 to 8 minutes**:

- Fetching and unpacking the prebuilt Mathlib `.olean` cache takes 1 to 3 minutes on the first run (depending on network and disk speed).
- Compiling `formal/FQ`, `formal/Core`, `core-oracle`, and `canon2-oracle` from scratch takes roughly 2 minutes once Mathlib is unpacked.
- The differential harnesses (`test_core_diff.py` and `test_core_evidence.py`), `tools/run_corpora.py`, and the cross-language conformance suites take 2 to 3 minutes combined.

## What is not covered and why

Steps that require root privileges, a live Linux kernel BPF subsystem, EDA synthesis tools, or physical boards are listed in `REPRODUCE_REPORT.md` as `NOT RUN` with the exact reason and are never faked or stubbed:

- **In-kernel eBPF loading and `BPF_PROG_TEST_RUN` (`ebpf-in-kernel`)**: `.github/workflows/ci.yml` (`ebpf_kernel` job) runs `sudo ./loader ... certify`, `facet_decode_cert.py`, `netcert`, and `collector/kernel_test.sh`. Loading BPF programs into the kernel requires `root` (`CAP_BPF` / `CAP_NET_ADMIN`) and a Linux kernel with BTF enabled (`/sys/kernel/btf/vmlinux`). Note that the eBPF evaluator's C code (`prismpath-ebpf/ppt_eval_bpf.h`) *is* tested on its userspace path in the `ebpf` leg of `core_diff.py`.
- **FPGA synthesis, bitstream generation, and PYNQ silicon replay (`fpga-silicon`)**: building `ppt_overlay.bit` requires Xilinx Vivado 2023.2, and hardware certification (`prismpath-hw/pynq/`, `prismpath-hw/hyst-cert/`) requires a physical Zynq-7020 board (Arty Z7-20 / PYNQ-Z1/Z2).
- **MCU on-device certification (`mcu-boards`)**: running `prismpath-hw/{avr,rp2350,esp}/certify_*.py` and the ESP-NOW mesh tests requires physical ATmega328P (Arduino Uno R3), RP2350 (Pico 2), ESP32, and ESP32-C6 boards attached over serial/USB plus their vendor cross-compilers (`avr-gcc`, Pico SDK, ESP-IDF).

## Reporting a discrepancy

If any step fails or produces a different result on your machine, open an issue on the repository and attach the generated `.reproduce/REPRODUCE_REPORT.md` along with the corresponding log file from `.reproduce/logs/` and the output of `uname -a`.
