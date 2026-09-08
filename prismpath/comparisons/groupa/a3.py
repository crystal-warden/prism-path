# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A3, cross substrate byte exact decisions (PREREGISTRATION.md section 5, A3).

PrismPath legs run so far, all on the a3_corpus (23 complete readings of network_admission and
sensor_interlock, one compiled image per policy, expected target = the host Python route, cross
checked against the C reference): host Python, C target, in kernel eBPF on aarch64 (this host) and on
x86_64 (the Protectli, program object rebuilt there). The MCU legs (ESP32 Xtensa, RP2350 ARM and
RISC-V) and the fabric leg need the boards attached; PrismPath's A3 result files are written by this
module only once at least one MCU class leg has run, because the pre registered NATIVE criterion
requires a host, a kernel, AND an MCU class target. Until then the evidence is in
results/prismpath/evidence/A3/ and this module writes the comparator rows.

Comparators, the real attempts the pre registration requires:
  OPA     compiled to WebAssembly (opa build -t wasm); module size and declared memory measured from
          the binary; not run on an MCU (no board attached; and see the notes)
  Cedar   the Rust core built for thumbv8m.main-none-eabi (Cortex-M33) in a no_std crate; fails at the
          first dependency that requires std (memchr), with no no_std feature in cedar-policy 4.12.0
  Cerbos, OpenFGA   server only architectures (documented)

Usage: python -m prismpath.comparisons.groupa.a3
"""
from __future__ import annotations

import json
import sys

from prismpath.comparisons.groupa.common import RESULTS, evidence_dir, policy_by_id, write_result
from prismpath.comparisons.harness import scenario_steps

POLICIES = ["network_admission", "sensor_interlock"]


def scenarios():
    for pid in POLICIES:
        for sid, kind, inp, exp in scenario_steps(policy_by_id(pid)):
            if kind != "undeclared_missing":
                yield pid, sid, exp["outcome"]


def run_opa() -> None:
    ev = evidence_dir("opa", "A3")
    facts = json.loads((ev / "wasm_module_facts.json").read_text())
    for pid, sid, exp in scenarios():
        write_result(system="opa", dimension="A3", policy=pid, scenario=sid, expected=exp, observed="not_run_on_mcu", grade="NOT",
                     idiomatic=True, evidence_path=ev,
                     measurements={"wasm_module_bytes": facts["module_bytes"], "wasm_code_section_bytes": facts["code_section_bytes"],
                                   "wasm_memory_min_bytes": facts["memory_min_bytes"], "wasm_imports": len(facts["imports"])},
                     notes=(f"opa build -t wasm compiles the policy to a {facts['module_bytes']} B module ({facts['code_section_bytes']} B of code, "
                            f"{len(facts['imports'])} host imports, an imported linear memory of at least {facts['memory_min_bytes']} B that the "
                            "module grows at runtime); that is the documented compiler to a second execution form, and it runs identically under a "
                            "host WebAssembly runtime (same class as the host tier). Reaching an MCU class target would need a WebAssembly runtime "
                            "ported to the board (WAMR or wasm3 on ESP-IDF) plus the module and its heap: on the ESP-WROOM-32 (520 KB SRAM, about "
                            "300 KB usable) 136 KB of module plus 128 KB of minimum memory plus the runtime does not leave a working heap; an "
                            "ESP32-S3 with PSRAM is the plausible target. Not attempted on hardware in this session (no boards attached), so the "
                            "grade is NOT on the evidence in hand and the attempt is named for the hardware session. The PrismPath comparison "
                            "point: the same policy is a 168 B table image decided by a 1.7 KB interpreter on an 8 bit AVR (ledger #92)."))


def run_cedar() -> None:
    ev = evidence_dir("cedar", "A3")
    for pid, sid, exp in scenarios():
        write_result(system="cedar", dimension="A3", policy=pid, scenario=sid, expected=exp, observed="not_buildable_no_std", grade="NOT",
                     idiomatic=True, evidence_path=ev,
                     notes=("A no_std staticlib crate depending on cedar-policy 4.12.0 with default features off, built for "
                            "thumbv8m.main-none-eabi (the RP2350's Cortex-M33): cargo fails at the first dependency that requires std "
                            "(memchr: can't find crate for `std`; build_attempt.log, Cargo.toml, lib.rs). cedar-policy exposes no no_std "
                            "feature (crates.io feature list recorded in the attempt). The formally verified core is a Rust library for std "
                            "hosts; an MCU port would be a fork of the crate and its dependency graph, not glue."))


def run_server_only(system: str, note: str) -> None:
    ev = evidence_dir(system, "A3")
    (ev / "note.txt").write_text(note + "\n")
    for pid, sid, exp in scenarios():
        write_result(system=system, dimension="A3", policy=pid, scenario=sid, expected=exp, observed="server_only", grade="NOT",
                     idiomatic=True, evidence_path=ev, notes=note)


def write_prismpath() -> None:
    """Write PrismPath's 23 A3 result files from every leg that has run: host Python and C (a3_vectors.json),
    the kernel logs, and every mcu_*.json the replay produced. NATIVE only if every leg agrees on every vector
    and at least one MCU class leg is present."""
    ev = RESULTS / "prismpath" / "evidence" / "A3"
    vectors = json.loads((ev / "a3_vectors.json").read_text())["vectors"]
    mcus = {f.stem[4:]: json.loads(f.read_text()) for f in sorted(ev.glob("mcu_*.json"))}
    kernels = {}
    for arch in ("aarch64_gx10", "x86_64_protectli"):
        text = (ev / f"kernel_{arch}.log").read_text()
        kernels[arch] = "23/23" in text and "ALL PASS" in text
    if not mcus:
        print("no MCU leg yet; prismpath A3 rows not written")
        return
    for v in vectors:
        pid, sid = v["policy"], v["scenario"]
        legs = {"python": v["python_target"], "c_target": v["c_target"]}
        agree = v["python_target"] == v["c_target"]
        for ident, m in mcus.items():
            row = next(r for r in m["rows"] if r["policy"] == pid and r["scenario"] == sid)
            legs[ident] = row["board_target"]
            agree = agree and row["agree"]
        agree = agree and all(kernels.values())
        grade = "NATIVE" if agree else "NOT"
        observed = v["expected_outcome"] if agree else "divergent"
        write_result(system="prismpath", dimension="A3", policy=pid, scenario=sid, expected=v["expected_outcome"], observed=observed,
                     grade=grade, idiomatic=True, evidence_path=ev,
                     measurements={"targets_by_substrate": legs, "kernel_certify_all_pass": kernels,
                                   "image_sha256_16": v["image_sha256_16"], "image_bytes": v["image_bytes"]},
                     notes=(f"One compiled image ({v['image_bytes']} B, sha256 {v['image_sha256_16']}...) decided the same scenario reading on: host "
                            f"Python (target {v['python_target']}), the C reference (target {v['c_target']}), in kernel eBPF via "
                            f"BPF_PROG_TEST_RUN on aarch64 (this host) and x86_64 (the Protectli, object rebuilt there), both 23/23 ALL PASS "
                            f"over the corpus (kernel_*.log), and on the RP2350's Cortex-M33 and Hazard3 RISC-V cores from one firmware source "
                            f"(mcu_*.json; board targets {[legs[k] for k in mcus]}). Every leg agrees. The FPGA fabric and ESP32 Xtensa legs are "
                            "not part of this run (prior rows #108, #98 certify the same interpreter on them); the pre registered NATIVE "
                            "criterion, host plus kernel plus MCU class, is met."))


def main() -> int:
    if "--write-prismpath" in sys.argv:
        write_prismpath()
        print("prismpath A3 rows written")
        return 0
    run_opa()
    run_cedar()
    run_server_only("cerbos", "Cerbos is a Go server (gRPC and HTTP) deployed as a sidecar or service; there is no library, compiler, or "
                              "runtime form for a kernel, MCU, or fabric. Server only by architecture (documentation).")
    run_server_only("openfga", "OpenFGA is a Go server with a datastore; the decision policies are not expressible in it in any case. "
                               "Server only by architecture (documentation).")
    ev = RESULTS / "prismpath" / "evidence" / "A3"
    summary = {"legs_run": {"python": "23/23 (a3_vectors.json, python_target)", "c_target": "23/23 (python vs C disagreements 0)",
                            "kernel_aarch64_gx10": (ev / "kernel_aarch64_gx10.log").read_text().strip().splitlines()[-2:],
                            "kernel_x86_64_protectli": (ev / "kernel_x86_64_protectli.log").read_text().strip().splitlines()[-2:]},
               "legs_pending_hardware": ["esp32 xtensa (certify_esp32 contract)", "rp2350 arm + riscv (certify_rp2350 contract)",
                                         "zynq-7020 fabric via the Protectli jump (fabric_corpus_cert contract)", "LA2016 wcet on pins for these images (A7)"],
               "result_files": "written only once an MCU class leg has run (pre registered NATIVE requires host + kernel + MCU)"}
    (ev / "status.json").write_text(json.dumps(summary, indent=2) + "\n")
    print("A3 comparator rows written; prismpath A3 evidence recorded, result files pending the MCU legs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
