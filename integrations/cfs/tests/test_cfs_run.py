# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The app's receipts (work package S2), held to the Python reference with no cFS build.

The receipt module (fsw/src/prismpath_app_run.c) and the decision core are compiled alone with the host's C
compiler, OpenSSL's SHA-256 (merkle.h's default) and the Monocypher prismpath-hw/mesh vendors, and driven by
tests/run_check.c through stdio instead of OSAL. Checked:

  * the policy table's C layout and initializer are the bytes the ground signs (ground/table.py);
  * every receipt line the C writes is the line the reference writes for the same payload, byte for byte, and the
    accumulator's root is the RFC 6962 root the Python computes over the same leaves;
  * the run directory the C writes, with the root statement it signed, passes the repository's verifier with both
    keys pinned and every receipt replayed (`core_evidence.verify`, and `prismpath evidence verify` itself);
  * the state the Critical Data Store holds round trips: a run with a simulated processor reset (state copied out,
    memory scribbled, torn writes left on the files) writes the same bytes as a run without one;
  * an older signed image, a tampered one, one signed by another key and an unsigned one are refused with their
    registered causes.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from integrations.cfs.ground import downlink, provision, reference, table
from integrations.cfs.prismpath_app.policy import gen_image
from integrations.cfs.tests import run_scenario
from prismpath.agent.policy import Policy
from prismpath.ledgers import core_evidence, root_statement

HERE = Path(__file__).resolve().parent
APP = HERE.parent / "prismpath_app"
REPO = HERE.parents[2]
MONO = REPO / "prismpath-hw" / "mesh" / "main"
TIME_US = 1_234_567_890_123_456


def _cc():
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if cc is None:
        pytest.skip("no C compiler")
    return cc


def _includes():
    return ["-I", str(REPO / "prismpath-hw"), "-I", str(REPO / "prismpath-ebpf"), "-I", str(MONO),
            "-I", str(APP / "fsw" / "inc"), "-I", str(APP / "fsw" / "src"), "-I", str(APP / "fsw" / "tables")]


@pytest.fixture(scope="module")
def run_check(tmp_path_factory):
    cc = _cc()
    work = tmp_path_factory.mktemp("run_check")
    probe = subprocess.run([cc, "-x", "c", "-", "-lcrypto", "-o", str(work / "probe")],
                           input="#include <openssl/sha.h>\nint main(void){return 0;}", capture_output=True, text=True)
    if probe.returncode != 0:
        pytest.skip("no OpenSSL development files (merkle.h's SHA-256 is OpenSSL's by default)")
    exe = work / "run_check"
    flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-g", "-O1"]
    ubsan = subprocess.run([cc, "-fsanitize=undefined", "-x", "c", "-", "-o", str(work / "p")],
                           input="int main(void){return 0;}", capture_output=True, text=True)
    if ubsan.returncode == 0:
        flags += ["-fsanitize=undefined", "-fno-sanitize-recover=undefined"]
    subprocess.run([cc, *flags, *_includes(), "-o", str(exe), str(HERE / "run_check.c"), str(MONO / "monocypher.c"),
                    str(MONO / "monocypher-ed25519.c"), "-lcrypto"], check=True)
    return exe


@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    pytest.importorskip("cryptography", reason="signing and verifying a core run needs the signing extra")
    out = tmp_path_factory.mktemp("keys")
    core_evidence.ensure_keys(out)
    return out


def _core() -> bytes:
    return gen_image.CORE.read_bytes().rstrip(b"\n")


def _signed(keys: Path, version: int = None, authority: Path = None) -> bytearray:
    data = table.pack(gen_image.build(_core()))
    if version is not None:
        table.set_version(data, version)
    table.sign(data, authority or keys / "authority.key")
    return data


def _payloads():
    """The S1 scripted sequence, every truncation of one payload, and a grid across the policy's thresholds."""
    out = [case if isinstance(case, bytes) else run_scenario.reading_payload(case) for _n, case in run_scenario.SEQUENCE]
    whole = run_scenario.reading_payload(dict(cmd_class=2, ground_contact=1, slew_deg=10, thrust_pct=60))
    out += [whole[:n] for n in range(len(whole) + 1)]
    for cls in (0, 1, 2, 3, 4, 11):
        for gc in (0, 1, 2):
            for slew in (0, 46, 91, 181):
                for thrust in (0, 51, 101, 201):
                    out.append(run_scenario.reading_payload(dict(cmd_class=cls, ground_contact=gc, slew_deg=slew,
                                                                 thrust_pct=thrust)))
    return out


def _run(run_check, tmp: Path, keys: Path, name: str, payloads, extra=()):
    out = tmp / name
    out.mkdir()
    (tmp / "table.bin").write_bytes(bytes(_signed(keys)))
    (tmp / "authority.raw").write_bytes((keys / "authority.pub").read_bytes())
    (tmp / "instance.seed").write_bytes(provision.instance_seed(keys / "instance.key"))
    (tmp / "payloads.txt").write_text("".join(p.hex() + "\n" for p in payloads))
    done = subprocess.run([str(run_check), str(out), str(tmp / "table.bin"), str(tmp / "authority.raw"),
                           str(tmp / "instance.seed"), str(tmp / "payloads.txt"), str(TIME_US), *extra],
                          capture_output=True, text=True)
    assert done.returncode == 0 and "run_check: all checks passed" in done.stdout, done.stdout + done.stderr
    return downlink.fetch(out, tmp / f"{name}.ground"), done.stdout


# ----------------------------------------------------------------- the table's layout
def test_the_table_layout_and_initializer_are_the_bytes_the_ground_signs(tmp_path):
    cc = _cc()
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    (stubs / "cfe_tbl_filedef.h").write_text("#define CFE_TBL_FILEDEF(a, b, c, d)\n")
    (stubs / "prismpath_app_msg.h").write_text('#include "prismpath_app_kernel.h"\n'
                                                "typedef PP_PolicyTable_t PRISMPATH_APP_PolicyTable_t;\n")
    members = ", ".join(f'(unsigned)offsetof(PP_PolicyTable_t, {name})' for name in table.OFF)
    probe = tmp_path / "probe.c"
    probe.write_text("#include <stdio.h>\n#include <stddef.h>\n#include \"prismpath_app_policy_tbl.c\"\n"
                     "int main(int argc, char **argv) {\n"
                     f"    unsigned off[] = {{{members}}};\n"
                     "    unsigned i;\n"
                     "    for (i = 0; i < sizeof(off) / sizeof(off[0]); i++) printf(\"%u \", off[i]);\n"
                     "    printf(\"%u\\n\", (unsigned)sizeof(PP_PolicyTable_t));\n"
                     "    FILE *f = fopen(argv[1], \"wb\"); fwrite(&PolicyTable, sizeof(PolicyTable), 1, f); fclose(f);\n"
                     "    return argc == 2 ? 0 : 1;\n}\n")
    exe = tmp_path / "probe"
    subprocess.run([cc, "-std=c11", "-Wall", "-Werror", "-I", str(stubs), *_includes(),
                    "-o", str(exe), str(probe)], check=True)
    out = subprocess.run([str(exe), str(tmp_path / "struct.bin")], capture_output=True, text=True, check=True).stdout
    numbers = [int(x) for x in out.split()]
    assert numbers[:-1] == list(table.OFF.values()) and numbers[-1] == table.SIZE
    assert (tmp_path / "struct.bin").read_bytes() == bytes(table.pack(gen_image.build(_core())))


# ----------------------------------------------------------------- receipts, root, verifier, reset
def test_the_c_receipts_are_the_references_and_the_run_verifies_with_both_keys_pinned(run_check, tmp_path, keys):
    payloads = _payloads()
    out, stdout = _run(run_check, tmp_path, keys, "run", payloads)
    policy = Policy(_core())
    lines = core_evidence._lines(out / "receipts.jsonl")
    assert len(lines) == len(payloads)
    for idx, (line, payload) in enumerate(zip(lines, payloads)):
        assert line == reference.receipt_line(policy, idx, f"v{gen_image.VERSION}", idx, payload), \
            f"receipt {idx} for payload {payload.hex()}"
    leaves = [core_evidence.sha256_hex(line) for line in lines]
    root = root_statement.merkle_root(leaves)
    assert f"receipts {len(payloads)} cases 1 root {root}" in stdout
    # the reference's own accumulator over the same leaves agrees, the streaming form the C keeps
    acc = root_statement.MerkleAccumulator()
    for leaf in leaves:
        acc.add(leaf)
    assert acc.root() == root

    summary = downlink.verify(out, keys)
    assert summary["receipts"] == len(payloads) and summary["agree"] == len(payloads) and summary["disagree"] == 0
    assert summary["root_statement"] == "signed" and summary["root"] == root
    assert summary["roots"] == [{"leaves": len(payloads), "root": root, "time_us": TIME_US}]
    cli = subprocess.run([sys.executable, "-m", "prismpath", "evidence", "verify", str(out), "--sample", "all",
                          "--pin-authority", str(keys / "authority.pub"), "--pin-instance", str(keys / "instance.pub")],
                         capture_output=True, text=True, cwd=REPO)
    assert cli.returncode == 0, cli.stdout + cli.stderr
    assert "verified" in cli.stdout


def test_a_processor_reset_continues_the_run_byte_for_byte(run_check, tmp_path, keys):
    payloads = _payloads()
    straight, _ = _run(run_check, tmp_path, keys, "straight", payloads)
    reset, stdout = _run(run_check, tmp_path, keys, "reset", payloads, ["--reset-at", "13"])
    assert "reset simulated before payload 13: 13 receipts restored" in stdout
    for name in sorted(p.name for p in straight.iterdir()):
        assert (reset / name).read_bytes() == (straight / name).read_bytes(), name
    downlink.verify(reset, keys)


def test_an_older_tampered_or_unsigned_table_is_refused_with_its_cause(run_check, tmp_path, keys):
    other = tmp_path / "other"
    core_evidence.ensure_keys(other)
    older = _signed(keys, version=gen_image.VERSION - 1)
    same_version_other_bytes = _signed(keys)
    same_version_other_bytes[table.OFF["Image"] + 56] ^= 0x01        # thrust > 100 becomes > 101, then signed: another table at v2
    table.sign(same_version_other_bytes, keys / "authority.key")
    tampered = _signed(keys)
    tampered[table.OFF["Image"] + 56] ^= 0x01                         # the same threshold, not signed again
    foreign = _signed(keys, authority=other / "authority.key")
    unsigned = table.pack(gen_image.build(_core()))
    broken = _signed(keys)
    broken[table.OFF["Image"] + 28] = 0x7F                            # atom 0's field index: the kernel's own check
    cases = [("older", older, 9), ("same-version", same_version_other_bytes, 9), ("tampered", tampered, 2),
             ("foreign", foreign, 2), ("unsigned", unsigned, 2), ("broken", broken, 76)]
    extra = []
    for name, data, cause in cases:
        (tmp_path / f"{name}.bin").write_bytes(bytes(data))
        extra += ["--refuse", str(tmp_path / f"{name}.bin"), str(cause)]
    _run(run_check, tmp_path, keys, "refusals", _payloads()[:3], extra)
