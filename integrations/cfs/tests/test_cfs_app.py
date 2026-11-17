# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The PrismPath cFS app (integrations/cfs/prismpath_app), held to the policy it runs.

Four things must not drift apart: the readable rules, the compiled image the C app loads, the reading layout the
C code assumes, and the decisions the kernel makes. The first three are checked here without a cFS build. The
kernel is compiled alone (it has no cFE in it) and compared with the Python reference decision path on a grid of
readings, and with every corruption of its image. The last test boots a native cFS build and plays the scripted
sequence end to end; it skips, saying why, when no cFS build with the app in it is staged.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from integrations.cfs.prismpath_app.policy import gen_image
from prismpath.agent.policy import Policy
from prismpath.kernel import policy_source

HERE = Path(__file__).resolve().parent
APP = HERE.parent / "prismpath_app"
REPO = HERE.parents[2]
POLICY = APP / "policy"
LAYOUT_H = APP / "fsw" / "inc" / "prismpath_app_layout.h"
MSG_H = APP / "config" / "default_prismpath_app_msg.h"
APP_C = APP / "fsw" / "src" / "prismpath_app.c"


def _core() -> bytes:
    raw = (POLICY / "example.core.json").read_bytes()
    assert raw.endswith(b"\n")
    return raw[:-1]


# ----------------------------------------------------------------- the policy and its image
def test_the_rules_source_compiles_to_the_committed_core_image():
    source = (POLICY / "example.rules.md").read_text(encoding="utf-8")
    assert policy_source.compile_source(source, "example.rules.md") + b"\n" == (POLICY / "example.core.json").read_bytes()


def test_the_cli_compiles_the_source_to_the_same_bytes():
    out = subprocess.run([sys.executable, "-m", "prismpath", "policy", "compile", str(POLICY / "example.rules.md")],
                         capture_output=True, cwd=REPO, check=True)
    assert out.stdout == (POLICY / "example.core.json").read_bytes()


def test_the_committed_table_include_is_what_the_generator_writes():
    assert (APP / "fsw" / "tables" / "prismpath_app_policy_image.inc").read_text() == gen_image.render_inc(
        gen_image.build(_core())), "run: python -m integrations.cfs.prismpath_app.policy.gen_image"


def test_every_rule_names_a_registered_cause():
    built = gen_image.build(_core())
    assert len(built["rules"]) == len(Policy(_core()).doc["rules"])
    for kind, cause in built["rules"]:
        assert (kind == 0) == (cause == 0)
        assert kind == 0 or gen_image.causes.name(cause) is not None


# ----------------------------------------------------------------- the reading layout the C code assumes
def _layout_rows():
    text = LAYOUT_H.read_text()
    rows = re.findall(r'X\(\s*(\d+),\s*"(\w+)",\s*(INT|BOOL|MONITOR),\s*(\d+),\s*(\d+),\s*(-?\d+),\s*(-?\d+)\s*\)', text)
    return [(int(reg), name, kind, int(off), int(width), int(lo), int(hi)) for reg, name, kind, off, width, lo, hi in rows]


def test_the_layout_lists_the_policys_fields_in_register_order_with_their_bounds():
    defs = gen_image.field_defs(Policy(_core()).doc)
    rows = _layout_rows()
    assert [r[1] for r in rows] == [d[0] for d in defs] == sorted(Policy(_core()).doc["fields"])
    for (reg, name, kind, _off, _width, lo, hi), (dname, dkind, dlo, dhi), index in zip(rows, defs, range(len(defs))):
        assert (reg, name, "bool" if kind == "MONITOR" else kind.lower(), lo, hi) == (index, dname, dkind, dlo, dhi), name
    text = LAYOUT_H.read_text()
    assert int(re.search(r"PRISMPATH_APP_FIELD_COUNT\s+(\d+)", text).group(1)) == len(defs)


def test_the_layout_offsets_are_disjoint_in_bounds_and_fit_their_fields():
    rows = _layout_rows()
    payload = int(re.search(r"PRISMPATH_APP_PAYLOAD_LEN\s+(\d+)", LAYOUT_H.read_text()).group(1))
    used = set()
    for _reg, name, _kind, off, width, lo, hi in rows:
        assert width in (1, 2) and lo >= 0, f"{name}: the kernel reads 1 or 2 byte unsigned fields"
        assert hi < 256 ** width, f"{name}: the maximum does not fit {width} byte(s)"
        span = set(range(off, off + width))
        assert not span & used, f"{name} overlaps another field"
        used |= span
        assert off + width <= payload
    assert payload % 2 == 0


def test_the_c_command_struct_puts_each_field_where_the_layout_says():
    """The message struct in default_prismpath_app_msg.h, laid out by C's own rules, against the layout table."""
    body = re.search(r"typedef struct\s*\{\s*CFE_MSG_CommandHeader_t CommandHeader;(.*?)\}\s*PRISMPATH_APP_ProposedCmd_t;",
                     MSG_H.read_text(), re.S).group(1)
    members = re.findall(r"\b(uint8|uint16)\s+(\w+);", body)
    offset, got = 0, {}
    for ctype, name in members:
        size = 1 if ctype == "uint8" else 2
        offset += (-offset) % size
        got[name] = (offset, size)
        offset += size
    snake = lambda camel: re.sub(r"(?<!^)(?=[A-Z])", "_", camel).lower()   # noqa: E731
    by_name = {snake(n): v for n, v in got.items()}
    for _reg, name, _kind, off, width, _lo, _hi in _layout_rows():
        assert by_name[name] == (off, width), f"{name}: struct {by_name.get(name)} vs layout {(off, width)}"
    # and the app's own compile time asserts say the same
    asserted = {snake(m): int(v) for m, v in re.findall(r"PAYLOAD_OFFSET\((\w+)\) == (\d+)", APP_C.read_text())}
    for _reg, name, _kind, off, _width, _lo, _hi in _layout_rows():
        assert asserted[name] == off, f"{name}: prismpath_app.c asserts offset {asserted.get(name)}, layout says {off}"


def test_the_layout_hash_the_c_computes_is_the_one_the_table_carries(tmp_path):
    """The C hashes the layout header's own text at run time; the generator hashes the policy's fields. Same number."""
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if cc is None:
        pytest.skip("no C compiler")
    probe = tmp_path / "probe.c"
    probe.write_text('#include <stdio.h>\n#include "prismpath_app_kernel.c"\n'
                     'int main(void) { printf("%08x\\n", PP_Kernel_LayoutHash()); return 0; }\n')
    exe = tmp_path / "probe"
    subprocess.run([cc, "-std=c11", "-I", str(REPO / "prismpath-hw"), "-I", str(APP / "fsw" / "inc"),
                    "-I", str(APP / "fsw" / "src"), "-o", str(exe), str(probe)], check=True)
    out = subprocess.run([str(exe)], capture_output=True, text=True, check=True).stdout.strip()
    assert int(out, 16) == gen_image.build(_core())["layout_hash"]


# ----------------------------------------------------------------- the kernel against the reference
def _vectors():
    policy = Policy(_core())
    contract = gen_image.causes.code("route:contract-violation")
    kinds = {"allow": 0, "refuse": 1, "escalate": 2}
    rows = []
    for cls in range(12):
        for gc in range(3):
            for slew in (0, 45, 46, 90, 91, 180, 181):
                for thrust in (0, 50, 51, 100, 101, 200, 201):
                    for mon in (0, 1):
                        if cls <= 10 and gc <= 1 and slew <= 180 and thrust <= 200:
                            decision = policy.decide(policy.reading_bytes(
                                dict(cmd_class=cls, ground_contact=bool(gc), monitor_ok=bool(mon), slew_deg=slew,
                                     thrust_pct=thrust)))
                            kind, cause = kinds[decision.kind], decision.cause_code or 0
                        else:                                 # outside a field's definition: the core's boundary
                            kind, cause = 1, contract
                        rows.append(f"{cls} {gc} {slew} {thrust} {mon} {kind} {cause}")
    return rows


def test_the_kernel_decides_like_the_python_reference_and_refuses_every_corrupted_image(tmp_path):
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if cc is None:
        pytest.skip("no C compiler")
    vectors = tmp_path / "vectors.txt"
    vectors.write_text("\n".join(_vectors()) + "\n")
    exe = tmp_path / "kernel_check"
    flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-g", "-O1"]
    probe = subprocess.run([cc, "-fsanitize=undefined", "-x", "c", "-", "-o", str(tmp_path / "p")],
                           input="int main(void){return 0;}", capture_output=True, text=True)
    if probe.returncode == 0:
        flags += ["-fsanitize=undefined", "-fno-sanitize-recover=undefined"]
    subprocess.run([cc, *flags, "-I", str(REPO / "prismpath-hw"), "-I", str(APP / "fsw" / "inc"),
                    "-I", str(APP / "fsw" / "tables"), "-I", str(APP / "fsw" / "src"),
                    "-o", str(exe), str(HERE / "kernel_check.c")], check=True)
    run = subprocess.run([str(exe), str(vectors)], capture_output=True, text=True)
    assert run.returncode == 0, run.stdout + run.stderr
    assert "all checks passed" in run.stdout


# ----------------------------------------------------------------- cFS, end to end
def _staged_cfs():
    exe = Path(os.environ.get("CFS_EXE_DIR") or REPO / ".cfs-build" / "cFS" / "build-native_std" / "exe" / "cpu1")
    if not (exe / "core-cpu1").exists():
        pytest.skip(f"no native cFS build staged at {exe}; see integrations/cfs/README.md")
    if "prismpath_app" not in (exe / "cf" / "cfe_es_startup.scr").read_text() or not (exe / "cf" / "pp_app_policy.tbl").exists():
        pytest.skip("the staged cFS build does not include the prismpath_app (startup script entry or table missing)")
    return exe


def test_the_scripted_sequence_gives_the_expected_events_in_a_native_cfs_run():
    exe = _staged_cfs()
    import socket
    for port in (1234, 2234):
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            pytest.skip(f"UDP port {port} is in use (another cFS running?)")
        finally:
            probe.close()
    from integrations.cfs.tests import run_scenario
    assert run_scenario.main(["--build-dir", str(exe)]) == 0
