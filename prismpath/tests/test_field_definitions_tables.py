# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The table targets agree with the engine on defined flows: comparisons on lowered thresholds and the
absent value (SPEC section 4.5).

Every accepted policy in the frozen field definition vectors is compiled to a PPT table by the shared
compiler and evaluated by the C reference interpreters, the one built from interp.c and the one built
from ppt_eval.h, the header the firmware targets and the eBPF evaluator's certification are held to. A
table never sees a decimal or a scale: the parser has lowered every threshold to an integer before the
compiler reads the graph, and an absent field reaches the table as a register of type none. Each probe
must take the route the engine took. The interpreters are built by `make -C prismpath-hw`, which CI's
substrates job runs before this test; elsewhere the test skips.
"""
import json
import subprocess
import sys

import pytest

from prismpath.kernel.parser import parse
from prismpath.tests._repo import repo_file

_hw = repo_file("prismpath-hw")
sys.path.insert(0, str(_hw))
import ppt_compile as pc  # noqa: E402

CORPUS = json.loads(repo_file("prismpath", "portable", "conformance", "field_definitions.json").read_text())
ACCEPTED = [policy for policy in CORPUS["policies"] if policy["accepted"]]
INTERPRETERS = ["interp", "interp_hdr"]


def _interpreter(name):
    path = _hw / "build" / name
    if not path.exists():
        pytest.skip(f"{path} is not built here (make -C prismpath-hw)")
    return path


@pytest.mark.parametrize("interpreter", INTERPRETERS)
@pytest.mark.parametrize("policy", ACCEPTED, ids=lambda policy: policy["name"])
def test_the_table_routes_every_probe_as_the_engine_does(policy, interpreter, tmp_path):
    binary = _interpreter(interpreter)
    graph = parse(policy["flow"])
    image = pc.compile_flow(graph)
    names = [name for name, _edges in image.nodes]
    table = tmp_path / "flow.ppt"
    table.write_bytes(image.serialize())
    for probe in policy["probes"]:
        registers = tmp_path / "regs.bin"
        registers.write_bytes(pc.encode_regs(image, probe["reading"], node_idx=names.index("s")))
        out = subprocess.run([str(binary), "eval", str(table), str(registers)],
                             capture_output=True, text=True, timeout=30).stdout.strip()
        route = names[int(out.split()[2])] if out.startswith("match") else None
        assert route == probe["route"], (policy["name"], probe["reading"], out)
