# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A3 corpus: the same two Level M policies (network_admission, sensor_interlock), compiled once by
the untouched table compiler, with every complete scenario reading framed the way the kernel
certification corpus frames its vectors (prismpath-ebpf/cert_corpus.py record format:
<s32 expected_target><u32 tbl_len><tbl><u32 pkt_len><pkt>). The expected target is the host Python
route (the translator's engine run) mapped to the image's node index, cross checked against the C
reference interpreter before anything reaches a kernel or a board.

Writes results/prismpath/evidence/A3/{a3.packets.bin, a3_vectors.json, <policy>.ppt}.

Usage: python -m prismpath.comparisons.groupa.a3_corpus
"""
from __future__ import annotations

import json
import socket
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from prismpath.comparisons.groupa.common import evidence_dir, policy_by_id
from prismpath.comparisons.harness import HERE, gen_dir_for, scenario_steps
from prismpath.comparisons.systems import prismpath as sys_pp
from prismpath.kernel.parser import parse

REPO = HERE.parent.parent
sys.path.insert(0, str(REPO / "prismpath-hw"))
import ppt_compile as pc  # noqa: E402

PPT_MAGIC = 0x4D545050
INTERP = REPO / "prismpath-ebpf" / "interp"
POLICIES = ["network_admission", "sensor_interlock"]


def frame_packet(node_idx, n_fields, regs_bytes):
    payload = struct.pack("<III", PPT_MAGIC, node_idx, n_fields) + regs_bytes
    eth = struct.pack("!6s6sH", b"\xff" * 6, b"\x02" * 6, 0x0800)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + 8 + len(payload), 0x1234, 0, 64, 17, 0,
                     socket.inet_aton("192.168.1.1"), socket.inet_aton("192.168.1.2"))
    udp = struct.pack("!HHHH", 12345, 9999, 8 + len(payload), 0)
    return eth + ip + udp + payload


def interp_target(ppt_bytes, regs_payload, tmp: Path):
    (tmp / "c.ppt").write_bytes(ppt_bytes)
    (tmp / "c.bin").write_bytes(regs_payload)
    out = subprocess.run([str(INTERP), "eval", str(tmp / "c.ppt"), str(tmp / "c.bin")], capture_output=True, text=True).stdout.strip()
    if out.startswith("match"):
        return int(out.split()[2]), out
    return -1, out


def main() -> int:
    ev = evidence_dir("prismpath", "A3")
    tmp = Path(tempfile.mkdtemp(prefix="a3_"))
    records = bytearray()
    vectors = []
    disagree = 0
    for pid in POLICIES:
        policy = policy_by_id(pid)
        gen = gen_dir_for("prismpath", pid)
        graph = parse((gen / f"{pid}.md").read_text())
        img = pc.compile_flow(graph)
        tbl = img.serialize()
        (ev / f"{pid}.ppt").write_bytes(tbl)
        node_names = list(graph.nodes)                       # image node order follows the parsed graph
        runner = sys_pp.Runner(policy, gen)
        for sid, kind, inp, exp in scenario_steps(policy):
            if kind == "undeclared_missing":
                continue
            ctx = {k: v for k, v in inp.items() if v is not None}
            d = runner.decide(ctx)
            py_target = node_names.index(json.loads(d.raw)["path"][-1]) if d.observed != "no_match" else -1
            regs_payload = pc.encode_regs(img, ctx, node_idx=0)
            c_target, c_out = interp_target(tbl, regs_payload, tmp)
            if c_target != py_target:
                disagree += 1
            pkt = frame_packet(0, len(img.fields), regs_payload[4:])
            records += struct.pack("<iI", py_target, len(tbl)) + tbl + struct.pack("<I", len(pkt)) + pkt
            vectors.append({"policy": pid, "scenario": sid, "expected_outcome": exp["outcome"], "python_target": py_target,
                            "python_node": node_names[py_target] if py_target >= 0 else None, "c_target": c_target, "c_out": c_out,
                            "image_sha256_16": __import__("hashlib").sha256(tbl).hexdigest()[:16], "image_bytes": len(tbl)})
    (ev / "a3.packets.bin").write_bytes(records)
    (ev / "a3_vectors.json").write_text(json.dumps({"vectors": vectors, "python_vs_c_disagreements": disagree}, indent=1) + "\n")
    print(f"a3 corpus: {len(vectors)} vectors, python vs C disagreements {disagree}, {len(records)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
