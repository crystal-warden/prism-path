# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The XDP program's decision on its userspace path: prismpath-ebpf/gnet/gn_batch.c, built from the
program's own text (gn_xdp.h and ppt_eval_bpf.h) over a shim of the BPF facilities. THIS IS NOT THE
KERNEL: it runs no verifier and no JIT, and it is how this host, where unprivileged BPF is disabled, runs
the decision at all. SETUP.md has the in-kernel runs that confirm the same object loads and decides.

`Batch` decides a list of frames at once (the differential); `Stream` keeps one process open and decides
frames one at a time (the userspace gate in front of the tool server).
"""
from __future__ import annotations

import hashlib
import struct
import subprocess
from pathlib import Path
from typing import Iterable, List, NamedTuple, Optional, Tuple

from . import frame as fr
from . import protocol as p

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
EBPF = REPO / "prismpath-ebpf"
SOURCES = (EBPF / "gnet" / "gn_batch.c", EBPF / "gnet" / "gn_xdp.h", EBPF / "gnet" / "gn_common.h",
           EBPF / "gnet" / "gn_maps.h", EBPF / "ppt_eval_bpf.h", EBPF / "ppt_common.h", EBPF / "ppt_image.c",
           EBPF / "ppt_image.h")


class XdpDecision(NamedTuple):
    outcome: int
    reason: int
    edge: int
    cause: int
    emitted: int
    request_id: int
    cmd: int
    hclass: int
    arg0: int
    arg1: int
    name_len: int
    data_len: int
    handle: int
    image_index: int
    src_port: int
    src_ip: int

    def reading(self):
        """The reading the receipt logger rebuilds from a ring buffer event: the decided fields."""
        return {"version": 1, "cmd": self.cmd, "hclass": self.hclass, "arg0": self.arg0, "arg1": self.arg1,
                "name_len": self.name_len, "data_len": self.data_len}


def build(out_dir: Path) -> Path:
    """Compile gn_batch into `out_dir`, named by a digest of its sources so a stale binary is never used."""
    digest = hashlib.sha256(b"".join(path.read_bytes() for path in SOURCES)).hexdigest()[:16]
    binary = Path(out_dir) / f"gn_batch-{digest}"
    if not binary.exists():
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        subprocess.run(["cc", "-O2", "-std=gnu11", "-Wall", "-Wextra", "-Wno-unknown-pragmas", "-Werror",
                        "-I", str(EBPF), "-o", str(binary), str(SOURCES[0]), str(EBPF / "ppt_image.c")], check=True)
    return binary


def _frames(frames: Iterable[bytes]) -> bytes:
    return b"".join(struct.pack("<I", len(frame)) + frame for frame in frames)


def _parse(line: str) -> XdpDecision:
    return XdpDecision(*(int(part) for part in line.split()))


def _args(binary, ppt, actions, empty, ring_full, image_index, server_ip, port):
    argv = [str(binary), str(ppt), str(actions), "--image-index", str(image_index),
            "--server-ip", server_ip, "--port", str(port)]
    if empty:
        argv.append("--empty")
    if ring_full:
        argv.append("--ring-full")
    return argv


def parse_counters(stderr: str) -> Optional[Tuple[int, int, int, int]]:
    """The `counters <other> <allow> <drop> <malformed>` line gn_batch prints at the end, or None."""
    for line in reversed(stderr.splitlines()):
        if line.startswith("counters "):
            parts = line.split()[1:]
            if len(parts) == 4:
                return tuple(int(part) for part in parts)
    return None


def batch(binary: Path, ppt: Path, actions: Path, frames: List[bytes], *, empty: bool = False,
          ring_full: bool = False, image_index: int = 1, server_ip: str = fr.SERVER_IP, port: int = p.PORT,
          counters: list = None) -> List[XdpDecision]:
    done = subprocess.run(_args(binary, ppt, actions, empty, ring_full, image_index, server_ip, port),
                          input=_frames(frames), capture_output=True, check=True)
    rows = [_parse(line) for line in done.stdout.decode().splitlines()]
    if len(rows) != len(frames):
        raise RuntimeError(f"gn_batch decided {len(rows)} of {len(frames)} frames: {done.stderr.decode()[-500:]}")
    if counters is not None:
        counters.append(parse_counters(done.stderr.decode()))
    return rows


class Stream:
    def __init__(self, binary: Path, ppt: Path, actions: Path, image_index: int = 1, server_ip: str = fr.SERVER_IP,
                 port: int = p.PORT):
        self.proc = subprocess.Popen(_args(binary, ppt, actions, False, False, image_index, server_ip, port),
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)

    def decide(self, frame: bytes) -> XdpDecision:
        self.proc.stdin.write(_frames([frame]))
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("gn_batch stream ended")
        return _parse(line.decode())

    def close(self) -> Optional[int]:
        self.proc.stdin.close()
        return self.proc.wait(timeout=10)
