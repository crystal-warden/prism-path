# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The simulated mesh: three nodes of the mesh firmware's own logic (main/mesh_node.c) built for the host as
`mesh_sim`, driven with the frames prismpath/distribution/frames.py writes. `SimFleet` is a fleet in the sense of
../mesh_checks.py, so the seven checks the boards run next run here first.

    fleet = SimFleet(build(out_dir), anchor_lines(...), seeds)
    mesh_checks.run_checks(fleet, signer, after_flash=fleet.booted)

Time is the simulator's own, in milliseconds, shared by the nodes, and each node counts its uptime from its last
boot, as esp_timer does. Records are read under each node's instance key, which it reports in `status`."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from prismpath.distribution import frames, state_record

HERE = Path(__file__).resolve().parent
MESH = HERE.parent
HW = MESH.parent
SOURCES = [HERE / "mesh_sim.c", MESH / "main" / "mesh_node.c", HW / "dist" / "pp_dist.c", MESH / "main" / "monocypher.c",
           MESH / "main" / "monocypher-ed25519.c"]
FLAGS = ["-std=c11", "-O1", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined", "-fno-sanitize-recover=all"]
TICK_MS = 20                                       # the firmware's tick


def build(out_dir: Path, cc: Optional[str] = None) -> Path:
    """mesh_sim built with the host cc from the sources the board builds, under the sanitizers."""
    cc = cc or shutil.which("cc")
    if cc is None:
        raise FileNotFoundError("no C compiler (cc) on this host")
    out = Path(out_dir) / "mesh_sim"
    subprocess.run([cc, *FLAGS, f"-I{HW / 'dist'}", f"-I{MESH / 'main'}", "-o", str(out), *map(str, SOURCES)],
                   check=True, capture_output=True, text=True)
    return out


# ------------------------------------------------------------------ NVS, as ESP-IDF 5 lays it out
NVS_PAGE = 4096
NVS_ENTRIES = 126                                  # 32 byte entries a page holds after its header and state bitmap
NVS_CHUNK = (NVS_ENTRIES - 1) * 32                 # the most data one chunk of a blob carries in one page


def nvs_entries(size: int) -> int:
    """The entries one blob of `size` bytes takes: its index entry, and for each chunk a header and its data."""
    chunks, left, entries = 0, size, 1
    while left > 0 or chunks == 0:
        take = min(left, NVS_CHUNK)
        entries += 1 + -(-take // 32)
        left -= take
        chunks += 1
    return entries


def nvs_pages(sizes: Sequence[int], *, extra_entries: int = 0) -> int:
    """The pages a partition needs for blobs of `sizes`: their entries and one namespace entry, room to write the
    largest blob again before the old one is erased (a part is always written whole, C4), and the one free page NVS
    keeps for its own garbage collection."""
    used = sum(nvs_entries(size) for size in sizes) + 1 + extra_entries
    rewrite = max((nvs_entries(size) for size in sizes), default=0)
    return -(-(used + rewrite) // NVS_ENTRIES) + 1


def partitions(csv_path: Path) -> Dict[str, tuple]:
    """{name: (type, subtype, offset, size)} of an ESP-IDF partition table."""
    out = {}
    for line in Path(csv_path).read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            name, kind, subtype, offset, size, *_flags = [item.strip() for item in line.split(",")]
            out[name] = (kind, subtype, int(offset, 0), int(size, 0))
    return out


def anchor_lines(authority: bytes, controller: Optional[bytes] = None, *, fresh: int = 0, stream: str = "mesh/demo",
                 install: Sequence[bytes] = (), threshold: int = 2, domain: str = "", layout: str = "",
                 fields: Sequence[tuple] = (), fingerprint: str = "") -> List[str]:
    """The build every node shares: its anchor, layout and domain, as mesh_sim reads them."""
    lines = [f"key {authority.hex()}", f"stream {stream}"]
    if controller is not None:
        lines += [f"controller {controller.hex()}", f"fresh {fresh}"]
    if domain:
        lines.append(f"domain {domain}")
    if layout:
        lines.append(f"layout {layout}")
        lines += [f"field {reg} {role} {low} {high} {stale}" for _name, reg, role, low, high, stale in fields]
    if install:
        lines += [f"ikey {key.hex()}" for key in install]
        lines.append(f"install {threshold} 0 {domain} {fingerprint}")
    return lines


class SimFleet:
    """Three simulated nodes on one radio. Every method answers what each node signed meanwhile, by node id."""

    def __init__(self, binary: Path, build_lines: List[str], seeds: Sequence[bytes], holds: Sequence[int] = (0, 0, 0)):
        self.process = subprocess.Popen([str(binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, bufsize=1)
        self.ms = 0
        self.ids = [f"node{k}" for k in range(len(seeds))]
        self.seeds = list(seeds)
        self.holds = list(holds)
        self.public: Dict[int, bytes] = {}
        self.records: Dict[str, list] = {node_id: [] for node_id in self.ids}
        self.drops: Dict[str, list] = {node_id: [] for node_id in self.ids}
        self.heard: Dict[str, int] = {node_id: 0 for node_id in self.ids}
        self.transfer = 0
        self._send(build_lines + [f"node {k} {hold} {seed.hex()}" for k, (hold, seed) in enumerate(zip(holds, seeds))])
        self.booted = self._boot_all()

    # ------------------------------------------------------------------ the simulator's lines
    def _send(self, lines: List[str]) -> List[str]:
        self.process.stdin.write("\n".join([*lines, "sync"]) + "\n")
        self.process.stdin.flush()
        out = []
        while True:
            line = self.process.stdout.readline()
            if not line:
                raise RuntimeError(f"mesh_sim stopped: {self.process.stderr.read()}")
            line = line.strip()
            if line == "sync":
                return out
            out.append(line)

    def _run(self, lines: List[str]) -> Dict[str, list]:
        """Run `lines`, then read each node's status, and answer the records each node signed."""
        out = self._send(lines + [f"status {k} {self.ms}" for k in range(len(self.ids))])
        for line in out:
            words = line.split()
            if words[0] == "status":
                self.public[int(words[1])] = bytes.fromhex(words[6])
        got: Dict[str, list] = {node_id: [] for node_id in self.ids}
        self.answers: Dict[str, tuple] = {}
        self.statuses: Dict[str, list] = {}
        for line in out:
            words = line.split()
            node_id = self.ids[int(words[1])] if len(words) > 1 and words[1].isdigit() else None
            if words[0] == "rec":
                record = state_record.read(bytes.fromhex(words[2]), self.public[int(words[1])])
                got[node_id].append(record)
                self.records[node_id].append(record)
            elif words[0] == "drop":
                self.drops[node_id].append((int(words[2]), int(words[3])))
            elif words[0] == "heard":
                self.heard[node_id] += int(words[2])
            elif words[0] == "ask":
                self.answers[node_id] = tuple(int(word) for word in words[2:6])
            elif words[0] == "status":
                self.statuses[node_id] = words[2:6]
            elif words[0] == "stopped":
                raise RuntimeError(f"{node_id} refused to start")
        return got

    def _boot_all(self) -> Dict[str, list]:
        return self._run([f"boot {k} {self.ms}" for k in range(len(self.ids))])

    # ------------------------------------------------------------------ a fleet (../mesh_checks.py)
    def hold(self, node_id: str) -> int:
        return self.holds[self.ids.index(node_id)]

    def radio(self, frame: bytes) -> Dict[str, list]:
        """One frame from the host's radio, which every node hears."""
        self.ms += 2                                   # about the time a frame takes on ESP-NOW
        return self._run([f"radio {frame.hex()} {self.ms}"])

    def deliver(self, sealed: bytes, body: bytes) -> Dict[str, list]:
        self.transfer = (self.transfer + 1) & 0xFFFF
        lines = []
        for frame in frames.frames_for(self.transfer, sealed, body, frames.ESPNOW_LIMIT):
            self.ms += 2
            lines.append(f"radio {frame.hex()} {self.ms}")
        return self._run(lines)

    def control(self, frame: bytes) -> Dict[str, list]:
        return self.radio(frame)

    def wait(self, seconds: float) -> Dict[str, list]:
        """Time passes, each node ticking every TICK_MS through the first second and then once a second."""
        end = self.ms + int(seconds * 1000)
        lines = []
        while self.ms < end:
            self.ms = min(end, self.ms + (TICK_MS if self.ms + 1000 > end or len(lines) < 50 else 1000))
            lines.append(f"tick {self.ms}")
        return self._run(lines)

    def reset(self) -> Dict[str, list]:
        self.ms += 300
        return self._run([f"reset {k} {self.ms}" for k in range(len(self.ids))])

    def forget(self) -> Dict[str, list]:
        self.ms += 300
        return self._run([*(f"erase {k} 2" for k in range(len(self.ids))),
                          *(f"boot {k} {self.ms}" for k in range(len(self.ids)))])

    def rebuild(self, node_id: str, variant: str) -> None:
        k = self.ids.index(node_id)
        self.holds[k] = 1 if variant == "hold" else 0
        self._run([f"node {k} {self.holds[k]} {self.seeds[k].hex()}", f"erase {k} 2", f"boot {k} {self.ms}"])

    def ask(self, regs: bytes, ages: str = "-") -> Dict[str, tuple]:
        self._run([f"ask {k} {self.ms} {regs.hex()} {ages}" for k in range(len(self.ids))])
        return dict(self.answers)

    def time(self) -> int:
        return max(record.time for records in self.records.values() for record in records)

    # ------------------------------------------------------------------ beyond a fleet
    def beat(self) -> Dict[str, list]:
        return self._run([f"beat {k} {self.ms}" for k in range(len(self.ids))])

    def lines(self, lines: List[str]) -> List[str]:
        """Raw lines, for what the fleet methods do not cover (corrupt, nvs, bounds)."""
        return self._send(lines)

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.stdin.write("done\n")
            self.process.stdin.close()
            self.process.wait(timeout=30)
