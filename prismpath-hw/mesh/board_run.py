# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The seven checks of the mesh (mesh_checks.py) on every ESP32 the fleet harness finds, for the board validation pass.
It flashes nothing itself: `fleet/run.py` builds, flashes and calls `run_checks`, and running this file runs the
harness. The same checks run on the simulated mesh (host/sim_fleet.py) under prismpath/tests/test_mesh_firmware.py.

The host speaks to one node over its serial port and that node broadcasts every frame on ESP-NOW, so the others
hear the release from the radio. A node that missed a frame is sent the transfer again over its own port. Every
node reports in state records signed by its instance key, which the host reads with the key the node printed at
boot, and every result is recorded against the board's MAC.

    . ~/cwprojects/esp-idf/export.sh && python prismpath-hw/mesh/board_run.py [--skip-flash]
"""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional

HERE = Path(__file__).resolve().parent
HW = HERE.parent
REPO = HW.parent
for path in (str(HW), str(REPO), str(HERE)):
    if path not in sys.path:
        sys.path.insert(0, path)

from prismpath.distribution import frames, state_record  # noqa: E402
from prismpath.kernel import causes  # noqa: E402

import mesh_checks as checks  # noqa: E402
import gen_mesh_tables as tables  # noqa: E402

LIMIT = frames.ESPNOW_LIMIT
_FORMS = {"I": re.compile(r"[0-9a-f]{64}"), "H": re.compile(r"[01]"), "S": re.compile(r"(?:[0-9a-f]{2})+"),
          "D": re.compile(r"\d+ \d+"), "X": re.compile(r"\d+"), "N": re.compile(r"(?:\w+=\S+ ?)+"),
          "Q": re.compile(r"\d+ \d+ \d+ [01]"), "E": re.compile(r".*")}


class Node:
    """One node on its serial port: the lines it prints, decoded."""

    def __init__(self, board, serial_class=None):
        import serial
        self.board = board
        self._serial_class = serial_class or serial.Serial
        self.port = self._serial_class(board.path, 115200, timeout=0)
        self.public: Optional[bytes] = None
        self.hold: Optional[int] = None
        self.records: List[state_record.StateRecord] = []
        self.drops: List[tuple] = []
        self.answers: List[tuple] = []
        self.status: Dict[str, str] = {}
        self.errors: List[str] = []
        self.crystal_mhz: Optional[int] = None
        self._buffer = b""
        self._retried = False

    def reopen(self) -> None:
        """Open the port again, after a flash tool has had it."""
        self.port = self._serial_class(self.board.path, 115200, timeout=0)
        self._buffer = b""

    @property
    def mac(self) -> str:
        return self.board.board_id

    def reset(self, wait: float = 15.0) -> None:
        """Reset the chip by its EN line, as the bridge's RTS drives it, and wait for its boot lines. Its durable
        state is in NVS and survives the reset as it survives a power cycle."""
        self.public, self.hold = None, None
        self.port.dtr = False
        self.port.rts = True
        time.sleep(0.1)
        self.port.rts = False
        end = time.time() + wait
        while time.time() < end and (self.public is None or self.hold is None):
            self.pump()
            time.sleep(0.05)
            if time.time() > end - wait / 2 and self.public is None and not self._retried:
                self._retried = True                       # a first boot after an erase calibrates the radio
                self.port.rts = True
                time.sleep(0.1)
                self.port.rts = False
        self._retried = False
        if self.public is None:
            raise RuntimeError(f"{self.mac} did not report its instance key after a reset")

    def send(self, line: str) -> None:
        self.port.write(line.encode("ascii") + b"\n")
        time.sleep(len(line) * 10 / 115200 + 0.004)   # the line's time on the wire, so the node's buffer keeps up

    def pump(self) -> None:
        self._buffer += self.port.read(65536)
        while b"\n" in self._buffer:
            raw, self._buffer = self._buffer.split(b"\n", 1)
            self._line(raw.decode("ascii", "replace").strip())

    def _line(self, line: str) -> None:
        """One line the node printed. The ROM and the bootloader print at boot too, so a line that is not one of
        the node's own forms is ignored, and a record that does not read under the node's key is kept as an
        error, never as a record. The instance key line comes after the boot's own records, which are read once
        the key is known."""
        tag, _, rest = line.partition(" ")
        if tag not in _FORMS or not _FORMS[tag].fullmatch(rest):
            return
        if tag == "I":
            self.public = bytes.fromhex(rest)
            for raw in getattr(self, "_early", []):
                self._record(raw)
            self._early = []
        elif tag == "H":
            self.hold = int(rest)
        elif tag == "X":
            self.crystal_mhz = int(rest)
        elif tag == "S":
            if self.public is None:
                self._early = getattr(self, "_early", []) + [rest]
            else:
                self._record(rest)
        elif tag == "D":
            transfer, cause = rest.split()
            self.drops.append((int(transfer), causes.name(int(cause))))
        elif tag == "Q":
            self.answers.append(tuple(int(word) for word in rest.split()))
        elif tag == "N":
            self.status = dict(item.split("=", 1) for item in rest.split())
        elif tag == "E":
            self.errors.append(rest)

    def _record(self, text: str) -> None:
        try:
            self.records.append(state_record.read(bytes.fromhex(text), self.public))
        except Exception as error:                   # a record changed on the wire
            self.errors.append(f"record: {error}")

    def since(self, mark: int) -> List[state_record.StateRecord]:
        return self.records[mark:]


class BoardFleet:
    """The attached nodes as a fleet of mesh_checks.py, the first of them the host's sender."""

    def __init__(self, nodes: List[Node], reflash: Callable):
        self.nodes = nodes
        self.ids = [node.mac for node in nodes]
        self.transfer = 0
        self._reflash = reflash

    def _node(self, node_id: str) -> Node:
        return self.nodes[self.ids.index(node_id)]

    def pump(self, seconds: float) -> None:
        end = time.time() + seconds
        while time.time() < end:
            for node in self.nodes:
                node.pump()
            time.sleep(0.02)

    def _until(self, done: Callable[[Node], bool], seconds: float) -> None:
        end = time.time() + seconds
        while time.time() < end and not all(done(node) for node in self.nodes):
            self.pump(0.1)

    def _marks(self) -> Dict[str, int]:
        return {node.mac: len(node.records) for node in self.nodes}

    def _since(self, marks: Dict[str, int]) -> Dict[str, list]:
        return {node.mac: node.since(marks[node.mac]) for node in self.nodes}

    def _send_all(self, lines: List[str], answered: Callable[[Node], bool], seconds: float) -> None:
        for line in lines:
            self.nodes[0].send(f"F {line}")
        self._until(answered, seconds)
        for node in self.nodes:
            if not answered(node):
                for line in lines:
                    node.send(f"L {line}")
        self._until(answered, seconds)

    def hold(self, node_id: str) -> int:
        return self._node(node_id).hold

    def deliver(self, sealed: bytes, body: bytes) -> Dict[str, list]:
        self.transfer = (self.transfer + 1) & 0xFFFF
        sequence = [data.hex() for data in frames.frames_for(self.transfer, sealed, body, LIMIT)]
        marks = self._marks()
        self._send_all(sequence, lambda node: any(record.event in ("staged", "refused", "beat", "trust-applied",
                                                                   "install-applied")
                                                  for record in node.since(marks[node.mac])), 3.0)
        return self._since(marks)

    def control(self, frame: bytes) -> Dict[str, list]:
        marks = self._marks()
        if frame[0] == frames.EPOCH:                   # H9: a statement sends no record
            self.nodes[0].send(f"F {frame.hex()}")
            self.pump(0.5)
        else:
            self._send_all([frame.hex()], lambda node: any(record.event in ("committed", "refused", "aborted")
                                                           for record in node.since(marks[node.mac])), 2.0)
        return self._since(marks)

    def wait(self, seconds: float) -> Dict[str, list]:
        marks = self._marks()
        self.pump(seconds)
        return self._since(marks)

    def reset(self) -> Dict[str, list]:
        marks = self._marks()
        for node in self.nodes:
            node.reset()
        self.pump(1.0)
        return self._since(marks)

    def forget(self) -> Dict[str, list]:
        """Every node forgets its durable state and its instance key and starts again from the baked anchor."""
        marks = self._marks()
        for node in self.nodes:
            node.public = node.hold = None
            node.send("Z")
        end = time.time() + 8
        while time.time() < end and not all(node.public is not None and node.hold is not None for node in self.nodes):
            self.pump(0.1)
        for node in self.nodes:
            if node.public is None:
                raise RuntimeError(f"{node.mac} did not come back after forgetting its state")
        self.pump(0.5)
        return self._since(marks)

    def rebuild(self, node_id: str, variant: str) -> None:
        node = self._node(node_id)
        node.port.close()                              # the flash tool needs the port to itself
        self._reflash(node.board, variant)
        node.reopen()
        node.reset(wait=10)

    def ask(self, regs: bytes) -> Dict[str, tuple]:
        marks = {node.mac: len(node.answers) for node in self.nodes}
        for node in self.nodes:
            node.send(f"A {regs.hex()}")
        self._until(lambda node: len(node.answers) > marks[node.mac], 2.0)
        return {node.mac: node.answers[-1] if len(node.answers) > marks[node.mac] else None for node in self.nodes}

    def time(self) -> int:
        """The latest time any node reported, the nodes' common time floor plus what they counted since."""
        return max(record.time for node in self.nodes for record in node.records)


def run_checks(boards, family, reflash: Callable) -> dict:
    """The seven checks of mesh_checks.py on every board attached, by MAC. Returns {check: {passed, boards, detail}}."""
    nodes = [Node(board) for board in boards]
    for node in nodes:
        node.reset()
    fleet = BoardFleet(nodes, reflash)
    out = checks.run_checks(fleet, tables.Signer())
    out["flashed"]["detail"] = {node.mac: f"one {family.name} build, flashed by path {node.board.path}; "
                                          f"{out['flashed']['detail'][node.mac]}" for node in nodes}
    for node in nodes:
        node.port.close()
    out["crystals"] = {node.mac: {"chip": node.board.chip, "esptool": node.board.crystal,
                                  "firmware_mhz": node.crystal_mhz} for node in nodes}
    return out


def main(argv=None) -> int:
    from fleet import run
    return run.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
