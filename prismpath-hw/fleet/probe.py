# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Find the boards attached to this host.

Each serial device under /dev/serial/by-path is offered to every prober in turn, and the first that knows it
returns one record: the chip family, a stable id (the MAC for an Espressif chip) and the by-path name. A port
number is never a key, since USB bridges of one kind can share a serial number and ports renumber. A device no
prober knows is returned as unknown, and the run says it was skipped.

    python -m fleet.probe          # from prismpath-hw, prints one line per device
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable, List, Optional

BY_PATH = "/dev/serial/by-path"


@dataclass(frozen=True)
class Board:
    """One attached board. `family` names an entry of families.FAMILIES, or "unknown"."""
    family: str
    board_id: str
    path: str
    chip: str = ""
    crystal: str = ""


def devices(directory: str = BY_PATH) -> List[str]:
    """The by-path names of the serial devices, one per device: a device listed under two names (the usb and
    usbv2 links of one bridge) is offered once, under its first name in sorted order."""
    if not os.path.isdir(directory):
        return []
    seen, out = set(), []
    for name in sorted(os.listdir(directory)):
        path = os.path.join(directory, name)
        real = os.path.realpath(path)
        if real not in seen:
            seen.add(real)
            out.append(path)
    return out


def _esptool() -> Optional[List[str]]:
    tool = shutil.which("esptool.py") or shutil.which("esptool")
    return [tool] if tool else None


def run_esptool(path: str, command: str, timeout: int = 30) -> Optional[str]:
    """esptool's output for `command` on the device at `path`, or None when it does not answer."""
    tool = _esptool()
    if tool is None:
        return None
    try:
        done = subprocess.run([*tool, "--port", path, command], capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return done.stdout if done.returncode == 0 else None


_CHIP = re.compile(r"Chip is (ESP32[\w-]*)")
_MAC = re.compile(r"MAC: ((?:[0-9a-f]{2}:){5}[0-9a-f]{2})")
_CRYSTAL = re.compile(r"Crystal is (\d+MHz)")


def espressif(path: str, run: Callable[[str, str], Optional[str]] = run_esptool) -> Optional[Board]:
    """An Espressif chip, by `esptool chip_id` and `read_mac`. The family is the ESP32 classic for an ESP32
    with no suffix (ESP32-D0WD and the like), and the chip name lowered otherwise."""
    chip_out = run(path, "chip_id")
    if not chip_out:
        return None
    chip = _CHIP.search(chip_out)
    mac_out = run(path, "read_mac") or ""
    mac = _MAC.search(mac_out) or _MAC.search(chip_out)
    if not chip or not mac:
        return None
    name = chip.group(1)
    family = "esp32" if re.fullmatch(r"ESP32-D0W\w*(-V\d)?|ESP32", name) else name.lower()
    crystal = _CRYSTAL.search(chip_out)
    return Board(family=family, board_id=mac.group(1), path=path, chip=name, crystal=crystal.group(1) if crystal else "")


def run_avrdude(path: str, timeout: int = 30) -> Optional[str]:
    """avrdude's reading of the signature bytes of the AVR behind the Uno's bootloader at `path`, or None."""
    tool = shutil.which("avrdude")
    if tool is None:
        return None
    try:
        done = subprocess.run([tool, "-q", "-c", "arduino", "-p", "m328p", "-P", path, "-b", "115200",
                               "-U", "signature:r:-:h"], capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return done.stdout if done.returncode == 0 else None


def serial_number(path: str, by_id: str = "/dev/serial/by-id") -> str:
    """The USB serial number of the bridge behind `path`, from its /dev/serial/by-id name, or "" for none. The Uno
    R3's ATmega16U2 bridge has one per board, and the ATmega328P has no id of its own that avrdude reads."""
    if not os.path.isdir(by_id):
        return ""
    real = os.path.realpath(path)
    for name in sorted(os.listdir(by_id)):
        if os.path.realpath(os.path.join(by_id, name)) == real:
            match = re.search(r"_([0-9A-Za-z]+)-if\d+", name)
            if match:
                return match.group(1)
    return ""


_SIGNATURES = {"0x1e,0x95,0xf": ("atmega328p", "ATmega328P")}


def avr(path: str, run: Callable[[str], Optional[str]] = run_avrdude,
        serial: Callable[[str], str] = serial_number) -> Optional[Board]:
    """An AVR behind an Arduino bootloader, by its signature bytes. The id is the bridge's USB serial number."""
    out = run(path)
    if not out:
        return None
    known = _SIGNATURES.get(out.strip().lower())
    if known is None:
        return None
    board_id = serial(path)
    if not board_id:
        return None   # no stable id, so it cannot be keyed and is listed as unknown
    return Board(family=known[0], board_id=board_id, path=path, chip=known[1])


PROBERS: List[Callable[[str], Optional[Board]]] = [espressif, avr]


def probe(paths: Optional[List[str]] = None, probers=None) -> List[Board]:
    """One record per device: what the first prober that knows it says, else unknown."""
    out = []
    for path in devices() if paths is None else paths:
        for prober in probers or PROBERS:
            board = prober(path)
            if board is not None:
                out.append(board)
                break
        else:
            out.append(Board(family="unknown", board_id="", path=path))
    return out


if __name__ == "__main__":
    for board in probe():
        print(f"{board.family:8} {board.board_id or '-':17} {board.chip or '-':16} {board.path}")
