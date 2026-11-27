# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""One entry per chip family the harness knows. An entry names the build target and project, the settings every
board of the family needs, how to flash one board, the target kind it runs as, its verify capability and the on
board checks it runs. A new family is one entry here and, if its chip is new, one prober in probe.py.

One chip can run two images. The ESP32-C6 runs the mesh firmware as a PEP (`full`) or the relay of B10, which holds
no key and is never run as a PEP (`cannot`, owner decision 13). A board runs the relay entry when the run names its
id with --relay."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

HW = Path(__file__).resolve().parent.parent

FULL, ONE_PASS, CANNOT = "full", "one-pass", "cannot"


@dataclass(frozen=True)
class Family:
    name: str
    target: str                       # the ESP-IDF target, or the toolchain's name for the chip
    project: Path                     # the firmware project built once for every board of the family
    settings: Dict[str, str]          # sdkconfig lines every board of the family needs
    capability: str                   # full, one-pass or cannot (spec-policy-distribution.md 7.8)
    kind: str = "mesh"                # the target kind the firmware runs as
    checks: str = "mesh.board_run"    # the module whose CHECKS the run takes
    variants: Dict[str, Dict[str, str]] = field(default_factory=dict)   # extra builds, by name
    tool: str = "idf"                 # idf for an ESP-IDF project, make for the AVR Makefile
    chip: str = ""                    # the family the prober reports, when it is not this entry's name

    @property
    def probed(self) -> str:
        return self.chip or self.name

    def build_dir(self, variant: str = "") -> Path:
        return self.project / (f"build-{variant}" if variant else "build")

    def flash_command(self, path: str, variant: str = "", erase: bool = False, baud: int = 460800) -> List[str]:
        """Flash one board by its path. `erase` clears the flash first, so a board flashed with another variant
        starts from no state (a node refuses to start under an expiry response it was not provisioned with)."""
        if self.tool == "make":   # the Uno's optiboot, the image and the anchor its EEPROM holds (section 14)
            return ["avrdude", "-q", "-c", "arduino", "-p", "m328p", "-P", path, "-b", "115200",
                    "-U", f"flash:w:{self.project / 'ppt_uno_dist.hex'}:i",
                    "-U", f"eeprom:w:{self.project / 'uno_anchor.eep'}:r"]
        return ["idf.py", "-B", str(self.build_dir(variant)), "-p", path, "-b", str(baud),
                *(["erase-flash"] if erase else []), "flash"]


FAMILIES: Dict[str, Family] = {
    "esp32": Family(
        name="esp32", target="esp32", project=HW / "mesh",
        # One build runs on the 26 MHz and the 40 MHz crystals of the ESP32 classic boards alike.
        settings={"CONFIG_XTAL_FREQ_AUTO": "y"}, capability=FULL,
        variants={"hold": {"CONFIG_PPT_MESH_EXPIRY_HOLD": "y"}}),
    # The C6 has one crystal, so it needs no setting of its own. As a PEP it runs the same mesh firmware.
    "esp32-c6": Family(name="esp32-c6", target="esp32c6", project=HW / "mesh", settings={}, capability=FULL),
    # The relay of B10: ESP-NOW on one side, a UART to the Uno on the other, checked for forwarding and holding no key.
    "esp32-c6-relay": Family(name="esp32-c6-relay", target="esp32c6", project=HW / "esp-relay-c6", settings={},
                             capability=CANNOT, kind="relay", checks="fleet.relay_checks", chip="esp32-c6"),
    # The constrained profile of B12 on an Uno. The build estimate of PR 17b says the image does not fit the chip
    # (prismpath-hw/avr/uno_dist_build_estimate.json), and the board pass of 2026-11-30 decides one-pass or cannot.
    "atmega328p": Family(name="atmega328p", target="atmega328p", project=HW / "avr", settings={},
                         capability=ONE_PASS, checks="fleet.uno_checks", tool="make"),
}
