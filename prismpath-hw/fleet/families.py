# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""One entry per chip family the harness knows. An entry names the build target and project, the settings every
board of the family needs, how to flash one board, the target kind it runs as, its verify capability and the on
board checks it runs. A new family is one entry here and, if its chip is new, one prober in probe.py."""
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

    def build_dir(self, variant: str = "") -> Path:
        return self.project / (f"build-{variant}" if variant else "build")

    def flash_command(self, path: str, variant: str = "", erase: bool = False, baud: int = 460800) -> List[str]:
        """Flash one board by its path. `erase` clears the flash first, so a board flashed with another variant
        starts from no state (a node refuses to start under an expiry response it was not provisioned with)."""
        return ["idf.py", "-B", str(self.build_dir(variant)), "-p", path, "-b", str(baud),
                *(["erase-flash"] if erase else []), "flash"]


FAMILIES: Dict[str, Family] = {
    "esp32": Family(
        name="esp32", target="esp32", project=HW / "mesh",
        # One build runs on the 26 MHz and the 40 MHz crystals of the ESP32 classic boards alike.
        settings={"CONFIG_XTAL_FREQ_AUTO": "y"}, capability=FULL,
        variants={"hold": {"CONFIG_PPT_MESH_EXPIRY_HOLD": "y"}}),
}
