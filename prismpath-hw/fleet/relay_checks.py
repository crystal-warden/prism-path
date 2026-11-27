# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The checks of the ESP32-C6 relay (spec-policy-distribution.md B10), for the board validation pass. The relay is
never run as a PEP (owner decision 13), so it is checked for two things only. It holds no key: its image links no
Ed25519 and no part of the C core, which is read from the build. And it forwards: what the Uno behind it stages,
commits and refuses through it is the atmega328p family's checks (fleet/uno_checks.py), run with the relay between
the host's radio and the Uno, so this module reports that check against those."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Callable, Dict, List

RUNS_AS_PEP = False
FORBIDDEN = ("crypto_ed25519", "crypto_eddsa", "crypto_sha512", "pp_verify", "pp_min_", "pp_pep_", "pp_sha256")


def symbols(elf: Path) -> List[str]:
    """The symbol names of the built image, or none when there is no nm for it."""
    tool = shutil.which("riscv32-esp-elf-nm") or shutil.which("nm")
    if tool is None or not elf.is_file():
        return []
    done = subprocess.run([tool, str(elf)], capture_output=True, text=True, check=False)
    return [line.split()[-1] for line in done.stdout.splitlines() if line.split()]


def holds_no_key(elf: Path) -> dict:
    names = symbols(elf)
    found = sorted({name for name in names for prefix in FORBIDDEN if name.startswith(prefix)})
    return {"passed": bool(names) and not found,
            "detail": {"image": str(elf), "symbols": len(names), "forbidden": found}}


def run_checks(boards, family, reflash: Callable) -> Dict[str, dict]:
    elf = family.build_dir() / "pp_relay_c6.elf"
    ids = [board.board_id for board in boards]
    key = holds_no_key(elf)
    return {"holds_no_key": {"passed": key["passed"], "boards": {board_id: key["passed"] for board_id in ids},
                             "detail": key["detail"]},
            "forwards": {"passed": None, "boards": {board_id: None for board_id in ids},
                         "detail": "read from the atmega328p checks, which run through the relay"}}
