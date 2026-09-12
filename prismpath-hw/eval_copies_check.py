#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""eval_copies_check.py: one evaluator, every firmware.

ppt_eval.h is the embedded evaluator every firmware is meant to include; interp_hdr.c certifies it on
the host against the frozen corpus (make cert). This check walks the firmware sources and reports
which ones include the header and which still carry a local copy of eval_atom. A local copy is only
tolerated while it is on the PENDING list with a reason, because converting a firmware changes the
bytes on the device and the device has to be recertified before that lands. A firmware that carries
a local copy and is not on the list fails the check; a firmware on the list that has been converted
is reported so the list can shrink.

Exit 0 when every local copy is a listed one.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
INCLUDE = re.compile(r'#include\s+"(?:\.\./)+ppt_eval\.h"')
LOCAL = re.compile(r'\bstatic\s+(?:inline\s+)?(?:uint8_t|int)\s+eval_atom\s*\(')

# firmware files that evaluate a table; the wrapper headers count for the firmwares that include them
FIRMWARE = [
    "esp-vision-node/main/vision_core.h",
    "esp-vision-c6/main/ppt_eval.h",
    "esp/main/ppt_esp32.c",
    "avr/ppt_uno.c",
    "rp2350/ppt_rp2350.c",
    "rp2350/ppt_tof.c",
    "esp-pot-pod/main/ppt_pot.c",
    "esp-fusion-pod/main/ppt_fusion.c",
    "mesh/main/ppt_mesh.c",
    "mesh-fusion/main/ppt_fusion_mesh.c",
]

# local copies tolerated for now: board not on the bench, so the conversion waits for its recertification
PENDING = {
    "esp/main/ppt_esp32.c": "ESP32 WROOM, recertify with esp/certify on the board",
    "avr/ppt_uno.c": "Arduino Uno, recertify with avr/certify_uno.py",
    "rp2350/ppt_rp2350.c": "RP2350, recertify with rp2350/certify_rp2350.py",
    "rp2350/ppt_tof.c": "RP2350 ToF node, recertify on the board",
    "esp-pot-pod/main/ppt_pot.c": "pot pod, recertify on the board",
    "esp-fusion-pod/main/ppt_fusion.c": "fusion pod, recertify on the board",
    "mesh/main/ppt_mesh.c": "ESP-NOW mesh, recertify with mesh/orchestrate.py; note it switches on raw opcode literals",
    "mesh-fusion/main/ppt_fusion_mesh.c": "mesh fusion, recertify with mesh-fusion/field_walk.py; raw opcode literals",
}


def main() -> int:
    bad = 0
    print(f"{'firmware':44s} state")
    for rel in FIRMWARE:
        text = (HERE / rel).read_text(errors="replace")
        included, local = bool(INCLUDE.search(text)), bool(LOCAL.search(text))
        if included and not local:
            state = "includes ppt_eval.h"
            if rel in PENDING:
                state += "  (converted: drop it from PENDING)"
        elif local and rel in PENDING:
            state = f"local copy, pending: {PENDING[rel]}"
        elif local:
            state = "local copy NOT on the pending list"; bad += 1
        else:
            state = "no evaluator found"; bad += 1
        print(f"{rel:44s} {state}")
    print(f"\n{'ok' if not bad else 'FAIL'}: {sum(1 for r in FIRMWARE if INCLUDE.search((HERE / r).read_text(errors='replace')))} of {len(FIRMWARE)} firmwares include the shared evaluator, {len(PENDING)} pending")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
