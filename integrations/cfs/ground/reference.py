# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""What the app's receipts must be, from the Python reference: the reading a payload is, and its receipt line.

The app writes both in C (fsw/src/prismpath_app_run.c). These are written from the layout header and the
reference's own writers (`canon2.dumps`, `core_evidence._decision`, the reference decision path through
`prismpath.agent.policy.Policy`), sharing no code with the C, so a test can hold the C's bytes to them.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Tuple

from prismpath.agent.policy import Policy
from prismpath.kernel import canon2
from prismpath.ledgers import core_evidence

APP = Path(__file__).resolve().parents[1] / "prismpath_app"
DECIDER = "cfs:prismpath_app"


def layout() -> List[Tuple[str, str, int, int]]:
    """(name, INT|BOOL|MONITOR, offset, width) per field in register order, from the C layout header."""
    text = (APP / "fsw" / "inc" / "prismpath_app_layout.h").read_text()
    rows = re.findall(r'X\(\s*\d+,\s*"(\w+)",\s*(INT|BOOL|MONITOR),\s*(\d+),\s*(\d+),', text)
    return [(name, kind, int(off), int(width)) for name, kind, off, width in rows]


def reading_of(payload: bytes) -> Dict:
    """The reading the reference decides for a payload: every field the payload holds, a bool as False or True when
    its byte is 0 or 1 and as its number otherwise (which the boundary then refuses as the wrong type). The MONITOR
    field is the app's, not the proposer's: the app writes its value into the byte it hands the receipt, and a
    payload that ends before it still reads as monitor_ok true (the app's value with no monitor in the mission)."""
    out = {}
    for name, kind, off, width in layout():
        if off + width > len(payload):
            if kind == "MONITOR":
                out[name] = True
            continue
        value = int.from_bytes(payload[off:off + width], "little")
        out[name] = bool(value) if kind in ("BOOL", "MONITOR") and value in (0, 1) else value
    return out


def reading_bytes(payload: bytes) -> bytes:
    return canon2.dumps(reading_of(payload))


def receipt_line(policy: Policy, idx: int, case: str, reading: int, payload: bytes) -> bytes:
    """The core receipt for one decision, exactly as core_evidence.produce and agent.evidence write one."""
    raw = reading_bytes(payload)
    receipt = {"format": core_evidence.RECEIPT_FORMAT, "idx": idx, "case": case, "reading": reading,
               "image_sha256": core_evidence.sha256_hex(policy.image), "reading_sha256": core_evidence.sha256_hex(raw),
               "decider": DECIDER, **core_evidence._decision(policy.verdict(raw))}
    return canon2.dumps(receipt)
