# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""What the app's receipts must be, from the Python reference: the reading a payload is, its receipt line, which
receipts the app made while held, and the RC4 files of an app with install statements, each written as
`core_evidence.produce` writes it.

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


def held_receipts(run: Path) -> List[int]:
    """The index of every receipt the app made while held past its release's expiry (X7). A hold opens a case of its
    own, whose line carries "hold": true, and its end opens another, so the receipts keep their format and their case
    says they were held. The receipts follow the cases in order, one per reading of each case."""
    out, idx = [], 0
    for line in core_evidence._lines(Path(run) / "cases.jsonl"):
        case = canon2.loads(line)
        count = len(case["readings"])
        if case.get("hold") is True:
            out.extend(range(idx, idx + count))
        idx += count
    return out


def install_lines(statements) -> bytes:
    """install.jsonl for (sealed, body) install statements in the order the app applied them (RC4), as
    core_evidence.produce writes it."""
    return b"".join(canon2.dumps({"body": bytes(body).hex(), "sealed": bytes(sealed).hex()}) + b"\n"
                    for sealed, body in statements)


def rate_line(rule: int, window: int, count: int, receipt_sha256: str) -> bytes:
    """One line of rates.jsonl: a counted override of the action floor (AF8, RC3), naming its receipt's leaf."""
    return canon2.dumps({"count": count, "receipt_sha256": receipt_sha256, "rule": rule, "window": window}) + b"\n"


def bases(run: Path) -> List[Tuple[str, str, bool, int]]:
    """(case id, basis, enacted, readings) of every case of a run, in order (RC4)."""
    out = []
    for line in core_evidence._lines(Path(run) / "cases.jsonl"):
        case = canon2.loads(line)
        out.append((case["case"], case.get("basis", "release"), case.get("enacted", True), len(case["readings"])))
    return out
