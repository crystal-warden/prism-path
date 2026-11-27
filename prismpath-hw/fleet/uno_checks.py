# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The on board checks of the constrained enforcement point (spec-policy-distribution.md B12) on an Uno, for the board
validation pass. `fleet/run.py` builds and flashes (the image and the EEPROM anchor of avr/uno_anchor.py) and calls
`run_checks`. The host sends the frames of section 8.3 in order over the board's serial port, as the C6 relay sends
what it hears (B10, B11), and reads back the state records the Uno signs with its instance key.

Done for PR 17b when the Uno stages and commits a signed release and refuses a bad signature, with the time of the
check recorded, or when the board cannot, which is PR 17c (owner decision 13). The same checks run on the host build
of the same C under prismpath/tests/test_distribution_c_min.py, through a link that is the host harness."""
from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Callable, Dict, List

HERE = Path(__file__).resolve().parent
HW = HERE.parent
for path in (str(HW / "mesh"), str(HW / "avr"), str(HW.parent)):
    if path not in sys.path:
        sys.path.insert(0, path)

from prismpath.distribution import envelope as env  # noqa: E402
from prismpath.distribution import frames, state_record  # noqa: E402

RUNS_AS_PEP = True   # a one-pass PEP (B12): the harness runs it as one
BAUD = 57600         # ppt_uno_dist.c
END, ESC, ESC_END, ESC_ESC = 0xC0, 0xDB, 0xDC, 0xDD   # pp_link.h


def encode(frame: bytes) -> bytes:
    """One frame on the line, as pp_link_encode writes it."""
    body = frame.replace(bytes([ESC]), bytes([ESC, ESC_ESC])).replace(bytes([END]), bytes([ESC, ESC_END]))
    return bytes([END]) + body + bytes([END])


def decode(line: bytes) -> List[bytes]:
    """The whole frames in `line`, as pp_link_rx_byte reads them. A broken frame is dropped."""
    out, frame, escaped, broken = [], bytearray(), False, False
    for b in line:
        if b == END:
            if frame and not broken and not escaped:
                out.append(bytes(frame))
            frame, escaped, broken = bytearray(), False, False
        elif broken:
            continue
        elif escaped:
            escaped = False
            if b in (ESC_END, ESC_ESC):
                frame.append(END if b == ESC_END else ESC)
            else:
                broken = True
        elif b == ESC:
            escaped = True
        else:
            frame.append(b)
    return out


class SerialLink:
    """The Uno at `path`: frames out, the state records it sends back."""

    def __init__(self, path: str):
        import serial   # pyserial, only on the host that runs the board pass
        self.port = serial.Serial(path, BAUD, timeout=0.05)
        time.sleep(2.0)   # the bootloader runs for a moment after the port opens and resets the board
        self.port.reset_input_buffer()

    def exchange(self, sent: List[bytes], seconds: float = 5.0) -> List[bytes]:
        for frame in sent:
            self.port.write(encode(frame))
            self.port.flush()
        line, until = bytearray(), time.monotonic() + seconds
        while time.monotonic() < until:
            line += self.port.read(512)
        return [frame[4:] for frame in decode(bytes(line)) if frame[:1] == bytes([frames.STATE])]


def _records(raw: List[bytes], public: bytes) -> List[state_record.StateRecord]:
    return [state_record.read(record, public) for record in raw]


def checks(link, signer, instance_public: bytes) -> Dict[str, dict]:
    """The checks on one Uno through `link`. A first release of policy A with its widening statement is staged and
    committed, then a release of B whose signature is wrong is refused with sig:invalid."""
    import gen_mesh_tables as tables
    body_a, body_b = tables.tables()[:2]
    out: Dict[str, dict] = {}
    sent, transfer = [], 1
    for sealed, body in signer.release_with_statement(body_a, 1):
        sent += list(frames.frames_for(transfer, sealed, body, frames.ESPNOW_LIMIT))
        transfer += 1
    policy_a = env.read(env.unseal(signer.release(body_a, 1))[0], reads_meta=False).policy_sha256
    sent.append(frames.encode(frames.commit_for(transfer, signer.stream, 1, policy_a)))
    started = time.monotonic()
    records = _records(link.exchange(sent), instance_public)
    took = time.monotonic() - started
    events = [(record.event, record.cause) for record in records]
    committed = [record for record in records if record.event == "committed"]
    out["release_committed"] = {"passed": events[-3:] == [("staged", None), ("staged", None), ("committed", None)] and
                                bool(committed) and committed[-1].active_policy == bytes.fromhex(policy_a)[:16],
                                "detail": events}
    good = signer.release(body_b, 2, widens=True)
    envelope_bytes, entries = env.unseal(good)
    forged = env.seal_entries(envelope_bytes, [(entries[0][0], bytes(64))])
    records = _records(link.exchange(list(frames.frames_for(transfer + 1, forged, body_b, frames.ESPNOW_LIMIT))),
                       instance_public)
    events = [(record.event, record.cause) for record in records]
    out["bad_signature_refused"] = {"passed": events == [("refused", "sig:invalid")], "detail": events}
    out["check_time"] = {"passed": None, "detail": {"stage_and_commit_seconds": round(took, 3),
                                                    "note": "over the link, an upper bound; pin 13 gives the check"}}
    return out


def run_checks(boards, family, reflash: Callable) -> dict:
    """The checks on every Uno attached, by its id. Returns {check: {passed, boards, detail}}."""
    import gen_mesh_tables as tables
    import uno_anchor
    signer = tables.Signer()
    public = tables.public_raw(uno_anchor.instance())
    results: Dict[str, dict] = {}
    for board in boards:
        for name, result in checks(SerialLink(board.path), signer, public).items():
            entry = results.setdefault(name, {"passed": True, "boards": {}, "detail": {}})
            entry["boards"][board.board_id] = result["passed"]
            entry["detail"][board.board_id] = result["detail"]
            if result["passed"] is None:
                entry["passed"] = None
            elif entry["passed"] is not None:
                entry["passed"] = entry["passed"] and result["passed"]
    return results
