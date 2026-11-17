#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Run the PrismPath cFS app end to end in a native cFS build and check what it does.

    python3 integrations/cfs/tests/run_scenario.py [--build-dir <cFS>/build-native_std/exe/cpu1]

It boots the staged `core-cpu1`, then plays a scripted sequence of proposed commands into it as UDP datagrams to
ci_lab, the stock command ingest app, exactly as a ground system would send them. It subscribes the stock to_lab
app to the vehicle command message id and to the app's housekeeping, and reads both back over UDP, so the check
is on what reaches the software bus and not only on what the app says about itself.

Checked, for every proposal:
  - the event the app sent (ALLOW, REFUSE with its cause code, ESCALATE with its cause code) from the cFS console,
    against the verdict of the Python reference decision path on the same reading (prismpath.agent.policy);
  - that exactly the allowed proposals reach the VEHICLE_CMD message id, with the payload they were sent with;
  - the housekeeping counters.
A second boot replaces the policy table file with a copy that has one byte of the image flipped: the app must
report the image rejected, stay up, and refuse every proposal (no image, no allow).

Exit status 0 when every check holds. The caller decides what to do when there is no cFS build (the pytest skips).
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
APP = HERE.parent / "prismpath_app"
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO))

from prismpath.agent.policy import Policy  # noqa: E402
from integrations.cfs.prismpath_app.policy import gen_image  # noqa: E402

CI_LAB_PORT = 1234        # ci_lab's UDP command ingest
TO_LAB_PORT = 2234        # to_lab's UDP telemetry output (TO_LAB_MISSION_TLM_PORT)
TO_LAB_CMD_TOPIC = 0x80   # to_lab's own command topic id
CMD_BASE, TLM_BASE = 0x1800, 0x0800   # the stock message id scheme of the sample mission

# ----------------------------------------------------------------- the app's message ids, read from its header
_TOPIC = re.compile(r"#define DEFAULT_PRISMPATH_APP_MISSION_(\w+)_TOPICID\s+(0x[0-9A-Fa-f]+)")


def topics() -> Dict[str, int]:
    text = (APP / "fsw" / "inc" / "prismpath_app_topicids.h").read_text()
    return {name: int(value, 16) for name, value in _TOPIC.findall(text)}


def layout() -> List[Tuple[str, int, int]]:
    """(name, offset, width) per field, from the C layout header."""
    text = (APP / "fsw" / "inc" / "prismpath_app_layout.h").read_text()
    rows = re.findall(r'X\(\s*\d+,\s*"(\w+)",\s*\w+,\s*(\d+),\s*(\d+),', text)
    return [(name, int(off), int(width)) for name, off, width in rows]


def packet(mid: int, fcn: int, payload: bytes) -> bytes:
    """A CCSDS command packet with the cFE secondary header: function code and the XOR checksum cFE generates."""
    total = 6 + 2 + len(payload)
    body = struct.pack(">HHH", mid, 0xC000, total - 7) + bytes([fcn & 0x7F, 0]) + payload
    check = 0xFF
    for byte in body:
        check ^= byte
    return body[:7] + bytes([check]) + body[8:]


def reading_payload(reading: Dict[str, int]) -> bytes:
    out = bytearray(8)
    for name, off, width in layout():
        out[off:off + width] = int(reading[name]).to_bytes(width, "little")
    return bytes(out)


# ----------------------------------------------------------------- the scripted sequence
# (what it is, the reading, or raw payload bytes for a malformed one)
Case = Tuple[str, object]
SEQUENCE: List[Case] = [
    ("attitude slew 30, no contact", dict(cmd_class=1, ground_contact=0, slew_deg=30, thrust_pct=0)),
    ("thruster 40 percent", dict(cmd_class=2, ground_contact=0, slew_deg=0, thrust_pct=40)),
    ("payload command", dict(cmd_class=3, ground_contact=0, slew_deg=0, thrust_pct=0)),
    ("thruster 150 percent", dict(cmd_class=2, ground_contact=1, slew_deg=0, thrust_pct=150)),
    ("attitude slew 120", dict(cmd_class=1, ground_contact=1, slew_deg=120, thrust_pct=0)),
    ("unknown command class 7", dict(cmd_class=7, ground_contact=1, slew_deg=0, thrust_pct=0)),
    ("thruster 80 percent, no contact", dict(cmd_class=2, ground_contact=0, slew_deg=0, thrust_pct=80)),
    ("thruster 80 percent, in contact", dict(cmd_class=2, ground_contact=1, slew_deg=0, thrust_pct=80)),
    ("attitude slew 60, no contact", dict(cmd_class=1, ground_contact=0, slew_deg=60, thrust_pct=0)),
    ("class 11, past the field's maximum", dict(cmd_class=11, ground_contact=0, slew_deg=0, thrust_pct=0)),
    ("thrust 201, past the field's maximum", dict(cmd_class=2, ground_contact=0, slew_deg=0, thrust_pct=201)),
    ("ground_contact 2, not a bool", dict(cmd_class=3, ground_contact=2, slew_deg=0, thrust_pct=0)),
    ("payload shorter than the layout", b"\x02\x01\x00\x00"),
]


def expected(policy: Policy, case: object) -> Tuple[str, int]:
    """(kind, cause) from the Python reference decision path. A short payload is the core's boundary refusal."""
    if isinstance(case, bytes):
        return "refuse", gen_image.causes.code("route:contract-violation")
    reading = {k: (bool(v) if k == "ground_contact" and v in (0, 1) else v) for k, v in case.items()}
    if reading["ground_contact"] == 2:
        return "refuse", gen_image.causes.code("route:contract-violation")   # not a bool: the reference refuses it too
    decision = policy.decide(policy.reading_bytes(reading))
    return decision.kind, decision.cause_code or 0


# ----------------------------------------------------------------- running cFS
class Core:
    """The staged core-cpu1 process and its console, collected line by line on a thread."""

    def __init__(self, exe_dir: Path):
        self.lines: List[str] = []
        self.proc = subprocess.Popen(["./core-cpu1"], cwd=exe_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True, bufsize=1, start_new_session=True)
        self._thread = threading.Thread(target=self._pump, daemon=True)
        self._thread.start()

    def _pump(self) -> None:
        for line in self.proc.stdout:
            self.lines.append(line.rstrip("\n"))

    def wait_for(self, pattern: str, count: int = 1, timeout: float = 30.0) -> List[str]:
        deadline = time.time() + timeout
        rx = re.compile(pattern)
        while time.time() < deadline:
            hits = [line for line in list(self.lines) if rx.search(line)]
            if len(hits) >= count:
                return hits
            if self.proc.poll() is not None:
                break
            time.sleep(0.05)
        raise TimeoutError(f"no {count} line(s) matching {pattern!r} within {timeout}s; the console ended:\n"
                           + "\n".join(self.lines[-25:]))

    def stop(self) -> None:
        if self.proc.poll() is None:
            os.killpg(self.proc.pid, signal.SIGINT)
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(self.proc.pid, signal.SIGKILL)
                self.proc.wait()
        self._thread.join(timeout=2)


EVENT = re.compile(r"66/1/PRISMPATH_APP (\d+): (PRISMPATH_APP .*)$")


def app_events(core: Core) -> List[Tuple[int, str]]:
    return [(int(m.group(1)), m.group(2)) for m in map(EVENT.search, list(core.lines)) if m]


def send(sock: socket.socket, data: bytes) -> None:
    sock.sendto(data, ("127.0.0.1", CI_LAB_PORT))
    time.sleep(0.05)


def subscribe_telemetry(sock: socket.socket, mids: List[int]) -> None:
    """Tell to_lab to send these message ids to UDP 127.0.0.1:TO_LAB_PORT."""
    mid = CMD_BASE | TO_LAB_CMD_TOPIC
    send(sock, packet(mid, 6, b"127.0.0.1".ljust(16, b"\0")))                      # OUTPUT_ENABLE
    for stream in mids:
        send(sock, packet(mid, 2, struct.pack("<IBBBx", stream, 0, 0, 4)))         # ADD_PKT


def drain(rx: socket.socket, quiet: float = 1.0) -> List[bytes]:
    rx.settimeout(quiet)
    out = []
    try:
        while True:
            out.append(rx.recv(4096))
    except socket.timeout:
        return out


class Check:
    def __init__(self) -> None:
        self.failures: List[str] = []
        self.report: List[str] = []

    def ok(self, condition: bool, what: str) -> None:
        self.report.append(f"  {'ok  ' if condition else 'FAIL'} {what}")
        if not condition:
            self.failures.append(what)


def run_good(exe_dir: Path, check: Check, log) -> None:
    policy = Policy.load(gen_image.CORE)
    built = gen_image.build(gen_image.CORE.read_bytes().rstrip(b"\n"))
    tp = topics()
    proposed_mid, vehicle_mid = CMD_BASE | tp["PROPOSED_CMD"], CMD_BASE | tp["VEHICLE_CMD"]
    hk_mid, send_hk_mid = TLM_BASE | tp["HK_TLM"], CMD_BASE | tp["SEND_HK"]

    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    rx.bind(("127.0.0.1", TO_LAB_PORT))
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    core = Core(exe_dir)
    try:
        core.wait_for(r"PRISMPATH_APP initialized, policy active")
        check.ok(any(e == 24 for e, _ in app_events(core)), "policy image loaded from the cFE table at startup (event 24)")
        subscribe_telemetry(tx, [vehicle_mid, hk_mid])
        time.sleep(1.0)                                             # let to_lab apply the subscriptions
        drain(rx, 0.3)                                              # discard to_lab's own housekeeping

        sent: List[bytes] = []
        for _name, case in SEQUENCE:
            payload = case if isinstance(case, bytes) else reading_payload(case)
            sent.append(payload)
            send(tx, packet(proposed_mid, 0, payload))
        send(tx, packet(send_hk_mid, 0, b""))
        core.wait_for(r"PRISMPATH_APP HK proposed=", 1, 10)
        time.sleep(0.5)
        datagrams = drain(rx, 1.0)
        events = [(e, text) for e, text in app_events(core) if e in (20, 21, 22)]
        log(f"console events ({len(events)}):")
        for _e, text in events:
            log(f"    {text}")

        check.ok(len(events) == len(SEQUENCE), f"one decision event per proposal ({len(events)} of {len(SEQUENCE)})")
        allowed_payloads: List[bytes] = []
        for index, ((name, case), (eid, text)) in enumerate(zip(SEQUENCE, events), start=1):
            kind, cause = expected(policy, case)
            want_eid = {"allow": 20, "refuse": 21, "escalate": 22}[kind]
            got_cause = re.search(r"cause=(\d+)", text)
            good = eid == want_eid and f"seq={index} " in text + " " and \
                (kind == "allow" or (got_cause is not None and int(got_cause.group(1)) == cause))
            rule = re.search(r"rule=(\d+)", text)
            if rule and kind != "allow":
                kind_code = built["rules"][int(rule.group(1))]
                good = good and kind_code == ({"refuse": 1, "escalate": 2}[kind], cause)
            if kind == "allow":
                allowed_payloads.append(sent[index - 1])
            check.ok(good, f"proposal {index:2d} ({name}): reference says {kind}"
                           f"{'' if kind == 'allow' else f' cause {cause}'}; app event: {text.split(' ', 1)[1]}")

        vehicle = [d[8:] for d in datagrams if len(d) >= 8 and struct.unpack(">H", d[:2])[0] & 0x1FFF == vehicle_mid]
        hk = [d for d in datagrams if len(d) >= 12 and struct.unpack(">H", d[:2])[0] & 0x1FFF == hk_mid]
        check.ok(vehicle == allowed_payloads,
                 f"exactly the {len(allowed_payloads)} allowed proposals reach VEHICLE_CMD, payloads intact "
                 f"({len(vehicle)} received)")
        for d in datagrams:
            if len(d) >= 8 and struct.unpack(">H", d[:2])[0] & 0x1FFF == vehicle_mid:
                total = 0xFF
                for byte in d:
                    total ^= byte
                check.ok(total == 0, "the republished command carries a valid cFE checksum")
                break
        want = {k: sum(1 for _n, c in SEQUENCE if expected(policy, c)[0] == k) for k in ("allow", "refuse", "escalate")}
        if hk:
            body = hk[-1][-44:]      # the payload is the last 44 bytes, whatever the telemetry header size
            fields = struct.unpack("<BBBBIIIIIIIIII", body)
            names = ("cmd_ctr", "err_ctr", "active", "spare", "layout", "proposed", "allowed", "refused", "escalated",
                     "forwarded", "fwd_err", "loaded", "rejected", "last_cause")
            got = dict(zip(names, fields))
            log(f"housekeeping telemetry: {got}")
            check.ok((got["proposed"], got["allowed"], got["refused"], got["escalated"], got["forwarded"],
                      got["active"]) == (len(SEQUENCE), want["allow"], want["refuse"], want["escalate"],
                                         want["allow"], 1),
                     "housekeeping counters match the sequence")
            check.ok(got["layout"] == built["layout_hash"], "housekeeping reports the policy layout hash")
        else:
            check.ok(False, "housekeeping telemetry reached the ground over to_lab")
    finally:
        core.stop()
        rx.close()
        tx.close()


def run_bad_image(exe_dir: Path, check: Check, log) -> None:
    tbl = exe_dir / "cf" / "pp_app_policy.tbl"
    good = tbl.read_bytes()
    at = good.find(b"PPTM")
    assert at >= 0, "the staged table does not hold a PPT image"
    bad = bytearray(good)
    bad[at + 28] = 0x7F                       # atom 0's field index, far past the image's four fields
    tbl.write_bytes(bytes(bad))
    tp = topics()
    proposed_mid = CMD_BASE | tp["PROPOSED_CMD"]
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    core = Core(exe_dir)
    try:
        core.wait_for(r"PRISMPATH_APP initialized")
        events = app_events(core)
        text = " | ".join(t for _e, t in events)
        log(f"bad image boot: {text}")
        check.ok(any(e == 25 and "cause=76" in t for e, t in events),
                 "a table with a corrupted image is rejected with image:field-index-oob (76), event 25")
        check.ok("policy NOT active" in text, "the app starts with no active policy")
        send(tx, packet(proposed_mid, 0, reading_payload(SEQUENCE[0][1])))
        core.wait_for(r"PRISMPATH_APP (ALLOW|REFUSE|ESCALATE) seq=1", 1, 10)
        decided = [t for e, t in app_events(core) if e in (20, 21, 22)]
        log(f"proposal 1 with no policy: {decided}")
        check.ok(len(decided) == 1 and decided[0].startswith("PRISMPATH_APP REFUSE") and "cause=32" in decided[0],
                 "with no active policy even an in-bounds, in-limits command is refused (cause 32), never allowed")
    finally:
        core.stop()
        tx.close()
        tbl.write_bytes(good)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    default = os.environ.get("CFS_EXE_DIR") or str(REPO / ".cfs-build" / "cFS" / "build-native_std" / "exe" / "cpu1")
    parser.add_argument("--build-dir", default=default, help="the staged cpu1 directory (holds core-cpu1)")
    args = parser.parse_args(argv)
    exe_dir = Path(args.build_dir)
    if not (exe_dir / "core-cpu1").exists():
        print(f"no staged cFS build at {exe_dir} (see integrations/cfs/README.md)", file=sys.stderr)
        return 2
    check = Check()

    def log(line: str) -> None:
        print(line, flush=True)

    log("== scripted sequence against the example policy ==")
    run_good(exe_dir, check, log)
    log("== a table with a corrupted image ==")
    run_bad_image(exe_dir, check, log)
    print("\n".join(check.report))
    if check.failures:
        print(f"\nFAILED: {len(check.failures)} check(s)")
        return 1
    print(f"\nall {len(check.report)} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
