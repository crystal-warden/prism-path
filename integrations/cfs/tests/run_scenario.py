#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Run the PrismPath cFS app end to end in a native cFS build, reset it, and verify its run on the ground.

    python3 integrations/cfs/tests/run_scenario.py [--build-dir <cFS>/build-native_std/exe/cpu1] [--keys DIR]

It provisions the staged build with test keys (integrations/cfs/ground/provision.py: the authority key the app
checks every table against, the instance key it signs root statements with) and a signed policy table, boots
`core-cpu1` with a power on reset, and plays proposed commands into it as UDP datagrams to ci_lab, the stock
command ingest app, exactly as a ground system would send them. The stock to_lab app is subscribed to the vehicle
command message id and to the app's housekeeping and read back over UDP, so the check is on what reaches the
software bus and not only on what the app says about itself.

  1. The S1 sequence. For every proposal, the event (ALLOW, REFUSE with its cause, ESCALATE with its cause, each
     with its receipt number) against the Python reference decision on the same reading; exactly the allowed
     proposals reach VEHICLE_CMD with their payload; the housekeeping counters, receipt count and root. Then a
     SEAL command: the app signs a root statement over the receipts so far.
  2. A processor reset, by the cFE ES restart command. The PSP exits and the driver boots it again, which starts
     as a processor reset from the boot record, as on a vehicle. The app restores its run from the Critical Data
     Store: the receipt count and root continue, and the same image is accepted against the version floor.
  3. More proposals, receipted after the ones before the reset. Then two table loads through cFE Table Services
     (load, validate, activate): the same policy signed by the authority as version 1, below the floor, which is
     refused as image:version-replay (9), and the version 2 table with one threshold changed and not signed
     again, refused as sig:invalid (2). A proposal after them is still decided by version 2. A second SEAL.
  4. The run directory is copied off the vehicle's file system (the downlink) and verified on the ground with
     the repository's own verifier, both keys pinned to the ground's copies and every receipt replayed through
     the reference kernel (`prismpath evidence verify RUN --sample all --pin-authority --pin-instance`), and the
     root history: the root signed before the reset is the root of the first receipts after it.
  5. A boot (power on) on a table whose image has one byte corrupted: rejected, nothing allowed.

Exit status 0 when every check holds. The caller decides what to do when there is no cFS build (the pytest skips).
The build's original table file is put back and the provisioned key files removed afterwards.
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
import tempfile
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
APP = HERE.parent / "prismpath_app"
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO))

from prismpath.agent.policy import Policy  # noqa: E402
from prismpath.ledgers import core_evidence, root_statement  # noqa: E402
from integrations.cfs.ground import downlink, provision, reference, table  # noqa: E402
from integrations.cfs.prismpath_app.policy import gen_image  # noqa: E402

CI_LAB_PORT = 1234        # ci_lab's UDP command ingest
TO_LAB_PORT = 2234        # to_lab's UDP telemetry output (TO_LAB_MISSION_TLM_PORT)
TO_LAB_CMD_TOPIC = 0x80   # to_lab's own command topic id
CMD_BASE, TLM_BASE = 0x1800, 0x0800   # the stock message id scheme of the sample mission
ES_CMD_MID, TBL_CMD_MID = CMD_BASE | 6, CMD_BASE | 4   # cFE Executive and Table Services commands
ES_RESTART_CC, TBL_LOAD_CC, TBL_VALIDATE_CC, TBL_ACTIVATE_CC, TBL_ABORT_LOAD_CC = 2, 2, 4, 5, 9
PROCESSOR_RESET = 1                   # CFE_PSP_RST_TYPE_PROCESSOR
SEAL_CC = 2                           # PRISMPATH_APP_SEAL_CC
TABLE_NAME = b"PRISMPATH_APP.PolicyTable"
HK_PAYLOAD = struct.Struct("<BBBBIIIIIIIIIIIIIII16s")
HK_NAMES = ("cmd_ctr", "err_ctr", "active", "spare", "layout", "proposed", "allowed", "refused", "escalated",
            "forwarded", "fwd_err", "loaded", "rejected", "last_cause", "receipts", "unreceipted", "record_errors",
            "version", "seals", "root16")

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


AFTER_RESET: List[Case] = [
    ("after the reset: payload command", dict(cmd_class=3, ground_contact=0, slew_deg=0, thrust_pct=0)),
    ("after the reset: thruster 120 percent", dict(cmd_class=2, ground_contact=1, slew_deg=0, thrust_pct=120)),
    ("after the reset: attitude slew 50, no contact", dict(cmd_class=1, ground_contact=0, slew_deg=50, thrust_pct=0)),
    ("after the reset: command class 0", dict(cmd_class=0, ground_contact=1, slew_deg=0, thrust_pct=0)),
]
AFTER_LOADS: List[Case] = [
    ("after the refused loads: thruster 101 percent", dict(cmd_class=2, ground_contact=1, slew_deg=0, thrust_pct=101)),
    ("after the refused loads: attitude slew 10", dict(cmd_class=1, ground_contact=0, slew_deg=10, thrust_pct=0)),
]


def payload_of(case: object) -> bytes:
    return case if isinstance(case, bytes) else reading_payload(case)


def expected(policy: Policy, case: object) -> Tuple[str, int]:
    """(kind, cause) from the Python reference decision path on the reading the payload is."""
    decision = policy.decide(reference.reading_bytes(payload_of(case)))
    return decision.kind, decision.cause_code or 0


# ----------------------------------------------------------------- running cFS
class Core:
    """The staged core-cpu1 process and its console, collected line by line on a thread."""

    def __init__(self, exe_dir: Path, args: Tuple[str, ...] = ("--reset", "PO")):
        self.lines: List[str] = []
        self.proc = subprocess.Popen(["./core-cpu1", *args], cwd=exe_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
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

    def exited(self, timeout: float) -> bool:
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return False
        self._thread.join(timeout=2)
        return True

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


class Ground:
    """The ground's side of the link: the command and telemetry sockets and the message ids."""

    def __init__(self) -> None:
        tp = topics()
        self.proposed_mid, self.vehicle_mid = CMD_BASE | tp["PROPOSED_CMD"], CMD_BASE | tp["VEHICLE_CMD"]
        self.hk_mid, self.send_hk_mid, self.cmd_mid = TLM_BASE | tp["HK_TLM"], CMD_BASE | tp["SEND_HK"], CMD_BASE | tp["CMD"]
        self.rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.rx.bind(("127.0.0.1", TO_LAB_PORT))
        self.tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def close(self) -> None:
        self.rx.close()
        self.tx.close()

    def connect(self) -> None:
        subscribe_telemetry(self.tx, [self.vehicle_mid, self.hk_mid])
        time.sleep(1.0)                                             # let to_lab apply the subscriptions
        drain(self.rx, 0.3)                                         # discard to_lab's own housekeeping

    def propose(self, cases: List[Case]) -> List[bytes]:
        sent = []
        for _name, case in cases:
            sent.append(payload_of(case))
            send(self.tx, packet(self.proposed_mid, 0, sent[-1]))
        return sent

    def housekeeping(self, core: Core, count: int) -> Tuple[List[bytes], Optional[Dict]]:
        send(self.tx, packet(self.send_hk_mid, 0, b""))
        core.wait_for(r"PRISMPATH_APP HK proposed=", count, 10)
        time.sleep(0.5)
        datagrams = drain(self.rx, 1.0)
        hk = [d for d in datagrams if len(d) >= 12 and struct.unpack(">H", d[:2])[0] & 0x1FFF == self.hk_mid]
        got = dict(zip(HK_NAMES, HK_PAYLOAD.unpack(hk[-1][-HK_PAYLOAD.size:]))) if hk else None
        return datagrams, got

    def vehicle(self, datagrams: List[bytes]) -> List[bytes]:
        return [d for d in datagrams if len(d) >= 8 and struct.unpack(">H", d[:2])[0] & 0x1FFF == self.vehicle_mid]

    def seal(self, core: Core, count: int) -> str:
        send(self.tx, packet(self.cmd_mid, SEAL_CC, b""))
        return core.wait_for(r"PRISMPATH_APP SEALED receipts=", count, 10)[-1]

    def table_load(self, core: Core, path: str, rejected: int) -> None:
        """Load, validate and activate a table file through cFE Table Services, as a ground operator does, then
        abort the load so the next one can start."""
        name = TABLE_NAME.ljust(40, b"\0")
        send(self.tx, packet(TBL_CMD_MID, TBL_LOAD_CC, path.encode().ljust(64, b"\0")))
        time.sleep(0.3)
        send(self.tx, packet(TBL_CMD_MID, TBL_VALIDATE_CC, struct.pack("<H", 0) + name))   # the inactive buffer
        core.wait_for(r"PRISMPATH_APP POLICY REJECTED", rejected, 10)
        send(self.tx, packet(TBL_CMD_MID, TBL_ACTIVATE_CC, name))
        time.sleep(2.5)                                              # past the app's table poll
        send(self.tx, packet(TBL_CMD_MID, TBL_ABORT_LOAD_CC, name))
        time.sleep(0.3)


def check_decisions(check: Check, policy: Policy, built: Dict, cases: List[Case], events: List[Tuple[int, str]],
                    first_receipt: int, sent: List[bytes]) -> List[bytes]:
    """Each event against the reference, with its receipt number; returns the payloads that should be allowed."""
    allowed = []
    check.ok(len(events) == len(cases), f"one decision event per proposal ({len(events)} of {len(cases)})")
    for index, ((name, case), (eid, text)) in enumerate(zip(cases, events), start=1):
        kind, cause = expected(policy, case)
        want_eid = {"allow": 20, "refuse": 21, "escalate": 22}[kind]
        got_cause = re.search(r"cause=(\d+)", text)
        good = eid == want_eid and f"seq={index} " in text + " " and \
            (kind == "allow" or (got_cause is not None and int(got_cause.group(1)) == cause))
        good = good and f"receipt={first_receipt + index - 1}" in text
        rule = re.search(r"rule=(\d+)", text)
        if rule and kind != "allow":
            good = good and built["rules"][int(rule.group(1))] == ({"refuse": 1, "escalate": 2}[kind], cause)
        if kind == "allow":
            allowed.append(sent[index - 1])
        check.ok(good, f"{name}: reference says {kind}{'' if kind == 'allow' else f' cause {cause}'}; "
                       f"app event: {text.split(' ', 1)[1]}")
    return allowed


def root_of(run: Path, count: int) -> str:
    lines = core_evidence._lines(run / "receipts.jsonl")
    return root_statement.merkle_root([core_evidence.sha256_hex(line) for line in lines[:count]])


def run_good(exe_dir: Path, keys: Path, downlinked: Path, check: Check, log) -> None:
    policy = Policy.load(gen_image.CORE)
    built = gen_image.build(gen_image.CORE.read_bytes().rstrip(b"\n"))
    run_dir = exe_dir / "cf" / "pprun"
    ground = Ground()
    seen = 0
    # ------------------------------------------------ 1. power on, the S1 sequence, a seal
    core = Core(exe_dir)
    try:
        core.wait_for(r"PRISMPATH_APP initialized, policy active")
        check.ok(any(e == 24 and "v2" in t for e, t in app_events(core)),
                 "the signed version 2 table is loaded at startup (event 24)")
        check.ok(any("RUN BEGUN receipts=0 floor=v0" in t for _e, t in app_events(core)),
                 "a power on reset begins a new run (no receipts, no floor)")
        ground.connect()
        sent = ground.propose(SEQUENCE)
        datagrams, hk = ground.housekeeping(core, 1)
        events = [(e, text) for e, text in app_events(core) if e in (20, 21, 22)]
        log(f"console events before the reset ({len(events)}):")
        for _e, text in events:
            log(f"    {text}")
        allowed = check_decisions(check, policy, built, SEQUENCE, events, 0, sent)
        vehicle = [d[8:] for d in ground.vehicle(datagrams)]
        check.ok(vehicle == allowed, f"exactly the {len(allowed)} allowed proposals reach VEHICLE_CMD, payloads intact "
                                     f"({len(vehicle)} received)")
        for d in ground.vehicle(datagrams)[:1]:
            total = 0xFF
            for byte in d:
                total ^= byte
            check.ok(total == 0, "the republished command carries a valid cFE checksum")
        want = {k: sum(1 for _n, c in SEQUENCE if expected(policy, c)[0] == k) for k in ("allow", "refuse", "escalate")}
        if hk:
            log(f"housekeeping telemetry: { {k: (v.hex() if isinstance(v, bytes) else v) for k, v in hk.items()} }")
            check.ok((hk["proposed"], hk["allowed"], hk["refused"], hk["escalated"], hk["forwarded"], hk["active"]) ==
                     (len(SEQUENCE), want["allow"], want["refuse"], want["escalate"], want["allow"], 1),
                     "housekeeping counters match the sequence")
            check.ok(hk["layout"] == built["layout_hash"], "housekeeping reports the policy layout hash")
            check.ok((hk["receipts"], hk["version"], hk["unreceipted"], hk["record_errors"]) == (len(SEQUENCE), 2, 0, 0),
                     f"housekeeping reports {len(SEQUENCE)} receipts and the version floor 2")
            check.ok(hk["root16"].hex() == root_of(run_dir, len(SEQUENCE))[:32],
                     "housekeeping's root is the Merkle root of the receipts in the run file")
        else:
            check.ok(False, "housekeeping telemetry reached the ground over to_lab")
        sealed = ground.seal(core, 1)
        log(f"seal before the reset: {sealed.split(': ', 1)[-1]}")
        seen = len(SEQUENCE)
        check.ok(f"receipts={seen} root={root_of(run_dir, seen)}" in sealed,
                 f"the first seal signs the root over the {seen} receipts")

        # ------------------------------------------------ 2. a processor reset, by the ES restart command
        send(ground.tx, packet(ES_CMD_MID, ES_RESTART_CC, struct.pack("<H", PROCESSOR_RESET)))
        check.ok(core.exited(20), "the cFE ES restart command (processor reset) ends the cFE instance")
        log("processor reset: " + " | ".join(line for line in core.lines if "PROCESSOR" in line))
    finally:
        core.stop()

    core = Core(exe_dir, ())                                       # the boot record says processor reset
    try:
        core.wait_for(r"PRISMPATH_APP initialized")
        check.ok(any("Starting the cFE with a PROCESSOR reset" in line for line in core.lines),
                 "the next boot is a processor reset, from the PSP's boot record")
        events = app_events(core)
        log("after the reset: " + " | ".join(t for e, t in events if e in (24, 25, 30, 31, 32, 1)))
        check.ok(any(e == 30 and f"RUN RESTORED from CDS receipts={seen} floor=v2" in t for e, t in events),
                 f"the run is restored from the Critical Data Store: {seen} receipts, floor version 2")
        check.ok(any(e == 1 and "policy active, processor reset" in t for e, t in events),
                 "the same signed version 2 table is accepted against the restored floor")

        # ------------------------------------------------ 3. more proposals, then an older and a tampered table
        ground.connect()
        sent = ground.propose(AFTER_RESET)
        datagrams, hk = ground.housekeeping(core, 1)
        events = [(e, text) for e, text in app_events(core) if e in (20, 21, 22)]
        for _e, text in events:
            log(f"    {text}")
        allowed = check_decisions(check, policy, built, AFTER_RESET, events, seen, sent)
        check.ok([d[8:] for d in ground.vehicle(datagrams)] == allowed,
                 "after the reset exactly the allowed proposals reach VEHICLE_CMD")
        seen += len(AFTER_RESET)
        check.ok(hk is not None and hk["receipts"] == seen and hk["root16"].hex() == root_of(run_dir, seen)[:32],
                 f"housekeeping continues: {seen} receipts and their root")

        tbl = exe_dir / "cf" / "pp_app_policy.tbl"
        _headers, good = table.split(tbl.read_bytes())
        (exe_dir / "cf" / "pp_policy_v1.tbl").write_bytes(
            table.signed_file(tbl.read_bytes(), keys / "authority.key", version=1))
        tampered = bytearray(tbl.read_bytes())
        tampered[table.HEADERS + table.OFF["Image"] + 56] ^= 0x01    # thrust > 100 becomes > 101, not signed again
        (exe_dir / "cf" / "pp_policy_bad.tbl").write_bytes(bytes(tampered))
        ground.table_load(core, "/cf/pp_policy_v1.tbl", 1)
        ground.table_load(core, "/cf/pp_policy_bad.tbl", 2)
        rejected = [t for e, t in app_events(core) if e == 25]
        loaded = [t for e, t in app_events(core) if e == 24]
        log("table loads: " + " | ".join(rejected))
        check.ok(any("cause=9" in t for t in rejected[:1]),
                 "the authority's version 1 table, below the floor, is refused as image:version-replay (9)")
        check.ok(any("cause=2" in t for t in rejected[1:2]),
                 "the version 2 table with a threshold changed and not signed again is refused as sig:invalid (2)")
        check.ok(len(loaded) == 1, "no refused table was activated (one POLICY LOADED event, at startup)")

        before = len([1 for e, _t in app_events(core) if e in (20, 21, 22)])
        sent = ground.propose(AFTER_LOADS)
        datagrams, hk = ground.housekeeping(core, 2)
        events = [(e, text) for e, text in app_events(core) if e in (20, 21, 22)][before:]
        for _e, text in events:
            log(f"    {text}")
        for (name, case), (eid, text) in zip(AFTER_LOADS, events):
            kind, cause = expected(policy, case)
            check.ok(eid == {"allow": 20, "refuse": 21, "escalate": 22}[kind] and f"receipt={seen}" in text,
                     f"{name}: still decided by version 2 ({kind}), receipt {seen}: {text.split(' ', 1)[1]}")
            seen += 1
        sealed = ground.seal(core, 1)
        log(f"seal after the reset: {sealed.split(': ', 1)[-1]}")
        check.ok(f"receipts={seen} root={root_of(run_dir, seen)}" in sealed,
                 f"the second seal signs the root over all {seen} receipts")
    finally:
        core.stop()
        ground.close()

    # ------------------------------------------------ 4. the downlink, verified on the ground
    if downlinked.exists():
        shutil.rmtree(downlinked)
    downlink.fetch(run_dir, downlinked)
    log(f"downlinked {sorted(p.name for p in run_dir.iterdir())} as {sorted(p.name for p in downlinked.iterdir())}")
    receipts = [core_evidence.canon2.loads(line) for line in core_evidence._lines(downlinked / "receipts.jsonl")]
    check.ok(len(receipts) == seen and [r["idx"] for r in receipts] == list(range(seen)),
             f"the downlinked run holds {seen} receipts, numbered without a gap across the reset")
    check.ok({r["case"] for r in receipts} == {"v2"} and [r["reading"] for r in receipts] == list(range(seen)),
             "every receipt is of the one version 2 case, its readings continuing across the reset")
    cli = subprocess.run([sys.executable, "-m", "prismpath", "evidence", "verify", str(downlinked), "--sample", "all",
                          "--pin-authority", str(keys / "authority.pub"), "--pin-instance", str(keys / "instance.pub")],
                         capture_output=True, text=True, cwd=REPO)
    log(f"$ prismpath evidence verify <downlink> --sample all --pin-authority <ground>/authority.pub "
        f"--pin-instance <ground>/instance.pub\n{cli.stdout.strip()}{cli.stderr.strip()}")
    check.ok(cli.returncode == 0 and "verified" in cli.stdout,
             "prismpath evidence verify accepts the downlinked run, both keys pinned, every receipt replayed")
    try:
        summary = downlink.verify(downlinked, keys)
        roots = summary["roots"]
        log(f"root history: {[(r['leaves'], r['root'][:16]) for r in roots]}")
        check.ok(summary["replayed"] == seen and summary["agree"] == seen and summary["root_statement"] == "signed",
                 f"all {seen} receipts replayed through the reference kernel agree; the root statement is signed "
                 "with the pinned instance key")
        check.ok([r["leaves"] for r in roots] == [len(SEQUENCE), seen],
                 "the root signed before the reset is the root of the first receipts after it")
    except downlink.Bad as bad:
        check.ok(False, f"the ground verifies the downlinked run: {bad}")


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
    parser.add_argument("--keys", default=None, help="the ground's key directory (default: a new temporary one)")
    parser.add_argument("--downlink", default=None, help="where to copy the run off the vehicle (default: temporary)")
    args = parser.parse_args(argv)
    exe_dir = Path(args.build_dir)
    if not (exe_dir / "core-cpu1").exists():
        print(f"no staged cFS build at {exe_dir} (see integrations/cfs/README.md)", file=sys.stderr)
        return 2
    check = Check()

    def log(line: str) -> None:
        print(line, flush=True)

    work = Path(tempfile.mkdtemp(prefix="pp-cfs-"))
    keys = Path(args.keys) if args.keys else work / "keys"
    downlinked = Path(args.downlink) if args.downlink else work / "downlink"
    cf = exe_dir / "cf"
    original = (cf / "pp_app_policy.tbl").read_bytes()
    try:
        provision.provision(exe_dir, keys)
        log("== the S1 sequence, a seal, a processor reset, more proposals, two refused loads, a seal ==")
        run_good(exe_dir, keys, downlinked, check, log)
        log("== a table with a corrupted image ==")
        run_bad_image(exe_dir, check, log)
    finally:
        (cf / "pp_app_policy.tbl").write_bytes(original)
        for name in ("pp_authority.pub", "pp_instance.key", "pp_policy_v1.tbl", "pp_policy_bad.tbl"):
            (cf / name).unlink(missing_ok=True)
        if not args.keys and not args.downlink:
            shutil.rmtree(work, ignore_errors=True)
    print("\n".join(check.report))
    if check.failures:
        print(f"\nFAILED: {len(check.failures)} check(s)")
        return 1
    print(f"\nall {len(check.report)} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
