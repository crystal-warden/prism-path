#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The collector against the governed net program in a real kernel (CI's ebpf_kernel job, kernel_test.sh).

Run as an ordinary account in the feed's group while gn_xdp.pin.bpf.o is attached to `lo` (generic XDP),
its maps filled with the network policy for 127.0.0.1, and the collector running under its systemd unit.
It subscribes, sends agent requests over loopback (allowed, refused, escalated and malformed ones), and
holds every decision record to the request it stands for and to the plain rules (owner_rules.expected),
each leaf to its frame, every seal to the tree it rebuilds from the join seal's peaks, and the enforcer's
own counters, read by the collector from the read only maps, to what it sent.
"""
import argparse
import hashlib
import json
import socket
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from integrations.governed_net import owner_rules, protocol as p  # noqa: E402
from prismpath.ledgers.root_statement import MerkleAccumulator  # noqa: E402

SUBSCRIPTION = b'{"op":"subscribe","protocol":"prismpath.collector/1"}\n'
OUTCOME = {"allow": "allow", "refuse": "drop_policy", "escalate": "drop_policy"}


def requests():
    """Well formed requests over every command and class, and three malformed ones, with what each must
    become: (datagram, request id, expected outcome name, expected cause name or None, reason)."""
    out = []
    request_id = 1000
    for cmd in range(1, p.CMD_MAX + 1):
        for hclass in ([p.H_WS_FILE, p.H_WS_DIR, p.H_TC_FILE, p.H_TC_DIR, 7] if cmd in p.USES_HANDLE else [0]):
            for arg in ([1, 99] if cmd in p.USES_ARG0 or cmd in p.USES_ARG1 else [0]):
                request_id += 1
                req = p.Request(cmd=cmd, request_id=request_id, hclass=hclass, handle=5 if cmd in p.USES_HANDLE else 0,
                                arg0=arg if cmd in p.USES_ARG0 else 0, arg1=arg * 50 if cmd in p.USES_ARG1 else 0,
                                name=b"note.txt" if cmd in p.USES_NAME else b"", data=b"x" * 3 if cmd in p.USES_DATA else b"")
                raw = p.encode(req)
                p.decode(raw)            # well formed by the strict reader
                kind, cause = owner_rules.expected(req.reading())
                out.append((raw, request_id, OUTCOME[kind], cause, 0))
    for reason, req in (("magic", p.Request(cmd=p.LIST, request_id=7001, hclass=2, handle=1, magic=0x41414141)),
                        ("version", p.Request(cmd=p.LIST, request_id=7002, hclass=2, handle=1, version=2)),
                        ("unused-field", p.Request(cmd=p.GIT_STATUS, request_id=7003, arg0=4))):
        out.append((p.encode(req), req.request_id, "drop_malformed", None, p.REASON_CODE[reason]))
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--socket", required=True)
    parser.add_argument("--port", type=int, default=p.PORT)
    args = parser.parse_args()
    feed = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    feed.connect(args.socket)
    feed.settimeout(30)
    feed.sendall(SUBSCRIPTION)
    lines = feed.makefile("rb")

    def record():
        line = lines.readline()
        if not line:
            raise SystemExit("FAIL the feed ended")
        assert line.endswith(b"\n") and len(line) <= 8192, line[:80]
        return json.loads(line)

    hello = record()
    assert hello["kind"] == "hello" and hello["source"] == "gnet", hello
    join = record()
    assert join["kind"] == "seal" and join["trigger"] == "join", join
    print("hello", json.dumps(hello, sort_keys=True))
    acc = MerkleAccumulator()
    # carry on from the join seal: its peaks and count are the tree so far
    heights = [h for h in range(63, -1, -1) if join["count"] >> h & 1]
    acc._peaks = [(h, bytes.fromhex(peak)) for h, peak in zip(heights, join["peaks"])]
    acc.count = join["count"]
    assert acc.root() == join.get("root", ""), "the join seal's peaks give its root"

    sent = requests()
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for raw, *_ in sent:
        sender.sendto(raw, ("127.0.0.1", args.port))
        time.sleep(0.002)
    expected = {request_id: (outcome, cause, reason) for _raw, request_id, outcome, cause, reason in sent}
    frames = {request_id: raw for raw, request_id, *_ in sent}
    by_reason = {reason: request_id for _raw, request_id, outcome, _cause, reason in sent if outcome == "drop_malformed"}
    seen, seals, status = {}, 0, None
    deadline = time.time() + 60
    while len(seen) < len(sent) or status is None or int(status.get("count", 0)) < acc.count:
        if time.time() > deadline:
            missing = sorted(set(expected) - set(seen))
            raise SystemExit("FAIL timed out: %d of %d decisions; missing %s (%s); last status %s"
                             % (len(seen), len(sent), missing, [expected[rid] for rid in missing], json.dumps(status)))
        value = record()
        if value["kind"] == "decision":
            assert value["index"] == acc.count, ("index", value["index"], acc.count)
            assert value["leaf"] == hashlib.sha256(bytes.fromhex(value["frame"])).hexdigest()
            acc.add(value["leaf"])
            request_id = int(value["request_id"])
            if request_id not in expected and value["outcome_name"] == "drop_malformed":
                # the strict reader stops at a bad magic before the request id, so the event carries none:
                # it stands for the malformed request whose reason it names
                request_id = by_reason.get(value["reason"], request_id)
            if request_id not in expected:
                continue
            outcome, cause, reason = expected[request_id]
            assert value["outcome_name"] == outcome, (request_id, value, outcome)
            assert value["reason"] == reason, (request_id, value, reason)
            assert value.get("cause_name") == cause or (cause is None and value["cause"] == 0), (request_id, value, cause)
            assert value["src_ip"] == "127.0.0.1", value
            if outcome != "drop_malformed":
                req = p.decode(frames[request_id])
                assert value["reading"] == req.reading(), (value["reading"], req.reading())
            seen[request_id] = value
        elif value["kind"] == "seal":
            assert value["count"] == acc.count and value["root"] == acc.root(), ("seal", value, acc.count)
            seals += 1
        elif value["kind"] == "status":
            status = value
        elif value["kind"] in ("gap", "error", "malformed"):
            raise SystemExit("FAIL " + json.dumps(value))
    counters = status["enforcer"]["counters"]
    allows = sum(1 for outcome, _c, _r in expected.values() if outcome == "allow")
    drops = sum(1 for outcome, _c, _r in expected.values() if outcome == "drop_policy")
    bad = sum(1 for outcome, _c, _r in expected.values() if outcome == "drop_malformed")
    assert status["enforcer"]["loaded"] == 1, status
    assert (int(counters["allow"]), int(counters["drop"]), int(counters["malformed"])) == (allows, drops, bad), (counters, allows, drops, bad)
    print("PASS %d decisions (%d allowed, %d refused or escalated, %d malformed) fed, each leaf its frame's hash, "
          "%d seals checked against the tree rebuilt from the join seal, counters %s"
          % (len(seen), allows, drops, bad, seals, json.dumps(counters, sort_keys=True)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
