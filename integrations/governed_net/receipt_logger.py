# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The receipt logger: each XDP decision, as the ring buffer reports it, written as a canon/2 core receipt.

XDP cannot sign, and it cannot write a file. What it can do is report, through a ring buffer, the decided
fields of each request (command, handle class, arguments, lengths), the request id, the index of the image
its tables hold, the matched rule and the cause. This logger, in userspace on the enforcement host:

  * rebuilds the reading from the event's fields (the same seven integers the program put in its
    registers) and the verdict from the matched rule (a route to that rule's target in the signed image,
    or the core's `route:no-matching-edge`), checks the event's cause against the image's, and writes the
    `prismpath.core-receipt/1` line through `governed_harness.evidence.EpisodeRun`, decider `xdp`;
  * seals the run when it stops (the cases, the image attestation under the authority key, the manifest
    and the signed root over every receipt), so `formal/diff/core_evidence.py verify` checks it unchanged,
    replaying each receipt through the Lean oracle, and `evidence.replay` re-decides every reading with the
    Python reference and compares the receipt bytes;
  * keeps, apart from the receipts, a line per frame XDP dropped as malformed or with no policy loaded
    (`drops.jsonl`): such a frame has no reading the core could decide, so it is counted, not receipted;
  * answers status queries (`STATUS_QUERY` datagrams on its own port, never the agent protocol's): a
    client whose request was dropped hears nothing on the wire, and asks here what became of it. The
    answer is information for the client, not authority; the receipts are the record.

In the kernel deployment the events come from `gn_loader events` as hex lines; on this host they come from
the userspace gate (gate.py), in process.
"""
from __future__ import annotations

import json
import socket
import struct
import threading
from pathlib import Path
from typing import Dict, NamedTuple, Optional

from integrations.governed_harness import evidence

from . import frame as fr
from . import protocol as p
from .policy import NetPolicy

EVENT = struct.Struct("<QQIiHBBBBBBHHIIIII")     # struct gn_event, gnet/gn_common.h (56 bytes, host order)
assert EVENT.size == 56
STATUS_QUERY = struct.Struct(">IQ")              # "GNSQ", request id
STATUS_MAGIC = 0x474E5351
DECIDER = "xdp"


class Event(NamedTuple):
    request_id: int
    t_ns: int
    image_index: int
    edge: int
    cause: int
    outcome: int
    reason: int
    version: int
    cmd: int
    hclass: int
    name_len: int
    data_len: int
    src_port: int
    handle: int
    arg0: int
    arg1: int
    src_ip: int

    @classmethod
    def from_ring(cls, raw: bytes) -> "Event":
        values = EVENT.unpack(raw)
        return cls(*values[:17])

    @classmethod
    def from_userspace(cls, row) -> "Event":
        return cls(row.request_id, 0, row.image_index, row.edge, row.cause, row.outcome, row.reason, 1, row.cmd,
                   row.hclass, row.name_len, row.data_len, row.src_port, row.handle, row.arg0, row.arg1, 0)

    def reading(self) -> Dict[str, int]:
        return {"version": self.version, "cmd": self.cmd, "hclass": self.hclass, "arg0": self.arg0, "arg1": self.arg1,
                "name_len": self.name_len, "data_len": self.data_len}


class ReceiptLogger:
    def __init__(self, policy: NetPolicy, run: Path, keys: Path, case_id: str = "net", image_index: int = 1):
        self.policy, self.image_index = policy, image_index
        self.run = evidence.EpisodeRun(Path(run), case_id, policy.image, keys, decider=DECIDER)
        self.drops = open(Path(run) / "drops.jsonl", "w")
        self.by_request: Dict[int, Dict] = {}
        self.findings = []
        self.lock = threading.Lock()

    def consume(self, ev: Event) -> Optional[int]:
        """One decision; the receipt index of a decided request, else None."""
        with self.lock:
            if ev.outcome in (fr.DROP_BAD, fr.DROP_NOPOL):
                self.drops.write(json.dumps({"request_id": ev.request_id, "outcome": fr.OUTCOMES[ev.outcome],
                                             "reason": ev.reason}) + "\n")
                self.drops.flush()
                self.by_request.setdefault(ev.request_id, {"status": p.BAD_REQUEST, "cause": 0, "receipt": 0})
                return None
            if ev.image_index != self.image_index:
                self.findings.append({"request_id": ev.request_id, "finding": "image-index", "got": ev.image_index})
            verdict = self.policy.verdict_of_edge(ev.edge)
            if ev.edge >= 0:
                kind, _cause, code = self.policy.rule_decision(ev.edge)
            else:
                kind, code = "refuse", verdict["code"]
            if (code or 0) != ev.cause or (ev.outcome == fr.ALLOW) != (kind == "allow"):
                # the program's action disagrees with the signed image's target: recorded, and the
                # receipt is still the image's decision of the reading
                self.findings.append({"request_id": ev.request_id, "finding": "action-mismatch",
                                      "event": [ev.outcome, ev.cause], "image": [kind, code]})
            idx = self.run.record(self.policy.reading_bytes(ev.reading()), verdict)
            status = {"allow": p.OK, "refuse": p.REFUSED, "escalate": p.ESCALATED}[kind]
            self.by_request[ev.request_id] = {"status": status, "cause": code or 0, "receipt": idx,
                                              "kind": kind, "reading": ev.reading()}
            return idx

    def status(self, request_id: int) -> p.Reply:
        with self.lock:
            row = self.by_request.get(request_id)
        if row is None:
            return p.Reply(p.STATUS_UNKNOWN, request_id)
        return p.Reply(row["status"], request_id, row["cause"], row["receipt"])

    def serve_status(self, sock: socket.socket, stop: threading.Event) -> None:
        sock.settimeout(0.2)
        while not stop.is_set():
            try:
                raw, addr = sock.recvfrom(64)
            except socket.timeout:
                continue
            except OSError:
                return
            if len(raw) != STATUS_QUERY.size:
                continue
            magic, request_id = STATUS_QUERY.unpack(raw)
            if magic == STATUS_MAGIC:
                sock.sendto(p.encode_reply(self.status(request_id)), addr)

    def close(self) -> Dict:
        with self.lock:
            self.drops.close()
            (self.run.run / "findings.json").write_text(json.dumps(self.findings, indent=1))
            return self.run.close()


def main(argv=None) -> int:
    """Kernel mode: read `gn_loader events` hex lines on standard input until it ends, then seal."""
    import argparse
    import sys
    parser = argparse.ArgumentParser(description="write the XDP program's decisions as signed core receipts")
    parser.add_argument("--run", required=True, help="a directory that does not exist yet")
    parser.add_argument("--keys", required=True)
    parser.add_argument("--status-port", type=int, default=p.PORT + 1)
    parser.add_argument("--status-bind", default="127.0.0.1")
    args = parser.parse_args(argv)
    logger = ReceiptLogger(NetPolicy.load(), Path(args.run), Path(args.keys))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.status_bind, args.status_port))
    stop = threading.Event()
    thread = threading.Thread(target=logger.serve_status, args=(sock, stop), daemon=True)
    thread.start()
    for line in sys.stdin:
        line = line.strip()
        if line:
            logger.consume(Event.from_ring(bytes.fromhex(line)))
    stop.set()
    thread.join()
    sock.close()
    print(json.dumps(logger.close()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
