# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The userspace gate: the XDP decision applied in front of the tool server on a host with no privileges.

THIS IS NOT THE KERNEL. On the enforcement host the XDP program sits on the wire's interface and decides
each frame before the stack delivers it; here, where loading BPF needs privileges this run does not have,
a UDP relay on loopback plays its part. Every datagram the client sends to the gate is wrapped in the
Ethernet + IPv4 + UDP frame the interface would see (`frame.build`), decided by the XDP program's own text
on its userspace path (`xdp_userspace.Stream`, prismpath-ebpf/gnet/gn_batch.c), reported to the receipt
logger as the ring buffer would report it, and forwarded to the tool server only when the outcome is
ALLOW, which is exactly when the program returns XDP_PASS. A dropped datagram gets no reply, as on the
wire; the client asks the logger's status port what became of it.

What this path shares with the kernel: the program's parse, strict reading, register fill, evaluator and
action, the table bytes and the action file. What it does not: the verifier, the JIT, the driver, the
ring buffer itself, and the fact that a packet cannot reach the server except through it. A local
process could send to the server's loopback port directly; the server's own re-decision is what holds
then, and the lying client probes do exactly that.
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
import threading
from pathlib import Path
from typing import Dict, Tuple

from . import frame as fr
from . import protocol as p
from . import xdp_userspace
from .policy import NetPolicy, write_build
from .receipt_logger import Event, ReceiptLogger


class Gate:
    def __init__(self, policy: NetPolicy, build_dir: Path, run: Path, keys: Path, server: Tuple[str, int]):
        policy_dir = Path(build_dir) / "policy"
        if not (policy_dir / "net_rules.actions").exists():
            write_build(policy_dir, policy)
        binary = xdp_userspace.build(Path(build_dir) / "bin")
        self.stream = xdp_userspace.Stream(binary, policy_dir / "net_rules.ppt", policy_dir / "net_rules.actions")
        self.logger = ReceiptLogger(policy, run, keys)
        self.server = server
        self.front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.status = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.pending: Dict[int, Tuple[str, int]] = {}
        self.counts = {"frames": 0, "passed": 0, "dropped": 0}
        self.stop = threading.Event()

    def bind(self, host: str = "127.0.0.1") -> Tuple[int, int]:
        self.front.bind((host, 0))
        self.back.bind((host, 0))
        self.status.bind((host, 0))
        return self.front.getsockname()[1], self.status.getsockname()[1]

    def _front_loop(self) -> None:
        self.front.settimeout(0.2)
        while not self.stop.is_set():
            try:
                raw, addr = self.front.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            self.counts["frames"] += 1
            row = self.stream.decide(fr.build(raw, sport=addr[1]))
            if row.outcome != fr.OTHER:
                self.logger.consume(Event.from_userspace(row))
            if row.outcome == fr.ALLOW:
                self.counts["passed"] += 1
                self.pending[row.request_id] = addr
                self.back.sendto(raw, self.server)
            else:
                self.counts["dropped"] += 1

    def _back_loop(self) -> None:
        self.back.settimeout(0.2)
        while not self.stop.is_set():
            try:
                raw, _addr = self.back.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                reply = p.decode_reply(raw)
            except p.Malformed:
                continue
            addr = self.pending.pop(reply.request_id, None)
            if addr:
                self.front.sendto(raw, addr)

    def start(self):
        self.threads = [threading.Thread(target=self._front_loop, daemon=True),
                        threading.Thread(target=self._back_loop, daemon=True),
                        threading.Thread(target=self.logger.serve_status, args=(self.status, self.stop), daemon=True)]
        for thread in self.threads:
            thread.start()

    def close(self) -> Dict:
        self.stop.set()
        for thread in self.threads:
            thread.join()
        for sock in (self.front, self.back, self.status):
            sock.close()
        self.stream.close()
        manifest = self.logger.close()
        return {"manifest": manifest, "counts": self.counts, "findings": self.logger.findings}


def main(argv=None) -> int:
    """Run until standard input ends. Prints the front port and the status port first."""
    parser = argparse.ArgumentParser(description="the XDP decision on its userspace path, in front of the tool server")
    parser.add_argument("--server-port", type=int, required=True)
    parser.add_argument("--build", required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--keys", required=True)
    args = parser.parse_args(argv)
    gate = Gate(NetPolicy.load(), Path(args.build), Path(args.run), Path(args.keys), ("127.0.0.1", args.server_port))
    front, status = gate.bind()
    print(front, status, flush=True)
    gate.start()
    sys.stdin.read()
    print(json.dumps(gate.close()), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
