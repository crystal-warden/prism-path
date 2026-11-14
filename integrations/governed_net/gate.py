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
import selectors
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
    """The XDP decision on its userspace path, standing in for the kernel in front of the tool server.

    A client datagram is wrapped in the Ethernet/IPv4/UDP frame the interface would see, with the frame's
    IPv4 DESTINATION set to the configured match address and its UDP destination to the match port (so the
    program recognises it), and its SOURCE set to the client's own loopback address (its LAN identity). The
    frame is decided by gn_batch; only an ALLOW is forwarded to the real tool server. So the two clients of
    the two-client run reach the server from distinct sources (each forwarded through a back socket bound to
    that client's loopback address), exactly as two LAN hosts would, and the receipts and findings are kept
    per client. THIS IS NOT THE KERNEL (no verifier, no JIT, no driver, and a local process could still
    reach the server's loopback port directly, which the server's own re-decision covers)."""

    def __init__(self, policy: NetPolicy, build_dir: Path, run: Path, keys: Path, server: Tuple[str, int],
                 match_ip: str = None, match_port: int = None):
        self.match_ip = match_ip or fr.SERVER_IP
        self.match_port = match_port or p.PORT
        policy_dir = Path(build_dir) / "policy"
        if not (policy_dir / "net_rules.actions").exists():
            write_build(policy_dir, policy)
        binary = xdp_userspace.build(Path(build_dir) / "bin")
        self.stream = xdp_userspace.Stream(binary, policy_dir / "net_rules.ppt", policy_dir / "net_rules.actions",
                                           server_ip=self.match_ip, port=self.match_port)
        self.logger = ReceiptLogger(policy, run, keys)
        self.server = server
        self.front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.status = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.backs: Dict[str, socket.socket] = {}        # client source ip -> its back socket to the server
        self.pending: Dict[int, Tuple[str, int]] = {}    # request id -> the client's front address
        self.selector = selectors.DefaultSelector()
        self.counts = {"frames": 0, "passed": 0, "dropped": 0, "other": 0}
        self.lock = threading.Lock()
        self.stop = threading.Event()

    def bind(self, host: str = "127.0.0.1") -> Tuple[int, int]:
        self.front.bind((host, 0))
        self.status.bind((host, 0))
        return self.front.getsockname()[1], self.status.getsockname()[1]

    def _back_for(self, client_ip: str) -> socket.socket:
        """A back socket bound to the client's own address, so the server sees each client as a distinct
        source (as two LAN hosts would appear). On loopback every 127.0.0.0/8 address is bindable."""
        sock = self.backs.get(client_ip)
        if sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.bind((client_ip, 0))
            except OSError:
                sock.bind(("127.0.0.1", 0))              # a source we cannot bind: fall back, identity by port
            self.backs[client_ip] = sock
            self.selector.register(sock, selectors.EVENT_READ)
        return sock

    def _front_loop(self) -> None:
        self.front.settimeout(0.2)
        while not self.stop.is_set():
            try:
                raw, addr = self.front.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            with self.lock:
                self.counts["frames"] += 1
                frame = fr.build(raw, src=addr[0], sport=addr[1], dst=self.match_ip, dport=self.match_port)
                row = self.stream.decide(frame)
                if row.outcome != fr.OTHER:
                    self.logger.consume(Event.from_userspace(row))
                if row.outcome == fr.ALLOW:
                    self.counts["passed"] += 1
                    self.pending[row.request_id] = addr
                    self._back_for(addr[0]).sendto(raw, self.server)
                elif row.outcome == fr.OTHER:
                    self.counts["other"] += 1
                else:
                    self.counts["dropped"] += 1

    def _back_loop(self) -> None:
        while not self.stop.is_set():
            for key, _mask in self.selector.select(timeout=0.2):
                try:
                    raw, _addr = key.fileobj.recvfrom(65535)
                except OSError:
                    continue
                try:
                    reply = p.decode_reply(raw)
                except p.Malformed:
                    continue
                with self.lock:
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
        for sock in list(self.backs.values()):
            self.selector.unregister(sock)
            sock.close()
        self.selector.close()
        for sock in (self.front, self.status):
            sock.close()
        self.stream.close()
        manifest = self.logger.close()
        return {"manifest": manifest, "counts": self.counts, "findings": self.logger.findings,
                "clients": self.logger.clients()}


def main(argv=None) -> int:
    """Run until standard input ends. Prints the front port and the status port first."""
    parser = argparse.ArgumentParser(description="the XDP decision on its userspace path, in front of the tool server")
    parser.add_argument("--server-port", type=int, required=True)
    parser.add_argument("--build", required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--keys", required=True)
    parser.add_argument("--match-ip", default=None, help="the frame destination the program matches (default the doc server IP)")
    parser.add_argument("--match-port", type=int, default=None)
    args = parser.parse_args(argv)
    gate = Gate(NetPolicy.load(), Path(args.build), Path(args.run), Path(args.keys), ("127.0.0.1", args.server_port),
                match_ip=args.match_ip, match_port=args.match_port)
    front, status = gate.bind()
    print(front, status, flush=True)
    gate.start()
    sys.stdin.read()
    print(json.dumps(gate.close()), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
