#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Certify ppt_net's real packet front end: the reading it builds from a frame, decided in kernel, must
route as the host engine routes the same frame's canonical reading.

The canonical reading is defined here, independently of ppt_net.bpf.c, from the header layouts: the eight
schema fields, each present when the frame carries it and absent when it does not. Ports are present only
on the first fragment of a TCP or UDP packet whose whole header is in the frame, tcp_flags only on such a
TCP packet; an address is its unsigned 32 bit value. Every frame is decided by the host engine on that
reading, and the expected first hop is written beside the frame and the table in the record format
`loader certify` reads, which `loader netcert` replays through ppt_net_prog with BPF_PROG_TEST_RUN.

The frames aim at what the front end got wrong before October 2026: ICMP and other protocols without
ports, a TCP header cut short, a later fragment whose payload looks like ports, addresses on both sides
of 128.0.0.0, and options in the IP header. The flows are net_frontend_cert.md, built for this, and the
two triage flows that run on live traffic. The compiler half is checked too: net_compile must refuse an
ordering on an address and a negative address constant, which the kernel could not decide faithfully.

    python3 net_cert.py <out.frames.bin>            # build the records, check the refusals
    sudo ./loader x netcert <out.frames.bin>        # replay them in kernel; exit 0 only on every match
"""
import socket
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "prismpath-hw"))
sys.path.insert(0, str(REPO))
import net_compile                                         # noqa: E402
from prismpath.kernel.engine import run                     # noqa: E402
from prismpath.kernel.parser import parse, parse_file       # noqa: E402

FLOWS = ["net_frontend_cert.md", "net_triage.md", "net_triage_enforce.md"]
TCP, UDP, ICMP, GRE = 6, 17, 1, 47


def frame(src, dst, proto, l4=b"", frag_off=0, ttl=64, options=b"", total_len=None, cut=None):
    """An Ethernet + IPv4 frame. `total_len` overrides the IP length field, `cut` truncates the frame."""
    ihl = 5 + len(options) // 4
    tot = total_len if total_len is not None else ihl * 4 + len(l4)
    ip = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, 0, tot, 0x1234, frag_off, ttl, proto, 0,
                     socket.inet_aton(src), socket.inet_aton(dst)) + options
    out = struct.pack("!6s6sH", b"\xff" * 6, b"\x02" * 6, 0x0800) + ip + l4
    return out[:cut] if cut is not None else out


def tcp(sport, dport, flags, payload=b""):
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, flags, 0xFFFF, 0, 0) + payload


def udp(sport, dport, payload=b""):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def canonical_reading(raw: bytes) -> dict:
    """The reading the front end must build, from the header layouts alone. Absent fields are omitted."""
    ver_ihl, _, tot, _, frag_off, ttl, proto = struct.unpack_from("!BBHHHBB", raw, 14)
    src, dst = struct.unpack_from("!II", raw, 14 + 12)
    ihl = (ver_ihl & 0x0F) * 4
    reading = {"src_ip": src, "dst_ip": dst, "protocol": proto, "pkt_len": tot, "ttl": ttl}
    l4 = 14 + ihl
    first_fragment = (frag_off & 0x1FFF) == 0
    if first_fragment and proto == TCP and len(raw) >= l4 + 20:
        reading["src_port"], reading["dst_port"] = struct.unpack_from("!HH", raw, l4)
        reading["tcp_flags"] = raw[l4 + 13]
    elif first_fragment and proto == UDP and len(raw) >= l4 + 8:
        reading["src_port"], reading["dst_port"] = struct.unpack_from("!HH", raw, l4)
    return reading


def frames():
    """(name, frame) for every case."""
    looks_like_ssh = struct.pack("!HH", 22, 22) + b"\x00" * 20
    return [
        ("tcp syn from 10.0.0.5", frame("10.0.0.5", "10.0.0.9", TCP, tcp(40000, 22, 0x02))),
        ("tcp ack 192.168.1.50 to 10.0.0.6", frame("192.168.1.50", "10.0.0.6", TCP, tcp(40001, 443, 0x10))),
        ("tcp psh ack high to high port 80", frame("192.168.1.50", "192.168.1.60", TCP, tcp(40002, 80, 0x18))),
        ("tcp syn to 10.0.0.7", frame("172.16.0.1", "10.0.0.7", TCP, tcp(40003, 8080, 0x02))),
        ("tcp syn high to high", frame("203.0.113.9", "198.51.100.7", TCP, tcp(40004, 25, 0x02))),
        ("tcp to 8080", frame("203.0.113.9", "198.51.100.7", TCP, tcp(40005, 8080, 0x10))),
        ("udp dns", frame("192.168.1.50", "8.8.8.8", UDP, udp(5353, 53))),
        ("udp quic", frame("192.168.1.50", "142.250.0.1", UDP, udp(50000, 443))),
        ("udp high port", frame("10.1.1.1", "10.1.1.2", UDP, udp(5000, 5001))),
        ("udp to port 0", frame("10.1.1.1", "10.1.1.2", UDP, udp(0, 0))),
        ("icmp echo, no ports", frame("192.168.1.50", "8.8.8.8", ICMP, b"\x08\x00" + b"\x00" * 6 + b"A" * 56)),
        ("icmp from 10.0.0.5", frame("10.0.0.5", "8.8.8.8", ICMP, b"\x08\x00" + b"\x00" * 6)),
        ("gre, no ports", frame("192.0.2.1", "192.0.2.2", GRE, b"\x00" * 24)),
        ("tcp header cut short", frame("192.168.1.50", "10.0.0.9", TCP, tcp(40006, 22, 0x02), cut=14 + 20 + 10)),
        ("udp header cut short", frame("192.168.1.50", "10.0.0.9", UDP, udp(5000, 53), cut=14 + 20 + 6)),
        ("udp later fragment, payload like ssh", frame("192.168.1.50", "10.0.0.9", UDP, looks_like_ssh,
                                                       frag_off=185)),
        ("tcp later fragment, payload like syn", frame("192.168.1.50", "10.0.0.9", TCP, tcp(40007, 22, 0x02),
                                                       frag_off=0x2000 | 64)),
        ("tcp first fragment, more fragments", frame("192.168.1.50", "10.0.0.9", TCP, tcp(40008, 8080, 0x10),
                                                     frag_off=0x2000)),
        ("tcp don't fragment", frame("192.168.1.50", "10.0.0.9", TCP, tcp(40009, 443, 0x10), frag_off=0x4000)),
        ("ip options then tcp", frame("192.168.1.50", "10.0.0.9", TCP, tcp(40010, 25, 0x10),
                                      options=b"\x01\x01\x01\x00")),
        ("jumbo tcp", frame("192.168.1.50", "10.0.0.9", TCP, tcp(40011, 9000, 0x10, b"A" * 1460))),
        ("jumbo icmp", frame("192.168.1.50", "10.0.0.9", ICMP, b"\x08\x00" + b"\x00" * 6 + b"A" * 1450)),
        ("udp 9999 (enforce drop)", frame("192.168.1.50", "10.0.0.9", UDP, udp(5000, 9999))),
        ("src 127.255.255.255", frame("127.255.255.255", "10.0.0.6", UDP, udp(1, 1))),
        ("src 128.0.0.0", frame("128.0.0.0", "10.0.0.6", UDP, udp(1, 1))),
        ("src 255.255.255.255", frame("255.255.255.255", "10.0.0.9", UDP, udp(1, 1))),
        ("src 0.0.0.0", frame("0.0.0.0", "10.0.0.9", ICMP, b"\x08\x00" + b"\x00" * 6)),
        ("dst 138.0.0.6, high bits set", frame("10.0.0.9", "138.0.0.6", TCP, tcp(1, 1, 0x10))),
        ("ttl 1", frame("10.0.0.9", "10.0.0.8", UDP, udp(33434, 33434), ttl=1)),
        ("length field larger than frame", frame("10.0.0.9", "10.0.0.8", UDP, udp(1, 53), total_len=1500)),
    ]


def first_hop(graph, reading):
    """The node the start node routes this reading to, or None when no edge matches."""
    result = run(graph, lambda node, instruction, state, reading=reading: reading)
    return result.path[1] if len(result.path) > 1 else None


REFUSED_FLOWS = {
    "an ordering on an address": "-> a: when src_ip > 167772160\n-> b: else\n",
    "a negative address constant": "-> a: when dst_ip == -1062731519\n-> b: else\n",
    "a negative constant in an address list": "-> a: when dst_ip in [1, -2]\n-> b: else\n",
}


def check_refusals():
    """net_compile must refuse every atom the kernel would decide unfaithfully. Returns failures."""
    failures = []
    for what, edges in REFUSED_FLOWS.items():
        flow = f"---\nname: refused\nstart: s\n---\n## s\n{edges}## a\nA.\n## b\nB.\n"
        img = net_compile.compile_with_schema(parse(flow), net_compile.SCHEMA)
        if not net_compile.address_refusals(img):
            failures.append(f"net_compile accepted {what}")
    return failures


def main():
    out_path = Path(sys.argv[1])
    failures = check_refusals()
    print(f"compiler refusals: {len(REFUSED_FLOWS) - len(failures)}/{len(REFUSED_FLOWS)} refused")
    records, routes = [], {}
    for flow_name in FLOWS:
        graph = parse_file(str(HERE / flow_name))
        img = net_compile.compile_with_schema(graph, net_compile.SCHEMA)
        refused = net_compile.address_refusals(img)
        if refused:
            failures.append(f"{flow_name} refused by net_compile: {refused}")
            continue
        table = img.serialize()
        names = [node_name for node_name, _ in img.nodes]
        for case_name, raw in frames():
            hop = first_hop(graph, canonical_reading(raw))
            expected = names.index(hop) if hop is not None else -1
            routes.setdefault(flow_name, {}).setdefault(hop, []).append(case_name)
            records.append(struct.pack("<iI", expected, len(table)) + table + struct.pack("<I", len(raw)) + raw)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(b"".join(records))
    for flow_name, by_route in routes.items():
        print(f"{flow_name}: " + ", ".join(f"{route} {len(cases)}" for route, cases in by_route.items()))
    print(f"wrote {len(records)} records ({len(FLOWS)} flows x {len(frames())} frames) to {out_path}")
    for failure in failures:
        print(f"  FAIL {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
