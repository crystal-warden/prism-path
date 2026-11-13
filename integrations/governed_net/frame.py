# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Frames on the wire, and the Python decision of one frame, held against the XDP program's.

`build` puts a datagram in an Ethernet + IPv4 + UDP frame (the addresses are documentation ranges; the
real wire's are set in SETUP.md). `decide` is the Python side of the differential: the frame level checks
written again from gn_xdp.h's comments, then `protocol.decode`, then the Python kernel's decision of the
reading. It returns the same outcome numbers as the XDP program (GN_OTHER .. GN_DROP_BAD), so a frame's two
decisions compare as tuples. `xdp_userspace.py` runs the XDP program's own text over the same frames.
"""
from __future__ import annotations

import struct
from typing import NamedTuple, Optional

from . import protocol

OTHER, ALLOW, DROP_POLICY, DROP_BAD, DROP_NOPOL, DROP_NOLOG = range(6)
OUTCOMES = {OTHER: "other", ALLOW: "allow", DROP_POLICY: "drop_policy", DROP_BAD: "drop_malformed",
            DROP_NOPOL: "drop_no_policy", DROP_NOLOG: "drop_no_log"}
BAD_FRAGMENT, BAD_UDP_LENGTH, BAD_IP_HEADER = 20, 21, 22
CLIENT_IP, SERVER_IP = "192.0.2.10", "192.0.2.20"      # RFC 5737 documentation addresses


def _ip(text: str) -> bytes:
    return bytes(int(part) for part in text.split("."))


def build(payload: bytes, *, dport: int = protocol.PORT, sport: int = 40000, proto: int = 17, ethertype: int = 0x0800,
          frag: int = 0, ihl: int = 5, udp_len: int = None, ip_len: int = None, pad: int = 0,
          src: str = CLIENT_IP, dst: str = SERVER_IP) -> bytes:
    options = b"\x01" * (ihl * 4 - 20) if ihl > 5 else b""
    udp_len = 8 + len(payload) if udp_len is None else udp_len
    udp = struct.pack(">HHHH", sport, dport, udp_len & 0xFFFF, 0) + payload
    total = (ihl * 4 + len(udp)) if ip_len is None else ip_len
    ip = struct.pack(">BBHHHBBH4s4s", (4 << 4) | (ihl & 0xF), 0, total & 0xFFFF, 0x1234, frag, 64, proto, 0,
                     _ip(src), _ip(dst)) + options
    eth = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + struct.pack(">H", ethertype)
    return eth + ip + udp + b"\x00" * pad


class Outcome(NamedTuple):
    outcome: int
    reason: int = 0
    target: Optional[str] = None          # the core verdict's target (a route) ...
    cause_code: int = 0                   # ... or the code of the refusal / escalation
    request: Optional[protocol.Request] = None
    verdict: Optional[dict] = None


def decide(frame: bytes, policy, loaded: bool = True) -> Outcome:
    """The Python decision of one frame (the XDP program's outcome numbers)."""
    be16 = lambda at: struct.unpack_from(">H", frame, at)[0]   # noqa: E731
    if len(frame) < 14 or be16(12) != 0x0800:
        return Outcome(OTHER)
    if len(frame) < 34 or frame[23] != 17:
        return Outcome(OTHER)
    ihl = (frame[14] & 0x0F) * 4
    if frame[14] >> 4 != 4 or ihl < 20:
        return Outcome(OTHER)
    frag = be16(20)
    if frag & 0x1FFF:
        return Outcome(OTHER)
    udp = 14 + ihl
    if len(frame) < udp + 8 or be16(udp + 2) != protocol.PORT:
        return Outcome(OTHER)
    tot_len, udp_len = be16(16), be16(udp + 4)
    reason = 0
    if frag & 0x2000:
        reason = BAD_FRAGMENT
    elif ihl > 60 or tot_len < ihl + 8:
        reason = BAD_IP_HEADER
    if not reason and (udp_len < 8 or udp_len != tot_len - ihl):
        reason = BAD_UDP_LENGTH
    payload_len = udp_len - 8
    if not reason and (payload_len > protocol.HEADER_LEN + protocol.NAME_MAX + protocol.DATA_MAX
                       or udp + 8 + payload_len > len(frame)):
        reason = BAD_UDP_LENGTH
    if reason:
        return Outcome(DROP_BAD, reason)
    try:
        request = protocol.decode(frame[udp + 8:udp + 8 + payload_len])
    except protocol.Malformed as bad:
        return Outcome(DROP_BAD, bad.code)
    if not loaded:
        return Outcome(DROP_NOPOL, request=request)
    reading = request.reading()
    decision = policy.decide(policy.reading_bytes(reading))
    verdict = decision.verdict
    outcome = ALLOW if decision.kind == "allow" else DROP_POLICY
    if verdict.get("verdict") == "route":
        return Outcome(outcome, 0, verdict["target"], decision.cause_code or 0, request, verdict)
    return Outcome(outcome, 0, None, verdict.get("code") or 0, request, verdict)
