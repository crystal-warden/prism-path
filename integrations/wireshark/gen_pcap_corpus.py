#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Generate the committed Facet pcap corpus + expected decode results, deterministically.

Every byte of the output is reproducible: fixed MACs/IPs/ports, fixed timestamps, and payloads
produced by the reference codec (adapters/telemetry). The expected results are computed by a
strict decode mirror of the kernel decode plane contract (facet_decode.bpf.c): structurally
malformed frames (no terminator, dangling partial codeword, u16 overflow) are marked malformed;
well formed frames carry their wire integers and trailing zero pad width.

Outputs (committed):
  facet_corpus.pcap            frames on UDP/4711, positive + negative + decoded form + ambiguous
  facet_corpus.expected.json   per frame expectations for check_dissector.py
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "adapters" / "telemetry"))
import packed  # noqa: E402
import receipts  # noqa: E402
import zeckendorf as z  # noqa: E402

FACET_PORT = 4711
TS_BASE = 1_787_200_000  # fixed epoch seconds; deterministic output is the point


# ------------------------------------------------------------------ strict decode (reference)
def strict_decode(payload: bytes) -> dict:
    """Mirror of the kernel decode plane contract, used to compute expectations."""
    if not payload:
        # Wireshark's UDP dissector never invokes a subdissector for a zero length payload,
        # so no facet output is expected; the kernel decode plane is what drops empties.
        return {"form": "none", "malformed": 1, "reason": "empty"}
    bits = packed.unpack(payload)
    ints, spans = [], []
    start = i = 0
    last_end = -1
    n = len(bits)
    while i < n - 1:
        if bits[i] == "1" and bits[i + 1] == "1":
            if (i - start + 1) > 70:
                return {"form": "raw", "malformed": 1, "reason": "overflow"}
            ints.append(z.decode(bits[start:i + 2]))
            spans.append((start, i + 1))
            last_end = i + 1
            i += 2
            start = i
        else:
            i += 1
    tail = bits[last_end + 1:]
    if not ints:
        return {"form": "raw", "malformed": 1, "reason": "noterm"}
    if "1" in tail:
        return {"form": "raw", "malformed": 1, "reason": "dangling"}
    if any(v > 65535 for v in ints):
        return {"form": "raw", "malformed": 1, "reason": "overflow"}
    return {"form": "raw", "malformed": 0, "count": len(ints),
            "wireints": ",".join(str(v) for v in ints), "padbits": len(tail)}


def looks_decoded(payload: bytes) -> bool:
    return (len(payload) >= 4 and payload[0] == 0x46 and payload[1] > 0
            and len(payload) == 2 + 2 * payload[1])


def expect(payload: bytes) -> dict:
    """Expectation for one payload under the dissector's documented heuristic order."""
    if looks_decoded(payload):
        cells = [struct.unpack_from("<H", payload, 2 + 2 * k)[0] for k in range(payload[1])]
        return {"form": "decoded", "malformed": 0, "count": payload[1],
                "wireints": ",".join(str(c) for c in cells)}
    return strict_decode(payload)


# ------------------------------------------------------------------------------ frame builder
def ip_checksum(hdr: bytes) -> int:
    s = 0
    for k in range(0, len(hdr), 2):
        s += (hdr[k] << 8) | hdr[k + 1]
    while s > 0xFFFF:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def frame(payload: bytes) -> bytes:
    eth = b"\x02" * 6 + b"\x02" * 6 + struct.pack(">H", 0x0800)
    udp = struct.pack(">HHHH", 5000, FACET_PORT, 8 + len(payload), 0) + payload
    tot = 20 + len(udp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, tot, 1, 0, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    ip = ip[:10] + struct.pack(">H", ip_checksum(ip)) + ip[12:]
    return eth + ip + udp


def raw_payload(wire_ints: list) -> bytes:
    return packed.pack(z.encode_stream(wire_ints), 8)


def decoded_payload(cells: list) -> bytes:
    return b"F" + bytes([len(cells)]) + b"".join(struct.pack("<H", c) for c in cells)


# ------------------------------------------------------------------------------------ corpus
def build_corpus() -> list:
    """[(name, payload)] in fixed order. Do not reorder: frame numbers are part of the corpus."""
    out = []
    # positive raw
    for ints in ([1], [2], [1, 2, 3], [2, 1, 5], [4, 3, 2, 1],
                 list(range(1, 17)), [610], [46368], [65535], [7, 12, 1]):
        out.append(("raw_" + "_".join(str(v) for v in ints), raw_payload(ints)))
    # negative raw
    out.append(("neg_empty", b""))
    out.append(("neg_allzero", b"\x00\x00"))
    out.append(("neg_dangling", raw_payload([1, 2, 3]) + b"\x80"))
    out.append(("neg_truncated", raw_payload([610])[:-1]))
    out.append(("neg_overflow", raw_payload([70000])))
    # decoded form (the kernel decode plane's local rewrite)
    out.append(("dec_2_1_5", decoded_payload([2, 1, 5])))
    out.append(("dec_1", decoded_payload([1])))
    # deliberate heuristic collision: raw parseable AND satisfies the decoded length check
    out.append(("ambiguous_specimen", bytes([0x46, 0x01, 0x03, 0x00])))
    # receipt stream specimens
    out.append(("rcpt_clean", receipts.encode_receipt(seq=1, prev_node=10, event=5, next_node=11, cause_val=0)))
    out.append(("rcpt_stuck", receipts.encode_receipt(seq=2, prev_node=10, event=5, next_node=11, cause_val=36)))
    return out


def main() -> int:
    corpus = build_corpus()
    pcap = HERE / "facet_corpus.pcap"
    expected = HERE / "facet_corpus.expected.json"

    with open(pcap, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for idx, (_name, payload) in enumerate(corpus):
            buf = frame(payload)
            fh.write(struct.pack("<IIII", TS_BASE + idx, 0, len(buf), len(buf)))
            fh.write(buf)

    table = []
    for idx, (name, payload) in enumerate(corpus):
        e = expect(payload)
        e["frame"] = idx + 1
        e["name"] = name
        table.append(e)
    expected.write_text(json.dumps(table, indent=2) + "\n")

    sha = hashlib.sha256(pcap.read_bytes()).hexdigest()
    print(f"{len(corpus)} frames -> {pcap.name}  sha256 {sha}")
    for e in table:
        detail = e.get("wireints", e.get("reason", ""))
        print(f"  #{e['frame']:>2} {e['name']:<22} {e['form']:<8} "
              f"{'MALFORMED' if e['malformed'] else 'ok':<9} {detail}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
