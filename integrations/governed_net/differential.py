# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The differential: the XDP program's decision (its own text on the userspace path) against the Python
decision (frame checks, `protocol.decode`, the Python kernel) on every frame of a corpus.

The corpus has three parts:

  * structured: every command x a spread of handle classes, arguments, name and data lengths that sit on
    and beside every bound the policy and the protocol name (well formed and not);
  * frame level: other ethertypes, other protocols, other ports, fragments, IP options, bad lengths,
    Ethernet padding, truncations;
  * random: requests with random fields (most of them well formed, so the policy is exercised, not only the
    reader), and mutations of valid frames (byte flips, truncation, extension, splices).

Per frame the two must agree on the outcome (other / allow / dropped by policy / malformed), on the reason
of a malformed frame, and on the core verdict of a decided one: the rule's target and its cause code. For
every decided frame the receipt the logger would write from the XDP event (its reading rebuilt from the
event's fields, its verdict from the matched rule) must be byte for byte the receipt of the Python
decision. Two more runs: with the tables empty every request must be dropped, and with the ring buffer
full no request may pass.

    python -m integrations.governed_net.differential --random 120000 --seed 1 --out DIR
"""
from __future__ import annotations

import argparse
import json
import random
import struct
import sys
import time
from pathlib import Path
from typing import Dict, List

from . import frame as fr
from . import protocol as p
from . import xdp_userspace
from .policy import NetPolicy, write_build

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "formal" / "diff"))
import core_evidence  # noqa: E402
from prismpath.kernel import canon2  # noqa: E402

BOUNDS = [0, 1, 2, 3, 4, 5, 49, 50, 51, 4095, 4096, 4097, 2 ** 31 - 1, 2 ** 31, 2 ** 32 - 1]


def req_bytes(cmd, hclass=0, handle=0, arg0=0, arg1=0, name=b"", data=b"", request_id=7, **kw) -> bytes:
    return p.encode(p.Request(cmd=cmd, request_id=request_id, hclass=hclass, handle=handle, arg0=arg0, arg1=arg1,
                              name=name, data=data, **kw))


def structured() -> List[bytes]:
    frames = []
    names = [b"", b"a", b"notes.txt", b"N" * 64, b"x" * 65, b".hidden", b"..", b"a/b", b"-x", b"_ok-1.2", b"a b", b"\xff"]
    datas = [b"", b"x", b"y" * 1024, b"z" * 1025]
    for cmd in range(0, 14):
        for hclass in (0, 1, 2, 3, 4, 5, 255):
            for arg0 in (0, 1, 3, 4, 50, 51, 2 ** 31 - 1, 2 ** 31):
                for arg1 in (0, 1, 4096, 4097):
                    for name in (b"", b"a", b"N" * 64):
                        for data in (b"", b"x", b"y" * 1024):
                            frames.append(fr.build(req_bytes(cmd, hclass, 1 if hclass else 0, arg0, arg1, name, data)))
    for name in names:
        for data in datas:
            frames.append(fr.build(req_bytes(p.CREATE, p.H_WS_DIR, 1, name=name, data=data)))
    good = req_bytes(p.READ, p.H_WS_FILE, 9, 0, 100)
    frames += [fr.build(req_bytes(p.READ, p.H_WS_FILE, 9, 0, 100, magic=0x47454E54)),
               fr.build(req_bytes(p.READ, p.H_WS_FILE, 9, 0, 100, version=2)),
               fr.build(req_bytes(p.READ, p.H_WS_FILE, 9, 0, 100, flags=1)),
               fr.build(req_bytes(p.READ, p.H_WS_FILE, 9, 0, 100, reserved=1)),
               fr.build(req_bytes(p.READ, p.H_WS_FILE, 9, 0, 100, request_id=0)),
               fr.build(good + b"\x00"), fr.build(good[:-1]), fr.build(good[:31]), fr.build(b""),
               fr.build(good, dport=p.PORT + 1), fr.build(good, dport=22), fr.build(good, proto=6),
               fr.build(good, ethertype=0x86DD), fr.build(good, ethertype=0x8100), fr.build(good, frag=0x2000),
               fr.build(good, frag=0x0001), fr.build(good, frag=0x4000), fr.build(good, ihl=6), fr.build(good, ihl=15),
               fr.build(good, udp_len=7), fr.build(good, udp_len=8 + len(good) + 1), fr.build(good, udp_len=8 + len(good) - 1),
               fr.build(good, ip_len=10), fr.build(good, ip_len=20 + 8 + len(good) + 4), fr.build(good, pad=18),
               fr.build(good)[:14], fr.build(good)[:33], fr.build(good)[:41], fr.build(good)[:-1]]
    # the whole frame cut at every length
    whole = fr.build(req_bytes(p.CREATE, p.H_WS_DIR, 1, name=b"new.txt", data=b"hello"))
    frames += [whole[:cut] for cut in range(len(whole))]
    return frames


def random_request(rng: random.Random) -> bytes:
    cmd = rng.choice([rng.randint(1, 11)] * 9 + [rng.randint(0, 255)])
    well = rng.random() < 0.85                              # mostly well formed, so the policy decides
    uses = lambda group: cmd in group or not well           # noqa: E731
    hclass = rng.choice([0, 1, 2, 3, 4, rng.randint(5, 255)]) if uses(p.USES_HANDLE) else 0
    handle = rng.randint(1, 2 ** 32 - 1) if hclass or (not well and rng.random() < 0.3) else 0
    arg = lambda: rng.choice(BOUNDS[:13] if well else BOUNDS) if rng.random() < 0.6 else rng.randint(0, 2 ** 31 - 1)  # noqa: E731
    arg0 = arg() if uses(p.USES_ARG0) else 0
    arg1 = arg() if uses(p.USES_ARG1) else 0
    alphabet = bytes(p.NAME_REST) if well else bytes(range(256))
    name = b""
    if uses(p.USES_NAME):
        length = rng.choice([0, 1, 2, 8, 64, 65] if not well else [0, 1, 2, 8, 63, 64])
        name = bytes(rng.choice(alphabet) for _ in range(length))
        if well and name and rng.random() < 0.8:
            name = bytes([rng.choice(bytes(p.NAME_FIRST))]) + name[1:]
    data = bytes(rng.getrandbits(8) for _ in range(rng.choice([0, 1, 5, 100, 1024, 1025] if not well else [0, 1, 5, 100, 1024]))) \
        if uses(p.USES_DATA) else b""
    return req_bytes(cmd, hclass, handle, arg0, arg1, name, data, request_id=rng.randint(0 if not well else 1, 2 ** 64 - 1),
                     version=1 if well or rng.random() < 0.7 else rng.randint(0, 255),
                     reserved=0 if well or rng.random() < 0.8 else rng.randint(0, 255))


def mutate(rng: random.Random, frame: bytes) -> bytes:
    data = bytearray(frame)
    kind = rng.randrange(5)
    if kind == 0 and data:                                   # flip some bytes anywhere
        for _ in range(rng.randint(1, 4)):
            data[rng.randrange(len(data))] = rng.getrandbits(8)
    elif kind == 1 and len(data) > 42:                       # flip bytes of the request header only
        for _ in range(rng.randint(1, 3)):
            data[rng.randint(42, min(len(data), 74) - 1)] = rng.getrandbits(8)
    elif kind == 2:                                          # truncate
        del data[rng.randint(0, len(data)):]
    elif kind == 3:                                          # extend
        data += bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 16)))
    else:                                                    # rewrap the payload with consistent lengths
        payload = bytes(data[42:])
        if payload:
            payload = bytearray(payload)
            payload[rng.randrange(len(payload))] = rng.getrandbits(8)
        return fr.build(bytes(payload))
    return bytes(data)


def corpus(count: int, seed: int) -> Dict[str, List[bytes]]:
    rng = random.Random(seed)
    rand = [fr.build(random_request(rng)) for _ in range(count // 2)]
    muts = [mutate(rng, rng.choice(rand)) for _ in range(count - count // 2)]
    return {"structured": structured(), "random": rand, "mutated": muts}


def receipt(policy: NetPolicy, reading: dict, verdict: dict) -> bytes:
    raw = policy.reading_bytes(reading)
    return canon2.dumps({"format": core_evidence.RECEIPT_FORMAT, "idx": 0, "case": "c", "reading": 0,
                         "image_sha256": policy.sha256, "reading_sha256": core_evidence.sha256_hex(raw),
                         "decider": "d", **core_evidence._decision(verdict)})


def compare(policy: NetPolicy, frames: List[bytes], rows) -> Dict:
    counts = {"frames": len(frames), "agree": 0, "disagree": 0, "receipts_compared": 0, "receipts_differ": 0,
              "outcomes": {}, "first": []}
    for frame_bytes, row in zip(frames, rows):
        py = fr.decide(frame_bytes, policy)
        name = fr.OUTCOMES[py.outcome]
        counts["outcomes"][name] = counts["outcomes"].get(name, 0) + 1
        ok = py.outcome == row.outcome and py.reason == row.reason and row.emitted == (py.outcome != fr.OTHER)
        if ok and py.outcome in (fr.ALLOW, fr.DROP_POLICY):
            xdp_verdict = policy.verdict_of_edge(row.edge)
            ok = (py.verdict.get("verdict") == xdp_verdict["verdict"] and py.target == xdp_verdict.get("target")
                  and py.cause_code == row.cause and row.request_id == py.request.request_id
                  and row.reading() == py.request.reading())
            if ok:
                counts["receipts_compared"] += 1
                if receipt(policy, row.reading(), xdp_verdict) != receipt(policy, py.request.reading(), py.verdict):
                    counts["receipts_differ"] += 1
                    ok = False
        if ok:
            counts["agree"] += 1
        else:
            counts["disagree"] += 1
            if len(counts["first"]) < 5:
                counts["first"].append({"frame": frame_bytes.hex(), "python": [py.outcome, py.reason, py.target, py.cause_code],
                                        "xdp": list(row)})
    return counts


def fail_closed(binary, build, policy, frames) -> Dict:
    """Empty tables: nothing passes but what is not the protocol. A full ring: no request passes."""
    empty = xdp_userspace.batch(binary, build["ppt"], build["actions"], frames, empty=True)
    full = xdp_userspace.batch(binary, build["ppt"], build["actions"], frames, ring_full=True)
    passed_empty = sum(row.outcome == fr.ALLOW for row in empty)
    passed_full = sum(row.outcome == fr.ALLOW for row in full)
    other_ok = all((row.outcome == fr.OTHER) == (fr.decide(frame_bytes, policy).outcome == fr.OTHER)
                   for frame_bytes, row in zip(frames, empty))
    return {"frames": len(frames), "allowed_with_empty_tables": passed_empty, "allowed_with_full_ring": passed_full,
            "no_log_drops_with_full_ring": sum(row.outcome == fr.DROP_NOLOG for row in full),
            "other_traffic_unchanged": other_ok}


def run(count: int, seed: int, out: Path) -> Dict:
    out.mkdir(parents=True, exist_ok=True)
    policy = NetPolicy.load()
    build = write_build(out / "policy", policy)
    binary = xdp_userspace.build(out / "bin")
    parts = corpus(count, seed)
    summary = {"seed": seed, "image_sha256": policy.sha256, "parts": {}}
    started = time.monotonic()
    for name, frames in parts.items():
        rows = xdp_userspace.batch(binary, build["ppt"], build["actions"], frames)
        summary["parts"][name] = compare(policy, frames, rows)
    summary["fail_closed"] = fail_closed(binary, build, policy, parts["structured"])
    summary["total_frames"] = sum(part["frames"] for part in summary["parts"].values())
    summary["total_disagree"] = sum(part["disagree"] for part in summary["parts"].values())
    summary["seconds"] = round(time.monotonic() - started, 1)
    (out / "differential.json").write_text(json.dumps(summary, indent=1))
    return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--random", type=int, default=120000)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    summary = run(args.random, args.seed, Path(args.out))
    print(json.dumps(summary, indent=1))
    closed = summary["fail_closed"]
    return 0 if (summary["total_disagree"] == 0 and closed["allowed_with_empty_tables"] == 0
                 and closed["allowed_with_full_ring"] == 0 and closed["other_traffic_unchanged"]) else 1


if __name__ == "__main__":
    sys.exit(main())
