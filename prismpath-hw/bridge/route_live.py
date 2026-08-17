#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""route_live.py — live sensor fields routed by the certified C table interpreter.

Demo #1, strengthened: the router is not the Python engine — it is `build/interp eval` over
the byte-identical `incident_severity` PPT image that will later sit in BRAM. Each NDJSON
sample from the Mac bridge becomes one field-register write + one evaluate(assess); the
matched edge is the severity decision. Every sample and decision is appended to
build/live_route_log.ndjson — the evidence file.

Usage:  python3 bridge/route_live.py [--port 9317] [--flow <flow.md>]
"""
from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))

import ppt_compile as pc                               # noqa: E402
from prismpath.parser import parse_file                # noqa: E402

DEFAULT_FLOW = (Path(pc._REPO) / "prismpath" / "gallery" / "incident_severity"
                / "incident_severity.md")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=9317)
    ap.add_argument("--flow", default=str(DEFAULT_FLOW))
    args = ap.parse_args()

    graph = parse_file(args.flow)
    img = pc.compile_flow(graph)
    blob = img.serialize()
    build = HERE / "build"
    image_path = build / "live.ppt"
    image_path.write_bytes(blob)
    names = [n for n, _ in img.nodes]
    start = img.start
    interp = build / "interp"
    log_path = build / "live_route_log.ndjson"
    print(f"flow={graph.name} image={len(blob)}B sha-relevant fields={list(img.fields)}")
    print(f"listening on :{args.port} — decisions log to {log_path}")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", args.port))
    srv.listen(1)
    log = open(log_path, "a")
    regs_path = build / "live_regs.bin"
    while True:                                  # a bridge restart is a reconnect, not an exit
        conn, addr = srv.accept()
        print(f"bridge connected from {addr[0]}")
        serve(conn, img, names, start, image_path, regs_path, interp, log)


def serve(conn, img, names, start, image_path, regs_path, interp, log) -> None:
    f = conn.makefile("r")
    last = None
    n_samples = 0
    for line in f:
        line = line.strip()
        if not line:
            continue
        sample = json.loads(line)
        regs_path.write_bytes(pc.encode_regs(img, sample, node_idx=start))
        out = subprocess.run([str(interp), "eval", str(image_path), str(regs_path)],
                             capture_output=True, text=True).stdout.strip()
        if out.startswith("match"):
            _, edge, target = out.split()
            decision = names[int(target)]
        else:
            decision = "<stuck>"
        n_samples += 1
        record = {"decision": decision, **sample}
        log.write(json.dumps(record) + "\n")
        log.flush()
        if decision != last:
            print(f"[{time.strftime('%H:%M:%S')}] #{n_samples:5d}  -> {decision:12s} "
                  f"(risk={sample['data_at_risk']} facing={sample['user_facing']} "
                  f"rate={sample['error_rate']} stab={sample.get('stability')!r} "
                  f"shakes={sample.get('shake_count')})")
            last = decision
    print(f"bridge disconnected after {n_samples} samples")


if __name__ == "__main__":
    sys.exit(main())
