#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""field_walk.py - field-test logger for the mesh-fusion ESP-NOW mesh.

Reads one (or two) tethered mesh-fusion node(s) over serial, timestamps every emitted line, parses the
fused-verdict / swap / partition telemetry, and appends it all to ONE replayable JSONL trail. It also
owns the primary node's serial so it can inject the on-device controls (policy swap, interference) and
drop human position marks onto the same timeline - so connectivity, swap, interference, and partition all
land on one clock, the way the decision-delta demo kept a single signed t_ns trail.

Control (from another shell, so the logger can run unattended while you walk):
    echo swap        > CTL      # 'R' -> coordinate a fleet-wide fusion-rule swap from the primary node
    echo intf 4      > CTL      # set simulated interference on the primary node to 40% verdict drop
    echo blackout    > CTL      # 'X' -> ~99% drop on the primary node
    echo clearintf   > CTL      # back to 0% drop
    echo mark 'waypoint 2, ~20 m' > CTL   # stamp a free-text position/event mark onto the trail
    echo quit        > CTL

    python3 field_walk.py --port /dev/ttyUSB0 [--port2 /dev/ttyUSB1] \
        --out trail-YYYYMMDD.jsonl --ctl /tmp/mesh_ctl

The primary node (--port) is the office node whose fused verdict is the spine of the measurement.
--port2 is optional (e.g. a window/door observer) and is read-only: its lines are logged but no controls
are sent to it. slot map in the emitted "a=/b=/arm=" line: a=slot0(office tof), b=slot1(door tof),
arm=slot2(walker). arm==8 (STALE sentinel) means the walker has partitioned - the logger flags it.
"""
import argparse, json, os, re, sys, threading, time

STALE = 8  # matches STALE_BAND in ppt_fusion_mesh.c: an unheard slot reads this sentinel band

# ---- parsers for the firmware's emit() lines (ppt_fusion_mesh.c) ----
RE_VERDICT = re.compile(r"\[(?P<node>[^\]]+)\]\s+pol=(?P<pol>\S+)\s+a=(?P<a>-?\d+)\s+b=(?P<b>-?\d+)\s+arm=(?P<arm>-?\d+)\s+->\s+(?P<posture>\S+)")
RE_PREPARE = re.compile(r"coord PREPARE seq=(?P<seq>\d+) target=fusion-(?P<target>\S+)")
RE_ACKTALLY = re.compile(r"coord ACK from (?P<from>\S+) \((?P<got>\d+)/(?P<need>\d+)\)")
RE_COMMIT = re.compile(r"COMMIT seq=(?P<seq>\d+) flip in (?P<delay>\d+)ms")
RE_ABORT = re.compile(r"coord ABORT seq=(?P<seq>\d+) only (?P<got>\d+)/(?P<need>\d+)")
RE_FLIP = re.compile(r">>> FLIP (?P<node>\S+) -> fusion policy (?P<pol>\S+) epoch=(?P<epoch>\d+)")
RE_INTF = re.compile(r"interference: dropping (?P<pct>\d+)%")


def classify(line):
    """Map a raw firmware line to a structured event dict (kind + fields), best-effort."""
    m = RE_VERDICT.search(line)
    if m:
        d = m.groupdict()
        a, b, arm = int(d["a"]), int(d["b"]), int(d["arm"])
        stale = [s for s, v in (("office", a), ("door", b), ("walker", arm)) if v == STALE]
        return {"kind": "verdict", "node": d["node"], "pol": d["pol"],
                "a": a, "b": b, "arm": arm, "posture": d["posture"],
                "stale": stale, "partitioned": bool(stale)}
    for rgx, kind in ((RE_PREPARE, "swap_prepare"), (RE_ACKTALLY, "swap_ack"),
                      (RE_ABORT, "swap_abort"), (RE_FLIP, "swap_flip"),
                      (RE_COMMIT, "swap_commit"), (RE_INTF, "interference")):
        m = rgx.search(line)
        if m:
            return {"kind": kind, **m.groupdict()}
    if "up — slot=" in line or "mesh ready" in line:
        return {"kind": "boot"}
    return {"kind": "raw"}


def reader(port_name, label, ser, out_lock, out_fh, live):
    buf = b""
    while True:
        try:
            chunk = ser.read(256)
        except Exception as e:
            _emit(out_lock, out_fh, {"kind": "error", "src": label, "err": str(e)})
            return
        if not chunk:
            continue
        buf += chunk
        while b"\n" in buf:
            raw, buf = buf.split(b"\n", 1)
            line = raw.decode("utf-8", "replace").strip("\r\n ")
            if not line:
                continue
            ev = classify(line)
            rec = {"t_ns": time.monotonic_ns(), "t_wall": time.time(),
                   "src": label, "raw": line, **ev}
            _emit(out_lock, out_fh, rec)
            if live and ev["kind"] in ("verdict", "swap_prepare", "swap_ack", "swap_abort",
                                       "swap_flip", "swap_commit", "interference"):
                flag = "  <<< PARTITION (walker STALE)" if ev.get("partitioned") else ""
                if ev["kind"] == "verdict":
                    print(f"  [{label}] {ev['pol']} a={ev['a']} b={ev['b']} arm={ev['arm']} -> {ev['posture']}{flag}", flush=True)
                else:
                    print(f"  [{label}] {ev['kind']}: {ev.get('raw','')}", flush=True)


def _emit(lock, fh, rec):
    with lock:
        fh.write(json.dumps(rec) + "\n")
        fh.flush()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", required=True, help="primary (office) node serial; controls go here")
    ap.add_argument("--port2", default=None, help="optional read-only second observer (window/door)")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--out", default=None, help="JSONL trail path (default trail-<epoch>.jsonl)")
    ap.add_argument("--ctl", default="/tmp/mesh_ctl", help="control file polled for commands")
    args = ap.parse_args()

    try:
        import serial  # pyserial
    except ImportError:
        sys.exit("pyserial not installed: pip install pyserial")

    out_path = args.out or f"trail-{int(time.time())}.jsonl"
    out_fh = open(out_path, "a")
    out_lock = threading.Lock()
    # fresh control file so a stale command does not fire on startup
    try:
        open(args.ctl, "w").close()
    except Exception:
        pass

    def open_noreset(port):
        # attach to an already-running node without pulsing DTR/RTS (which would reset it into a blip)
        s = serial.Serial()
        s.port = port; s.baudrate = args.baud; s.timeout = 0.2
        s.dtr = False; s.rts = False
        s.open()
        return s

    primary = open_noreset(args.port)
    ports = [(args.port, "office", primary)]
    if args.port2:
        ports.append((args.port2, "observer", open_noreset(args.port2)))

    print(f"field_walk: logging {[p[0] for p in ports]} -> {out_path}", flush=True)
    print(f"control: echo swap|intf N|blackout|clearintf|mark <text>|quit > {args.ctl}", flush=True)
    _emit(out_lock, out_fh, {"t_ns": time.monotonic_ns(), "t_wall": time.time(),
                             "kind": "session_start", "ports": [p[0] for p in ports]})

    for pn, label, ser in ports:
        threading.Thread(target=reader, args=(pn, label, ser, out_lock, out_fh, True), daemon=True).start()

    def send(byte, note):
        primary.write(byte)
        _emit(out_lock, out_fh, {"t_ns": time.monotonic_ns(), "t_wall": time.time(),
                                 "kind": "control", "cmd": note})
        print(f"  >>> control: {note}", flush=True)

    # poll the control file for commands; keeps the logger unattended while you walk
    while True:
        try:
            with open(args.ctl) as f:
                cmd = f.read().strip()
            if cmd:
                open(args.ctl, "w").close()  # consume
                low = cmd.lower()
                if low == "swap":
                    send(b"R", "swap (R): coordinate fusion-rule flip")
                elif low.startswith("intf"):
                    n = "".join(ch for ch in low if ch.isdigit()) or "0"
                    send(str(int(n) % 10).encode(), f"interference {int(n)*10}% drop")
                elif low == "blackout":
                    send(b"X", "blackout (~99% drop)")
                elif low == "clearintf":
                    send(b"0", "interference cleared (0%)")
                elif low.startswith("mark"):
                    text = cmd[4:].strip()
                    _emit(out_lock, out_fh, {"t_ns": time.monotonic_ns(), "t_wall": time.time(),
                                             "kind": "mark", "text": text})
                    print(f"  *** MARK: {text}", flush=True)
                elif low in ("quit", "exit", "q"):
                    _emit(out_lock, out_fh, {"t_ns": time.monotonic_ns(), "t_wall": time.time(),
                                             "kind": "session_end"})
                    print("field_walk: done.", flush=True)
                    return
                else:
                    print(f"  ?? unknown command: {cmd}", flush=True)
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"  ctl error: {e}", flush=True)
        time.sleep(0.1)


if __name__ == "__main__":
    main()
