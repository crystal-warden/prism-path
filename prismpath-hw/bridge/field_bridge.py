#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""field_bridge.py — BNO086 -> PrismPath field dict, streamed as NDJSON over TCP.

The Day-2 field bridge (runs on the Mac, under the Merkle-ledger venv whose adafruit_bno08x
carries the local resilience patch). The worker is an ADC: raw sensor -> the three fields the
gallery flow `incident_severity` routes on, plus raw extras for the record.

v2, accel-only: bring-up showed the shake-detector and stability-classifier report channels
wedge silently on this stack while the accelerometer stream stays live — so every field is
now derived from acceleration, and the sensor is re-initialized automatically after
consecutive bus errors (shaking the board also shakes the I2C wiring).

  data_at_risk  bool   a violent spike (|mag - g| > SHAKE_DEV) within the last SHAKE_HOLD_S
  user_facing   bool   sustained handling: peak deviation over the window > MOVE_DEV
  error_rate    int    0-100: peak deviation, deadbanded and scaled

Usage:  python field_bridge.py --host <router-ip> [--port 9317] [--hz 10] [--stdout]
"""
from __future__ import annotations

import argparse
import json
import math
import os
import signal
import socket
import sys
import time

os.environ["BLINKA_MCP2221"] = "1"

import board                                      # noqa: E402
import busio                                      # noqa: E402
import digitalio                                  # noqa: E402
from adafruit_bno08x.i2c import BNO08X_I2C        # noqa: E402
from adafruit_bno08x import BNO_REPORT_ACCELEROMETER   # noqa: E402

G = 9.81
DEADBAND = 0.15          # m/s^2 of |mag - g| ignored (sensor noise on a resting board)
SCALE = 20.0             # error_rate units per m/s^2 of deviation beyond the deadband
HOLD_S = 1.5             # peak-hold window: keeps a nudge visible for a few samples
MOVE_DEV = 0.5           # sustained-handling threshold -> user_facing
SHAKE_DEV = 2.5          # violent-spike threshold -> a "shake"
SHAKE_HOLD_S = 3.0       # data_at_risk stays raised this long after a shake
REINIT_AFTER = 10        # consecutive read errors before a full sensor re-init
REPORT_US = 50_000       # sensor-side accel report interval: 20 Hz — the PROVEN rate. 100 Hz
                         # saturates the MCP2221A HID pipe (v3 wedged; v4 froze stale); the
                         # fast poll loop below still catches every report the sensor makes
STALE_S = 2.5            # identical readings this long = frozen cache (impossible live at mg
                         # resolution) -> full hardware reset


class ReadTimeout(Exception):
    """A sensor read (or init) exceeded its deadline. Bring-up showed the patched library can
    WEDGE inside a read — swallowing malformed packets forever without raising — so every
    library call runs under a SIGALRM watchdog that converts a hang into this exception,
    which then feeds the normal error-count -> hardware-reset recovery path."""


def _alarm(signum, frame):
    raise ReadTimeout("sensor call exceeded deadline")


def init_sensor():
    rst = digitalio.DigitalInOut(board.G0)
    rst.direction = digitalio.Direction.OUTPUT
    rst.value = False
    time.sleep(0.2)
    rst.value = True
    time.sleep(1.5)
    i2c = busio.I2C(board.SCL, board.SDA, frequency=400000)
    bno = BNO08X_I2C(i2c, address=0x4B)
    bno.enable_feature(BNO_REPORT_ACCELEROMETER, report_interval=REPORT_US)
    time.sleep(0.5)
    return bno, rst


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default=None, help="router address (omit with --stdout)")
    ap.add_argument("--port", type=int, default=9317)
    ap.add_argument("--hz", type=float, default=10.0)
    ap.add_argument("--stdout", action="store_true", help="print NDJSON instead of TCP")
    args = ap.parse_args()

    out = sys.stdout
    if not args.stdout:
        if not args.host:
            ap.error("--host required unless --stdout")
        sock = socket.create_connection((args.host, args.port), timeout=10)
        out = sock.makefile("w")
        print(f"connected to {args.host}:{args.port}", file=sys.stderr)

    signal.signal(signal.SIGALRM, _alarm)
    signal.setitimer(signal.ITIMER_REAL, 25)
    bno, rst = init_sensor()
    signal.setitimer(signal.ITIMER_REAL, 0)
    print("sensor up — streaming (bridge v4: accel-only + read watchdog)", file=sys.stderr)

    shake_count = 0
    last_shake = 0.0
    peak_dev = 0.0
    peak_at = 0.0
    errors = 0
    period = 1.0 / args.hz

    next_emit = time.monotonic()
    ax = ay = az = 0.0
    last_raw = None
    last_change = time.monotonic()
    while True:
        # inner loop: poll as fast as the HID transport allows, peak-hold every reading —
        # the emit rate is a display choice; the *detection* rate is the poll rate
        t = time.monotonic()
        try:
            signal.setitimer(signal.ITIMER_REAL, 1.5)
            ax, ay, az = bno.acceleration
            signal.setitimer(signal.ITIMER_REAL, 0)
            errors = 0
        except Exception as e:
            signal.setitimer(signal.ITIMER_REAL, 0)
            errors += 1
            if errors == 1 or errors % 20 == 0:
                print(f"read error x{errors} (continuing): {e}", file=sys.stderr)
            if errors >= REINIT_AFTER:
                print("re-initializing sensor…", file=sys.stderr)
                try:
                    rst.deinit()
                except Exception:
                    pass
                try:
                    signal.setitimer(signal.ITIMER_REAL, 25)
                    bno, rst = init_sensor()
                    signal.setitimer(signal.ITIMER_REAL, 0)
                    errors = 0
                    print("sensor re-initialized", file=sys.stderr)
                except Exception as e2:
                    signal.setitimer(signal.ITIMER_REAL, 0)
                    print(f"re-init failed, retrying: {e2}", file=sys.stderr)
                    time.sleep(1.0)
            else:
                time.sleep(0.02)
            continue

        if (ax, ay, az) != last_raw:
            last_raw = (ax, ay, az)
            last_change = t
        elif t - last_change > STALE_S:
            print("sensor frozen (identical readings > stale window) — hardware reset",
                  file=sys.stderr)
            last_change = t
            try:
                rst.deinit()
            except Exception:
                pass
            try:
                signal.setitimer(signal.ITIMER_REAL, 25)
                bno, rst = init_sensor()
                signal.setitimer(signal.ITIMER_REAL, 0)
                print("sensor re-initialized (stale recovery)", file=sys.stderr)
            except Exception as e2:
                signal.setitimer(signal.ITIMER_REAL, 0)
                print(f"stale re-init failed, retrying: {e2}", file=sys.stderr)
                time.sleep(1.0)
            continue

        dev = abs(math.sqrt(ax * ax + ay * ay + az * az) - G)
        if dev > SHAKE_DEV and (t - last_shake) > 0.5:      # rising-edge shake counter
            shake_count += 1
            last_shake = t
        if dev > peak_dev or (t - peak_at) > HOLD_S:
            peak_dev, peak_at = dev, t

        if t < next_emit:
            time.sleep(0.005)
            continue
        next_emit = t + period

        eff = max(0.0, peak_dev - DEADBAND)
        shaken = (t - last_shake) < SHAKE_HOLD_S and shake_count > 0
        moving = peak_dev > MOVE_DEV
        fields = {
            "data_at_risk": shaken,
            "user_facing": moving,
            "error_rate": min(100, int(eff * SCALE)),
            # raw extras — not routed on, kept for the record/debug
            "accel_mg": [int(ax * 1000), int(ay * 1000), int(az * 1000)],
            "dev_mg": int(peak_dev * 1000),
            "stability": "shaken" if shaken else ("moving" if moving else "still"),
            "shake_count": shake_count,
            "ts": round(time.time(), 3),
        }
        out.write(json.dumps(fields) + "\n")
        out.flush()


if __name__ == "__main__":
    sys.exit(main())
