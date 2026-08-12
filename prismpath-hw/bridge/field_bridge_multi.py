#!/usr/bin/env python3
"""Multi-modal field bridge (v5): the proven accel-derived decision fields PLUS the BNO086's
on-chip fusion outputs — orientation (quaternion -> roll/pitch/yaw/tilt) and the chip's own
stability classifier — streamed as NDJSON.

The decision fields (`stability`, `dev_mg`, `data_at_risk`, `user_facing`, `error_rate`) are
computed by the SAME derivation as field_bridge.py v4, so a reading from this bridge routes
through fusion_triage byte-identically to the committed pipeline. The extra fields are captured
context (a richer website visual, a fatter standard-stream baseline, and an honest cross-check of
our derived posture against the chip's own verdict) — they do not change the decision.

Runs the accel + rotation-vector + stability-classifier trio at 10 Hz sensor-side (the sustainable
rate on the MCP2221A HID pipe; the full six-channel suite saturates it — that is the case for
wiring the sensor directly to the FPGA).

    sudo BLINKA_MCP2221=1 .venv/bin/python bridge/field_bridge_multi.py --stdout [--hz 10]
"""
from __future__ import annotations

import argparse
import json
import math
import signal
import socket
import sys
import time

import board
import busio
import digitalio
from adafruit_bno08x import (
    BNO_REPORT_ACCELEROMETER,
    BNO_REPORT_ROTATION_VECTOR,
    BNO_REPORT_STABILITY_CLASSIFIER,
)
from adafruit_bno08x.i2c import BNO08X_I2C

# --- derivation constants: identical to field_bridge.py v4 (do not drift) ---
G = 9.81
DEADBAND = 0.15
SCALE = 20.0
HOLD_S = 1.5
MOVE_DEV = 0.5
SHAKE_DEV = 2.5
SHAKE_HOLD_S = 3.0
REINIT_AFTER = 10
STALE_S = 2.5
REPORT_US = 100_000   # 10 Hz sensor-side: the sustainable trio rate on the MCP2221A


class ReadTimeout(Exception):
    pass


def _alarm(signum, frame):
    raise ReadTimeout()


def init_sensor():
    rst = digitalio.DigitalInOut(board.G0)
    rst.direction = digitalio.Direction.OUTPUT
    rst.value = False
    time.sleep(0.2)
    rst.value = True
    time.sleep(1.5)
    i2c = busio.I2C(board.SCL, board.SDA, frequency=400000)
    bno = BNO08X_I2C(i2c, address=0x4B)
    for feat in (BNO_REPORT_ACCELEROMETER, BNO_REPORT_ROTATION_VECTOR,
                 BNO_REPORT_STABILITY_CLASSIFIER):
        bno.enable_feature(feat, report_interval=REPORT_US)
        time.sleep(0.2)
    time.sleep(0.5)
    return bno, rst


def quat_to_orientation(x, y, z, w):
    """(i,j,k,real) -> {roll, pitch, yaw, tilt_deg} in degrees (tilt = angle off level)."""
    roll = math.atan2(2 * (w * x + y * z), 1 - 2 * (x * x + y * y))
    sp = max(-1.0, min(1.0, 2 * (w * y - z * x)))
    pitch = math.asin(sp)
    yaw = math.atan2(2 * (w * z + x * y), 1 - 2 * (y * y + z * z))
    up_z = max(-1.0, min(1.0, 1 - 2 * (x * x + y * y)))
    tilt = math.acos(up_z)
    return {"roll": round(math.degrees(roll), 1), "pitch": round(math.degrees(pitch), 1),
            "yaw": round(math.degrees(yaw), 1), "tilt_deg": round(math.degrees(tilt), 1)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=None)
    ap.add_argument("--port", type=int, default=9317)
    ap.add_argument("--hz", type=float, default=10.0)
    ap.add_argument("--stdout", action="store_true")
    args = ap.parse_args()

    out = sys.stdout
    if not args.stdout:
        if not args.host:
            ap.error("--host required unless --stdout")
        out = socket.create_connection((args.host, args.port), timeout=10).makefile("w")

    signal.signal(signal.SIGALRM, _alarm)
    signal.setitimer(signal.ITIMER_REAL, 25)
    bno, rst = init_sensor()
    signal.setitimer(signal.ITIMER_REAL, 0)
    print("sensor up — multi-modal (accel + orientation + chip stability)", file=sys.stderr)

    shake_count = 0
    last_shake = 0.0
    peak_dev = 0.0
    peak_at = 0.0
    errors = 0
    period = 1.0 / args.hz
    next_emit = time.monotonic()
    last_raw = None
    last_change = time.monotonic()
    orient = {"roll": 0.0, "pitch": 0.0, "yaw": 0.0, "tilt_deg": 0.0}
    chip = None

    while True:
        t = time.monotonic()
        try:
            signal.setitimer(signal.ITIMER_REAL, 1.5)
            ax, ay, az = bno.acceleration
            try:
                qi, qj, qk, qr = bno.quaternion
                orient = quat_to_orientation(qi, qj, qk, qr)
            except Exception:
                pass
            try:
                chip = bno.stability_classification
            except Exception:
                pass
            signal.setitimer(signal.ITIMER_REAL, 0)
            errors = 0
        except Exception as e:
            signal.setitimer(signal.ITIMER_REAL, 0)
            errors += 1
            if errors == 1 or errors % 20 == 0:
                print(f"read error x{errors} (continuing): {e}", file=sys.stderr)
            if errors >= REINIT_AFTER:
                try:
                    rst.deinit()
                except Exception:
                    pass
                try:
                    signal.setitimer(signal.ITIMER_REAL, 25)
                    bno, rst = init_sensor()
                    signal.setitimer(signal.ITIMER_REAL, 0)
                    errors = 0
                except Exception:
                    signal.setitimer(signal.ITIMER_REAL, 0)
                    time.sleep(1.0)
            else:
                time.sleep(0.02)
            continue

        if (ax, ay, az) != last_raw:
            last_raw = (ax, ay, az)
            last_change = t
        elif t - last_change > STALE_S:
            last_change = t
            try:
                rst.deinit()
            except Exception:
                pass
            try:
                signal.setitimer(signal.ITIMER_REAL, 25)
                bno, rst = init_sensor()
                signal.setitimer(signal.ITIMER_REAL, 0)
            except Exception:
                signal.setitimer(signal.ITIMER_REAL, 0)
                time.sleep(1.0)
            continue

        dev = abs(math.sqrt(ax * ax + ay * ay + az * az) - G)
        if dev > SHAKE_DEV and (t - last_shake) > 0.5:
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
            # --- decision fields: identical derivation to v4 ---
            "data_at_risk": shaken,
            "user_facing": moving,
            "error_rate": min(100, int(eff * SCALE)),
            "dev_mg": int(peak_dev * 1000),
            "stability": "shaken" if shaken else ("moving" if moving else "still"),
            "shake_count": shake_count,
            # --- multi-modal context (on-chip fusion) ---
            "accel_mg": [int(ax * 1000), int(ay * 1000), int(az * 1000)],
            "orientation": orient,
            "chip_stability": chip,
            "ts": round(time.time(), 3),
        }
        out.write(json.dumps(fields) + "\n")
        out.flush()


if __name__ == "__main__":
    sys.exit(main())
