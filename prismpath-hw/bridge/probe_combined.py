# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Confirm the BNO086 fusion suite streams SIMULTANEOUSLY on this rig (the capture needs it),
and derive orientation from the quaternion. ~8s at 20 Hz with all features enabled at once.

    sudo BLINKA_MCP2221=1 .venv/bin/python bridge/probe_combined.py [--seconds 8]
"""
from __future__ import annotations

import argparse
import math
import time
from collections import Counter

import board
import busio
import digitalio
from adafruit_bno08x import (
    BNO_REPORT_ACCELEROMETER,
    BNO_REPORT_GYROSCOPE,
    BNO_REPORT_LINEAR_ACCELERATION,
    BNO_REPORT_MAGNETOMETER,
    BNO_REPORT_ROTATION_VECTOR,
    BNO_REPORT_STABILITY_CLASSIFIER,
)
from adafruit_bno08x.i2c import BNO08X_I2C

REPORT_US = 50_000


def quat_to_euler_deg(quat_i, quat_j, quat_k, quat_real):
    """(i,j,k,real) -> (roll, pitch, yaw) degrees, plus tilt-from-level."""
    roll = math.atan2(2 * (quat_real * quat_i + quat_j * quat_k), 1 - 2 * (quat_i * quat_i + quat_j * quat_j))
    sin_pitch = max(-1.0, min(1.0, 2 * (quat_real * quat_j - quat_k * quat_i)))
    pitch = math.asin(sin_pitch)
    yaw = math.atan2(2 * (quat_real * quat_k + quat_i * quat_j), 1 - 2 * (quat_j * quat_j + quat_k * quat_k))
    # tilt = angle between the device's up axis and world up (0 = perfectly level)
    up_z = 1 - 2 * (quat_i * quat_i + quat_j * quat_j)
    tilt = math.acos(max(-1.0, min(1.0, up_z)))
    return tuple(round(math.degrees(angle), 1) for angle in (roll, pitch, yaw, tilt))


def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("--seconds", type=float, default=8.0)
    args = arg_parser.parse_args()

    rst = digitalio.DigitalInOut(board.G0)
    rst.direction = digitalio.Direction.OUTPUT
    rst.value = False
    time.sleep(0.2)
    rst.value = True
    time.sleep(1.5)
    i2c = busio.I2C(board.SCL, board.SDA, frequency=400000)
    bno = BNO08X_I2C(i2c, address=0x4B)
    for feat in (BNO_REPORT_ACCELEROMETER, BNO_REPORT_LINEAR_ACCELERATION, BNO_REPORT_GYROSCOPE,
                 BNO_REPORT_MAGNETOMETER, BNO_REPORT_ROTATION_VECTOR,
                 BNO_REPORT_STABILITY_CLASSIFIER):
        bno.enable_feature(feat, report_interval=REPORT_US)
        time.sleep(0.2)
    time.sleep(0.5)

    counts = Counter()
    stab = Counter()
    cycle_count = 0
    printed = 0
    deadline = time.time() + args.seconds
    while time.time() < deadline:
        cycle_count += 1
        try:
            ax, ay, az = bno.acceleration
            counts["accel"] += 1
        except Exception:
            ax = ay = az = None
        try:
            lx, ly, lz = bno.linear_acceleration
            counts["lin_accel"] += 1
        except Exception:
            lx = ly = lz = None
        try:
            gx, gy, gz = bno.gyro
            counts["gyro"] += 1
        except Exception:
            gx = gy = gz = None
        try:
            qi, qj, qk, qr = bno.quaternion
            counts["quat"] += 1
        except Exception:
            qi = None
        try:
            stability = bno.stability_classification
            counts["stability"] += 1
            stab[stability] += 1
        except Exception:
            stability = None
        try:
            bno.magnetic
            counts["mag"] += 1
        except Exception:
            pass
        if qi is not None and printed < 4:
            eul = quat_to_euler_deg(qi, qj, qk, qr)
            gmag = round(math.sqrt(gx * gx + gy * gy + gz * gz), 3) if gx is not None else None
            lmag = round(math.sqrt(lx * lx + ly * ly + lz * lz), 3) if lx is not None else None
            print(f"  sample: roll/pitch/yaw/tilt={eul}  gyro|w|={gmag} rad/s  "
                  f"lin|a|={lmag} m/s2  stability={stability}")
            printed += 1
        time.sleep(0.05)

    print(f"\n{cycle_count} read cycles in {args.seconds}s, all-features-simultaneous:")
    for channel in ("accel", "lin_accel", "gyro", "quat", "stability", "mag"):
        print(f"  {channel:12s} {counts[channel]:4d}/{cycle_count}  ({100*counts[channel]//max(cycle_count,1)}%)")
    print(f"  chip stability verdicts: {dict(stab)}")
    rst.value = False


if __name__ == "__main__":
    main()
