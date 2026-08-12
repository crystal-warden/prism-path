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


def quat_to_euler_deg(x, y, z, w):
    """(i,j,k,real) -> (roll, pitch, yaw) degrees, plus tilt-from-level."""
    roll = math.atan2(2 * (w * x + y * z), 1 - 2 * (x * x + y * y))
    sp = max(-1.0, min(1.0, 2 * (w * y - z * x)))
    pitch = math.asin(sp)
    yaw = math.atan2(2 * (w * z + x * y), 1 - 2 * (y * y + z * z))
    # tilt = angle between the device's up axis and world up (0 = perfectly level)
    up_z = 1 - 2 * (x * x + y * y)
    tilt = math.acos(max(-1.0, min(1.0, up_z)))
    return tuple(round(math.degrees(a), 1) for a in (roll, pitch, yaw, tilt))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=8.0)
    args = ap.parse_args()

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
    n = 0
    printed = 0
    deadline = time.time() + args.seconds
    while time.time() < deadline:
        n += 1
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
            s = bno.stability_classification
            counts["stability"] += 1
            stab[s] += 1
        except Exception:
            s = None
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
                  f"lin|a|={lmag} m/s2  stability={s}")
            printed += 1
        time.sleep(0.05)

    print(f"\n{n} read cycles in {args.seconds}s, all-features-simultaneous:")
    for k in ("accel", "lin_accel", "gyro", "quat", "stability", "mag"):
        print(f"  {k:12s} {counts[k]:4d}/{n}  ({100*counts[k]//max(n,1)}%)")
    print(f"  chip stability verdicts: {dict(stab)}")
    rst.value = False


if __name__ == "__main__":
    main()
