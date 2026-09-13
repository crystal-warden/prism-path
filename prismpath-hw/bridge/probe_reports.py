# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Empirically probe which BNO086 report channels actually stream on THIS MCP2221A rig.

The field bridge is accelerometer-only on purpose: earlier bring-up found the rotation-vector
and stability-classifier channels wedge silently on this stack. This probe re-tests that, one
feature at a time, at the proven 20 Hz, and reports which channels yield live values — so we
design the richer capture around what actually works, not what the datasheet promises.

    sudo BLINKA_MCP2221=1 .venv/bin/python bridge/probe_reports.py [--seconds 8]
"""
from __future__ import annotations

import argparse
import time

import board
import busio
import digitalio
from adafruit_bno08x import (
    BNO_REPORT_ACCELEROMETER,
    BNO_REPORT_GYROSCOPE,
    BNO_REPORT_LINEAR_ACCELERATION,
    BNO_REPORT_MAGNETOMETER,
    BNO_REPORT_ROTATION_VECTOR,
    BNO_REPORT_GAME_ROTATION_VECTOR,
    BNO_REPORT_STABILITY_CLASSIFIER,
    BNO_REPORT_STEP_COUNTER,
)
from adafruit_bno08x.i2c import BNO08X_I2C

REPORT_US = 50_000

# (feature id, human label, accessor) — each probed on its own so one wedging channel does not
# mask the others.
FEATURES = [
    (BNO_REPORT_ACCELEROMETER, "accelerometer", lambda sensor: sensor.acceleration),
    (BNO_REPORT_LINEAR_ACCELERATION, "linear_acceleration", lambda sensor: sensor.linear_acceleration),
    (BNO_REPORT_GYROSCOPE, "gyroscope", lambda sensor: sensor.gyro),
    (BNO_REPORT_MAGNETOMETER, "magnetometer", lambda sensor: sensor.magnetic),
    (BNO_REPORT_ROTATION_VECTOR, "rotation_vector(quat)", lambda sensor: sensor.quaternion),
    (BNO_REPORT_GAME_ROTATION_VECTOR, "game_rotation_vector", lambda sensor: sensor.game_quaternion),
    (BNO_REPORT_STABILITY_CLASSIFIER, "stability_classifier", lambda sensor: sensor.stability_classification),
    (BNO_REPORT_STEP_COUNTER, "step_counter", lambda sensor: sensor.steps),
]


def _reset_bno():
    rst = digitalio.DigitalInOut(board.G0)
    rst.direction = digitalio.Direction.OUTPUT
    rst.value = False
    time.sleep(0.2)
    rst.value = True
    time.sleep(1.5)
    i2c = busio.I2C(board.SCL, board.SDA, frequency=400000)
    return BNO08X_I2C(i2c, address=0x4B), rst


def probe_one(feat, label, accessor, seconds):
    bno, rst = _reset_bno()
    try:
        try:
            bno.enable_feature(feat, report_interval=REPORT_US)
        except Exception as error:
            return {"label": label, "enabled": False, "error": f"enable: {type(error).__name__}: {error}"}
        time.sleep(0.5)
        ok = err = 0
        sample = None
        deadline = time.time() + seconds
        while time.time() < deadline:
            try:
                reading = accessor(bno)
                if reading is not None:
                    ok += 1
                    sample = reading
            except Exception:
                err += 1
            time.sleep(0.05)
        return {"label": label, "enabled": True, "samples": ok, "errors": err,
                "sample": _fmt(sample)}
    finally:
        try:
            rst.value = False
        except Exception:
            pass


def _fmt(value):
    if value is None:
        return None
    if isinstance(value, (tuple, list)):
        return [round(float(component), 3) for component in value]
    if isinstance(value, float):
        return round(value, 3)
    return value


def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("--seconds", type=float, default=6.0)
    args = arg_parser.parse_args()
    print(f"probing {len(FEATURES)} BNO086 channels, {args.seconds}s each "
          f"(full reset between each)...\n")
    for feat, label, accessor in FEATURES:
        result = probe_one(feat, label, accessor, args.seconds)
        if not result.get("enabled"):
            print(f"  {label:24s} ENABLE-FAIL  {result.get('error')}")
        else:
            verdict = "LIVE " if result["samples"] > 0 else "WEDGED"
            print(f"  {label:24s} {verdict} samples={result['samples']:4d} errors={result['errors']:4d} "
                  f"sample={result['sample']}")
        time.sleep(0.3)


if __name__ == "__main__":
    main()
