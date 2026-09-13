#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Fault injection proxy: edge sink connects to :19401, we forward to agg :19402, mangling per
phase. Every injected fault is logged to faults.ndjson so the harvest can attribute damage."""

import json, random, socket, threading, time
from datetime import datetime, timezone

START = time.time()
random.seed(1337)
LOG = open("faults.ndjson", "a", buffering=1)


def phase():
    elapsed_minutes = (time.time() - START) / 60
    if elapsed_minutes < 45:
        return "P0-clean"
    if elapsed_minutes < 135:
        return "P1-intermittent"
    if elapsed_minutes < 225:
        return "P2-severe"
    if elapsed_minutes < 270:
        return "P3-blackout"
    if elapsed_minutes < 315:
        return "P4-recovery"
    return "DONE"


def log(kind, **kw):
    LOG.write(
        json.dumps({"t": datetime.now(timezone.utc).isoformat(), "phase": phase(), "fault": kind, **kw})
        + "\n"
    )


blackout_until = 0.0


def maybe_fault(data):
    """Return (data, close_now). Mutates per phase."""
    global blackout_until
    current_phase = phase()
    if current_phase in ("P0-clean", "P4-recovery", "DONE"):
        return data, False
    draw = random.random()
    if current_phase == "P1-intermittent":
        if draw < 0.002:
            stall_seconds = random.uniform(2, 10)
            log("stall", secs=round(stall_seconds, 1))
            time.sleep(stall_seconds)
        elif draw < 0.003:
            log("reset")
            return data, True
        elif draw < 0.006 and len(data) > 4:
            byte_index = random.randrange(len(data))
            corrupted = bytearray(data)
            corrupted[byte_index] ^= 0xFF
            log("corrupt", bytes=1, at=byte_index)
            return bytes(corrupted), False
    elif current_phase == "P2-severe":
        if draw < 0.01:
            stall_seconds = random.uniform(5, 20)
            log("stall", secs=round(stall_seconds, 1))
            time.sleep(stall_seconds)
        elif draw < 0.02:
            log("reset")
            return data, True
        elif draw < 0.05 and len(data) > 8:
            corrupted = bytearray(data)
            nf = random.randint(1, 8)
            for _ in range(nf):
                corrupted[random.randrange(len(corrupted))] ^= random.randrange(1, 256)
            log("corrupt", bytes=nf)
            return bytes(corrupted), False
        elif draw < 0.06:
            time.sleep(random.uniform(0.2, 1.5))
    elif current_phase == "P3-blackout":
        now = time.time()
        if now < blackout_until:
            log("drop-during-blackout")
            return None, True
        if draw < 0.01:
            dur = random.uniform(30, 60)
            blackout_until = now + dur
            log("blackout", secs=round(dur))
            return None, True
    return data, False


def handle(client):
    try:
        if time.time() < blackout_until:
            log("refused-during-blackout")
            client.close()
            return
        up = socket.create_connection(("127.0.0.1", 19402), timeout=10)
    except OSError:
        client.close()
        return

    def pump(src, dst, mangle):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                if mangle:
                    data, close = maybe_fault(data)
                    if data is None or close and data is None:
                        break
                    if data:
                        dst.sendall(data)
                    if close:
                        break
                else:
                    dst.sendall(data)
        except OSError:
            pass
        finally:
            for endpoint in (src, dst):
                try:
                    endpoint.close()
                except OSError:
                    pass

    upstream_thread = threading.Thread(target=pump, args=(up, client, False), daemon=True)
    upstream_thread.start()
    pump(client, up, True)


srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 19401))
srv.listen(4)
log("proxy-start")
while phase() != "DONE":
    srv.settimeout(5)
    try:
        client, _ = srv.accept()
        threading.Thread(target=handle, args=(client,), daemon=True).start()
    except socket.timeout:
        continue
log("proxy-done")
