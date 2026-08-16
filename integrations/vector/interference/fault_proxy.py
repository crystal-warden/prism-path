#!/usr/bin/env python3
"""Fault injection proxy: edge sink connects to :19401, we forward to agg :19402, mangling per
phase. Every injected fault is logged to faults.ndjson so the harvest can attribute damage."""
import json, random, socket, threading, time
from datetime import datetime, timezone

START = time.time()
random.seed(1337)
LOG = open("faults.ndjson", "a", buffering=1)

def phase():
    m = (time.time() - START) / 60
    if m < 45: return "P0-clean"
    if m < 135: return "P1-intermittent"
    if m < 225: return "P2-severe"
    if m < 270: return "P3-blackout"
    if m < 315: return "P4-recovery"
    return "DONE"

def log(kind, **kw):
    LOG.write(json.dumps({"t": datetime.now(timezone.utc).isoformat(), "phase": phase(),
                          "fault": kind, **kw}) + "\n")

blackout_until = 0.0

def maybe_fault(data):
    """Return (data, close_now). Mutates per phase."""
    global blackout_until
    p = phase()
    if p in ("P0-clean", "P4-recovery", "DONE"):
        return data, False
    r = random.random()
    if p == "P1-intermittent":
        if r < 0.002:
            d = random.uniform(2, 10); log("stall", secs=round(d, 1)); time.sleep(d)
        elif r < 0.003:
            log("reset"); return data, True
        elif r < 0.006 and len(data) > 4:
            i = random.randrange(len(data)); b = bytearray(data); b[i] ^= 0xFF
            log("corrupt", bytes=1, at=i); return bytes(b), False
    elif p == "P2-severe":
        if r < 0.01:
            d = random.uniform(5, 20); log("stall", secs=round(d, 1)); time.sleep(d)
        elif r < 0.02:
            log("reset"); return data, True
        elif r < 0.05 and len(data) > 8:
            b = bytearray(data); nf = random.randint(1, 8)
            for _ in range(nf): b[random.randrange(len(b))] ^= random.randrange(1, 256)
            log("corrupt", bytes=nf); return bytes(b), False
        elif r < 0.06:
            time.sleep(random.uniform(0.2, 1.5))
    elif p == "P3-blackout":
        now = time.time()
        if now < blackout_until:
            log("drop-during-blackout"); return None, True
        if r < 0.01:
            dur = random.uniform(30, 60); blackout_until = now + dur
            log("blackout", secs=round(dur)); return None, True
    return data, False

def handle(client):
    try:
        if time.time() < blackout_until:
            log("refused-during-blackout"); client.close(); return
        up = socket.create_connection(("127.0.0.1", 19402), timeout=10)
    except OSError:
        client.close(); return
    def pump(src, dst, mangle):
        try:
            while True:
                data = src.recv(65536)
                if not data: break
                if mangle:
                    data, close = maybe_fault(data)
                    if data is None or close and data is None: break
                    if data: dst.sendall(data)
                    if close: break
                else:
                    dst.sendall(data)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try: s.close()
                except OSError: pass
    t = threading.Thread(target=pump, args=(up, client, False), daemon=True)
    t.start()
    pump(client, up, True)

srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 19401)); srv.listen(4)
log("proxy-start")
while phase() != "DONE":
    srv.settimeout(5)
    try:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()
    except socket.timeout:
        continue
log("proxy-done")
