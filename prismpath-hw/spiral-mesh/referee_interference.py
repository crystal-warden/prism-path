#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Phased interference referee for the ESP-NOW mesh — the real-RF counterpart to #107's modeled
Gilbert-Elliott burst soak. Run one command per interference phase (baseline, microwave, hotspot,
bowl, hand); each captures all three nodes, then measures, PER DIRECTED LINK (sender -> observer):

  - delivery: fraction of the sender's band-tier frames that reached the observer;
  - the BURST CHANNEL: the run-length histogram of consecutive lost ticks (the thing #107 modeled
    with a two-state Gilbert-Elliott channel, now measured over real 2.4 GHz interference);
  - band tier (class 1, every tick) vs refinement (class 2, every 5th) survival, separately;
  - INTEGRITY: any received symbol whose value disagrees with what the sender transmitted for that
    tick. ESP-NOW drops FCS-failed frames, so this must stay 0 — a wrong symbol would be a real bug,
    and 0-wrong-under-interference is the mesh's version of #107's "0 wrong events".

  - posture coherence: fraction of fully-reported ticks where all nodes agree, per phase.

    python3 referee_interference.py <phase_label> <seconds>      # capture + dump phase_<label>.json
    python3 referee_interference.py --aggregate                  # summarize every phase_*.json
    python3 referee_interference.py --selftest                   # synthetic-log unit test, no board

The tick a frame carries is the SENDER's local tick, so losses are exact: sender's transmitted
band-tier ticks minus the observer's received ticks for that sender. Boundary runs at the window
edges are negligible over a multi-minute phase.
"""
import glob
import json
import os
import sys
import threading
import time

PORTS = ["/dev/ttyUSB2", "/dev/ttyUSB3", "/dev/ttyUSB4"]
HERE = os.path.dirname(os.path.abspath(__file__))


# ----------------------------------------------------------------- parsing (pure, unit-tested)
def parse_logs(logs_by_port):
    """logs_by_port: list (one per port) of line-lists. Returns transmitted/received/postures/roles."""
    roles = {}                      # port_idx -> role
    transmitted = {}                # role -> {cls -> {tick: value}}
    received = {}                   # observer_role -> {sender_role -> {cls -> {tick: value}}}
    postures = {}                  # tick -> {role -> n}
    for pi, lines in enumerate(logs_by_port):
        role = None
        for ln in lines:
            p = ln.split()
            try:
                if ln.startswith("BOOT"):
                    for tok in p:
                        if tok.startswith("role="):
                            role = int(tok.split("=")[1])
                    roles[pi] = role
                    transmitted.setdefault(role, {})
                    received.setdefault(role, {})
                elif ln.startswith("T ") and role is not None:
                    tick, cls, val = int(p[1]), int(p[2][1:]), int(p[3][1:])
                    transmitted[role].setdefault(cls, {})[tick] = val
                elif ln.startswith("R ") and role is not None:
                    src, cls, tick, val = int(p[1]), int(p[2][1:]), int(p[3][1:]), int(p[4][1:])
                    received[role].setdefault(src, {}).setdefault(cls, {})[tick] = val
                elif ln.startswith("P ") and role is not None:
                    tick = int(p[1])
                    n = int(p[2].split("=")[1])
                    postures.setdefault(tick, {})[role] = n
            except (ValueError, IndexError):
                pass
    return transmitted, received, postures, roles


def loss_runs(sent_ticks, recv_ticks):
    """Consecutive-loss run lengths over the sender's tick span. Returns (runs, delivered, sent)."""
    if not sent_ticks:
        return [], 0, 0
    lo, hi = min(sent_ticks), max(sent_ticks)
    sent = set(sent_ticks)
    runs, cur = [], 0
    delivered = 0
    for t in range(lo, hi + 1):
        if t not in sent:
            continue
        if t in recv_ticks:
            delivered += 1
            if cur:
                runs.append(cur)
                cur = 0
        else:
            cur += 1
    if cur:
        runs.append(cur)
    return runs, delivered, len(sent)


def analyze(transmitted, received, postures, roles, label, secs):
    link_stats = []
    wrong = 0
    all_runs = []
    tot_sent = tot_deliv = 0
    for obs, by_src in received.items():
        for src, by_cls in by_src.items():
            if src not in transmitted or 1 not in transmitted[src]:
                continue
            sent1 = transmitted[src][1]
            recv1 = by_cls.get(1, {})
            runs, deliv, sent = loss_runs(set(sent1), set(recv1))
            all_runs += runs
            tot_sent += sent
            tot_deliv += deliv
            for t, v in recv1.items():
                if t in sent1 and v != sent1[t]:
                    wrong += 1
            link_stats.append({"link": f"{src}->{obs}", "sent": sent, "delivered": deliv,
                               "delivery_pct": round(100 * deliv / sent, 1) if sent else None,
                               "n_bursts": len(runs), "max_burst": max(runs) if runs else 0})
    # refinement (class 2) delivery, aggregate
    ref_sent = ref_deliv = 0
    for obs, by_src in received.items():
        for src, by_cls in by_src.items():
            if src in transmitted and 2 in transmitted[src]:
                s2 = set(transmitted[src][2]); r2 = set(by_cls.get(2, {}))
                ref_sent += len(s2); ref_deliv += len(s2 & r2)
    # posture coherence
    full = {t: v for t, v in postures.items() if len(v) == len(PORTS)}
    agree = sum(1 for v in full.values() if len(set(v.values())) == 1)
    # burst histogram
    hist = {}
    for r in all_runs:
        hist[r] = hist.get(r, 0) + 1
    return {
        "phase": label, "seconds": secs,
        "band_tier": {"sent": tot_sent, "delivered": tot_deliv,
                      "delivery_pct": round(100 * tot_deliv / tot_sent, 1) if tot_sent else None},
        "refinement": {"sent": ref_sent, "delivered": ref_deliv,
                       "delivery_pct": round(100 * ref_deliv / ref_sent, 1) if ref_sent else None},
        "burst_runlength_hist": {str(k): hist[k] for k in sorted(hist)},
        "max_burst": max(all_runs) if all_runs else 0,
        "mean_burst": round(sum(all_runs) / len(all_runs), 2) if all_runs else 0.0,
        "wrong_symbols": wrong,
        "coherence_pct": round(100 * agree / len(full), 1) if full else None,
        "links": link_stats,
    }


# ----------------------------------------------------------------- capture (needs the boards)
def capture(port, out, secs):
    import serial
    s = serial.Serial(port, 115200, timeout=2)
    s.dtr = False; s.rts = True
    time.sleep(0.1); s.rts = False
    s.reset_input_buffer()
    end = time.time() + secs
    while time.time() < end:
        line = s.readline().decode(errors="replace").strip()
        if line:
            out.append(line)
    s.close()


def run_phase(label, secs):
    logs = [[] for _ in PORTS]
    ts = [threading.Thread(target=capture, args=(p, logs[i], secs)) for i, p in enumerate(PORTS)]
    for t in ts: t.start()
    for t in ts: t.join()
    tx, rx, post, roles = parse_logs(logs)
    res = analyze(tx, rx, post, roles, label, secs)
    path = os.path.join(HERE, f"phase_{label}.json")
    json.dump(res, open(path, "w"), indent=2)
    bt = res["band_tier"]
    print(f"[{label}] band delivery {bt['delivery_pct']}%  max_burst {res['max_burst']}  "
          f"mean_burst {res['mean_burst']}  wrong_symbols {res['wrong_symbols']}  "
          f"coherence {res['coherence_pct']}%  -> {os.path.basename(path)}")


def aggregate():
    rows = []
    for f in sorted(glob.glob(os.path.join(HERE, "phase_*.json"))):
        rows.append(json.load(open(f)))
    print(f"{'phase':<12} {'band%':>6} {'refine%':>8} {'maxburst':>9} {'meanburst':>10} {'wrong':>6} {'cohere%':>8}")
    for r in rows:
        print(f"{r['phase']:<12} {str(r['band_tier']['delivery_pct']):>6} "
              f"{str(r['refinement']['delivery_pct']):>8} {r['max_burst']:>9} {r['mean_burst']:>10} "
              f"{r['wrong_symbols']:>6} {str(r['coherence_pct']):>8}")
    tot_wrong = sum(r["wrong_symbols"] for r in rows)
    print(f"\nINTEGRITY across all phases: {tot_wrong} wrong symbols "
          f"({'PASS — 0 wrong under real RF, the mesh counterpart to #107' if tot_wrong == 0 else 'FAIL'})")


# ----------------------------------------------------------------- self-test (no board)
def selftest():
    # sender role 0 transmits band ticks 100..119; observer role 1 loses ticks 103,104,105 (burst 3)
    # and 110 (burst 1); refinement every 5th; posture agrees except tick 112.
    sent = {t: (t % 4) for t in range(100, 120)}
    lost = {103, 104, 105, 110}
    recv = {t: v for t, v in sent.items() if t not in lost}
    logs = [
        [f"BOOT mac=0 role=0 ssc=0 bands=4 size=8"] + [f"T {t} c1 v{sent[t]}" for t in sent],
        [f"BOOT mac=1 role=1 ssc=0 bands=4 size=8"] + [f"R 0 c1 t{t} v{recv[t]} ab" for t in recv],
        [f"BOOT mac=2 role=2 ssc=0 bands=4 size=8"],
    ]
    tx, rx, post, roles = parse_logs(logs)
    res = analyze(tx, rx, post, roles, "selftest", 1)
    runs = sorted(k for k in res["burst_runlength_hist"])
    assert res["burst_runlength_hist"] == {"1": 1, "3": 1}, res["burst_runlength_hist"]
    assert res["max_burst"] == 3 and res["wrong_symbols"] == 0
    assert res["band_tier"]["sent"] == 20 and res["band_tier"]["delivered"] == 16
    # a corrupted value must be caught as a wrong symbol
    logs[1].append("R 0 c1 t101 v9 ab")  # sent value for 101 was 1, not 9
    tx, rx, post, roles = parse_logs(logs)
    assert analyze(tx, rx, post, roles, "x", 1)["wrong_symbols"] == 1
    print("selftest PASS — loss run-lengths, delivery, and integrity detection all correct")


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--selftest":
        selftest()
    elif len(sys.argv) == 2 and sys.argv[1] == "--aggregate":
        aggregate()
    elif len(sys.argv) == 3:
        run_phase(sys.argv[1], int(sys.argv[2]))
    else:
        print(__doc__)
        sys.exit(1)
