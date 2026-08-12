"""Live coincident capture — the only artifact that fills the fusion bands with a TRUE joint.

Two real streams recorded in the SAME wall-clock window: the sensor bridge's physical posture
(spawned via sudo BLINKA_MCP2221) and the live SIEM's alerts (polled read-only). Each alert is
joined to the WORST physical posture within +/- a few seconds of when it fired ("was the device
disturbed around when this alert happened?"), fused through fusion_triage, and counted per band.

Unlike the month-scale census this is genuinely coincident: a `tandem_watch` here means a real
watch-grade alert fired while the device was really being handled. `coincident_critical` needs a
containment-grade alert (rule_level >= 12), which does not occur naturally in a few minutes — if
that band is empty, that is the honest finding, not a gap to paper over.

    sudo-capable:  python adapters/fusion/live_capture.py --seconds 240 --insecure
    offline test:  python adapters/fusion/live_capture.py --from-capture readings.ndjson alerts.json
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import subprocess
import sys
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
for p in (str(REPO / "adapters" / "telemetry"), str(REPO / "adapters" / "soc"), str(REPO), str(HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

import packed as pk       # noqa: E402
import quantizer as q     # noqa: E402
import spiral as sp       # noqa: E402
import zeckendorf as z    # noqa: E402
from prismpath.parser import parse  # noqa: E402

import projection as pj  # noqa: E402

FLOW_PATH = HERE / "flows" / "fusion_triage.md"
NODE = "correlate"
HW = REPO / "prismpath-hw"
BRIDGE = HW / "bridge" / "field_bridge.py"
BRIDGE_MULTI = HW / "bridge" / "field_bridge_multi.py"
BRIDGE_PY = HW / ".venv" / "bin" / "python"
JOIN_WINDOW_S = 3.0   # +/- seconds around an alert to look for coincident posture

# chip stability_classification verdicts -> our derived-posture vocabulary, for the cross-check
_CHIP_TO_POSTURE = {"On Table": "still", "Stationary": "still", "Stable": "still",
                    "In motion": "moving", "Motion": "moving"}


def _iso_to_epoch(s: str) -> float:
    return _dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


# ------------------------------------------------------- stream collectors

def collect_sensor(readings: List[dict], raw_rows: List[dict], stop: threading.Event,
                   hz: float, bridge: Path) -> None:
    """Spawn the sudo bridge in --stdout mode; append each normalized posture and its raw row."""
    proc = subprocess.Popen(
        ["sudo", "env", "BLINKA_MCP2221=1", str(BRIDGE_PY), "-u", str(bridge),
         "--stdout", "--hz", str(hz)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    try:
        for line in proc.stdout:
            if stop.is_set():
                break
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            norm = pj.normalize_imu(row)
            if norm and norm.get("ts") is not None and norm.get("dev_mg") is not None:
                readings.append(norm)
                raw_rows.append(row)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()


def collect_alerts(src, alerts: List[Tuple[float, int]], stop: threading.Event,
                   start_epoch: float, min_level: int) -> None:
    """Poll the SIEM for alerts newer than the last seen, read-only, until stopped."""
    import requests
    getattr(src, "_ensure_auth", lambda: None)()
    seen = set()
    while not stop.is_set():
        body = {"size": 200, "sort": [{"timestamp": "desc"}],
                "query": {"bool": {"filter": [
                    {"range": {"rule.level": {"gte": min_level}}},
                    {"range": {"timestamp": {"gte": _dt.datetime.utcfromtimestamp(start_epoch)
                                             .isoformat() + "Z"}}}]}}}
        try:
            r = requests.post(f"{src.url}/{src.index}/_search", auth=src.auth,
                              verify=src.verify, json=body, timeout=20)
            r.raise_for_status()
            for h in r.json()["hits"]["hits"]:
                hid = h.get("_id")
                if hid in seen:
                    continue
                seen.add(hid)
                s = h["_source"]
                ts = s.get("timestamp")
                lvl = (s.get("rule") or {}).get("level")
                if ts is not None and lvl is not None:
                    alerts.append((_iso_to_epoch(ts), int(lvl)))
        except Exception:
            pass
        stop.wait(10)


# ------------------------------------------------------------------- join

def _worst_posture(postures: List[dict], t: float, window: float) -> Optional[dict]:
    """The most-disturbed posture within +/- window of time t (shaken > moving > still, then
    max dev_mg) — the honest 'was the device disturbed when this alert fired' question."""
    rank = {"shaken": 2, "moving": 1}
    near = [p for p in postures if abs(p["ts"] - t) <= window]
    if not near:
        return None
    return max(near, key=lambda p: (rank.get(p["stability"], 0), p["dev_mg"]))


def join_and_census(postures: List[dict], alerts: List[Tuple[float, int]],
                    window: float = JOIN_WINDOW_S) -> dict:
    graph = parse(FLOW_PATH.read_text())
    layout = sp.SpiralLayout(graph, NODE)
    parts = q.build_partitions(graph)

    bands: Counter = Counter()
    matched = unmatched = 0
    coincidences = []   # aggregate-only: (level_bin, posture) pairs, no content
    for ts, level in alerts:
        posture = _worst_posture(postures, ts, window)
        if posture is None:
            unmatched += 1
            continue
        matched += 1
        reading = pj.fused_reading(level, pj.soc_action_from_level(level), posture)
        band = layout.routes[layout.band_id(reading)]
        bands[band] += 1
        if band not in ("cyber_watch", "all_quiet"):
            coincidences.append({"level": level, "stability": posture["stability"],
                                 "dev_mg": posture["dev_mg"], "band": band,
                                 "dt_s": round(abs(posture["ts"] - ts), 2)})

    return {
        "join_window_s": window,
        "alerts_seen": len(alerts),
        "alerts_matched_to_posture": matched,
        "alerts_unmatched": unmatched,
        "bands": {r: bands.get(r, 0) for r in layout.routes},
        "notable_coincidences": coincidences,
    }


def posture_summary(postures: List[dict]) -> dict:
    stab = Counter(p["stability"] for p in postures)
    devs = sorted(p["dev_mg"] for p in postures)
    n = len(devs)
    return {
        "n_readings": n,
        "stability": dict(stab),
        "dev_mg": {"max": devs[-1] if n else None,
                   "median": devs[n // 2] if n else None} if n else {},
        "span_s": round(postures[-1]["ts"] - postures[0]["ts"], 1) if n >= 2 else 0,
    }


# ------------------------------------------------------------------ artifact

def multimodal_summary(raw_rows: List[dict]) -> Optional[dict]:
    """On-chip fusion outputs captured alongside the decision: orientation range, the chip's own
    stability verdicts, its agreement with our derived posture, and the standard-multimodal-stream
    vs decision-code bandwidth (this capture's richer point)."""
    rich = [r for r in raw_rows if r.get("orientation") or r.get("chip_stability") is not None]
    if not rich:
        return None
    graph = parse(FLOW_PATH.read_text())
    parts = q.build_partitions(graph)

    def rng(field):
        vals = [r["orientation"][field] for r in rich if r.get("orientation")]
        return {"min": min(vals), "max": max(vals)} if vals else None

    chip = Counter(r.get("chip_stability") for r in rich if r.get("chip_stability") is not None)
    # cross-check: derived posture vs the chip's own verdict (still-class agreement)
    agree = total = 0
    for r in rich:
        cs = r.get("chip_stability")
        if cs is None or "stability" not in r:
            continue
        total += 1
        derived_still = r["stability"] == "still"
        chip_still = _CHIP_TO_POSTURE.get(cs, "moving") == "still"
        agree += (derived_still == chip_still)

    # bandwidth: the full multimodal reading as JSON vs the physical decision code
    std_bytes, dec_bits = [], []
    for r in rich:
        std_bytes.append(len(json.dumps(r, separators=(",", ":")).encode()))
        n = pj.normalize_imu(r)
        if n and n["dev_mg"] is not None:
            syms = [parts["stability"].symbol(n["stability"]) + 1,
                    parts["dev_mg"].symbol(n["dev_mg"]) + 1]
            dec_bits.append(len(z.encode_stream(syms)))
    std_avg = sum(std_bytes) / len(std_bytes)
    dec_avg_bytes = (sum(dec_bits) / len(dec_bits)) / 8 if dec_bits else 0
    return {
        "n_rich_readings": len(rich),
        "orientation_deg": {f: rng(f) for f in ("roll", "pitch", "yaw", "tilt_deg")},
        "chip_stability_verdicts": dict(chip),
        "derived_vs_chip_still_agreement": round(agree / total, 3) if total else None,
        "bandwidth": {
            "standard_multimodal_json_bytes_per_reading": round(std_avg, 1),
            "physical_decision_bits_per_reading": round(sum(dec_bits) / len(dec_bits), 2)
            if dec_bits else None,
            "ratio_json_over_decision": round(std_avg / dec_avg_bytes, 1) if dec_avg_bytes else None,
            "note": "the full on-chip fusion reading vs the decision-sufficient physical code, "
                    "per reading, LIVE; a batch compressor (zstd) needs the whole batch buffered "
                    "and is not a streaming competitor; decision-lossless, not data-lossless",
        },
    }


def build_artifact(postures: List[dict], alerts: List[Tuple[float, int]],
                   min_level: int, window: float, raw_rows: Optional[List[dict]] = None) -> dict:
    census = join_and_census(postures, alerts, window)
    art = {
        "generated": _dt.datetime.utcnow().isoformat() + "Z",
        "adapter": "fusion",
        "capture": "live_coincident",
        "node": NODE,
        "min_level": min_level,
        "physical": posture_summary(postures),
        "cyber": {"alerts_seen": len(alerts),
                  "level_histogram": dict(sorted(Counter(l for _, l in alerts).items()))},
        "joint": census,
    }
    multimodal = multimodal_summary(raw_rows) if raw_rows else None
    if multimodal:
        art["multimodal"] = multimodal
    art["caveats"] = [
            "TRUE joint: each alert is matched to the worst device posture within "
            f"+/-{window}s of when it fired; both streams are real and time-coincident.",
            "coincident_critical requires a containment-grade alert (rule_level >= 12), which "
            "does not occur naturally in a short window; an empty coincident_critical band is "
            "the honest finding for this capture, not a defect.",
            "Aggregates only: no alert content, hostnames, agent names, or IPs are recorded.",
    ]
    return art


def _load_capture(readings_path: Path, alerts_path: Path):
    postures, raw_rows = [], []
    for line in readings_path.read_text().splitlines():
        line = line.strip()
        if line:
            row = json.loads(line)
            n = pj.normalize_imu(row)
            if n and n.get("ts") is not None and n.get("dev_mg") is not None:
                postures.append(n)
                raw_rows.append(row)
    alerts = [(float(a["ts"]), int(a["level"])) for a in json.loads(alerts_path.read_text())]
    return postures, alerts, raw_rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seconds", type=int, default=240)
    ap.add_argument("--hz", type=float, default=10.0)
    ap.add_argument("--min-level", type=int, default=3,
                    help="capture all real alerts at or above this level (3 = dense timeline)")
    ap.add_argument("--window", type=float, default=JOIN_WINDOW_S)
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--rich", action="store_true",
                    help="use the multi-modal bridge (orientation + on-chip stability at 10 Hz)")
    ap.add_argument("--from-capture", nargs=2, metavar=("READINGS", "ALERTS"),
                    help="offline replay of a recorded capture")
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    raw_rows: List[dict] = []
    if args.from_capture:
        postures, alerts, raw_rows = _load_capture(Path(args.from_capture[0]),
                                                   Path(args.from_capture[1]))
    else:
        if args.insecure:
            import os
            os.environ.setdefault("SIEM_VERIFY_TLS", "0")
        from siem import source_from_env
        src = source_from_env()
        bridge = BRIDGE_MULTI if args.rich else BRIDGE
        postures: List[dict] = []
        alerts: List[Tuple[float, int]] = []
        stop = threading.Event()
        start = time.time()
        threads = [
            threading.Thread(target=collect_sensor,
                             args=(postures, raw_rows, stop, args.hz, bridge), daemon=True),
            threading.Thread(target=collect_alerts,
                             args=(src, alerts, stop, start, args.min_level), daemon=True),
        ]
        for t in threads:
            t.start()
        try:
            while time.time() - start < args.seconds:
                time.sleep(5)
                el = int(time.time() - start)
                print(f"  [{el:3d}s/{args.seconds}s] readings={len(postures):5d} "
                      f"alerts={len(alerts):3d}", flush=True)
        finally:
            stop.set()
            for t in threads:
                t.join(timeout=5)

    artifact = build_artifact(postures, alerts, args.min_level, args.window, raw_rows)
    out = Path(args.out) if args.out else \
        HERE / "evidence" / f"coincident_{_dt.date.today():%Y-%m-%d}.json"
    out.write_text(json.dumps(artifact, indent=1) + "\n")
    print(f"\nwrote {out}")
    print(f"  physical: {artifact['physical']['n_readings']} readings, "
          f"stability {artifact['physical']['stability']}")
    print(f"  cyber   : {artifact['cyber']['alerts_seen']} alerts, "
          f"levels {artifact['cyber']['level_histogram']}")
    print(f"  JOINT   : {json.dumps(artifact['joint']['bands'])}")
    if artifact.get("multimodal"):
        m = artifact["multimodal"]
        print(f"  chip    : {m['chip_stability_verdicts']}  "
              f"derived-vs-chip agreement={m['derived_vs_chip_still_agreement']}")
        print(f"  orient  : tilt {m['orientation_deg']['tilt_deg']}  "
              f"yaw {m['orientation_deg']['yaw']}")
        b = m["bandwidth"]
        print(f"  band/w  : multimodal JSON {b['standard_multimodal_json_bytes_per_reading']} B "
              f"vs decision {b['physical_decision_bits_per_reading']} bits/reading "
              f"({b['ratio_json_over_decision']}x)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
