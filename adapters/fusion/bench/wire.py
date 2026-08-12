"""Wire-bytes benchmark — the honest transmission-cost model the payload benchmark deferred.

`bandwidth.py` measured payload + attestation. This measures what actually goes on the wire:
per-PACKET transport framing (IP/TCP/TLS) under three transmission strategies, over two real
arrival patterns (a bursty SIEM stream and a steady sensor stream), for our decision codec vs a
JSON baseline, with and without per-packet compression. It answers the question a rigorous
reviewer asks first: "the header tax eats your 1.5-byte payload — what's the real wire cost?"

The point it proves: because the codec is self-framing (zero per-reading framing), batching is
lossless, so the one per-packet transport header amortizes to near-zero as a packet fills — while
a batched JSON stream still carries its per-record keys. The header tax only bites in the
unbatched per-event regime, which is a latency choice, not a codec limit.

Strategies:
  stream      one packet per decision, sent immediately   (min latency, max header tax)
  batch:N     flush every N decisions                       (count-batched)
  mtu         fill to the MTU, flush; also flush on a max-latency cap  (the hybrid, recommended)

    python adapters/fusion/bench/wire.py --imu            # steady ~6 Hz sensor corpus (on disk)
    python adapters/fusion/bench/wire.py --live [--insecure] [--max-docs N]   # bursty SIEM
    python adapters/fusion/bench/wire.py --from-fixture   # CI
"""
from __future__ import annotations

import argparse
import json
import math
import sys
import zlib
from pathlib import Path
from typing import Callable, List, Tuple

HERE = Path(__file__).resolve().parent
ADAPTER = HERE.parent
REPO = ADAPTER.parent.parent
for p in (str(REPO / "adapters" / "telemetry"), str(REPO / "adapters" / "soc"), str(REPO), str(ADAPTER)):
    if p not in sys.path:
        sys.path.insert(0, p)

import packed as pk      # noqa: E402
import quantizer as q    # noqa: E402
import wire as w         # noqa: E402
from prismpath.parser import parse  # noqa: E402

import projection as pj  # noqa: E402

FLOW = ADAPTER / "flows" / "fusion_triage.md"
HW = REPO / "prismpath-hw" / "evidence"
IMU_SESSIONS = ["mac_bridge_sessions2-5.ndjson", "fabric_session1.ndjson"]

# transport per-packet overhead presets (bytes)
OVERHEAD = {"tcp_tls": 70, "udp_dtls": 48, "lora": 13, "raw": 0}
ATTEST_BYTES = 32   # one Merkle root per packet (tamper-evidence); JSON baseline carries none
MTU_PAYLOAD = 1400  # leave room under a 1500 MTU


def _compress(b: bytes) -> bytes:
    try:
        import zstandard
        return zstandard.ZstdCompressor(level=19).compress(b)
    except Exception:
        return zlib.compress(b, 9)


# ---------------------------------------------------------------- corpora

def events_from_imu() -> List[Tuple[float, dict]]:
    """Real steady sensor stream: each posture fused with a baseline cyber verdict."""
    out = []
    for name in IMU_SESSIONS:
        path = HW / name
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            n = pj.normalize_imu(json.loads(line))
            if n and n.get("ts") is not None and n.get("dev_mg") is not None and not n["derived"]:
                out.append((float(n["ts"]), pj.fused_reading(3, "ignore", n)))
    out.sort(key=lambda e: e[0])
    return out


def events_from_live(src, min_level: int, max_docs) -> List[Tuple[float, dict]]:
    """Real bursty SIEM stream: alert level + projected action, at real arrival timestamps."""
    import datetime as dt
    getattr(src, "_ensure_auth", lambda: None)()
    import requests
    out, after, seen = [], None, 0
    while True:
        body = {"size": 500, "query": {"range": {"rule.level": {"gte": min_level}}},
                "sort": [{"timestamp": "asc"}, {"_id": "asc"}]}
        if after is not None:
            body["search_after"] = after
        r = requests.post(f"{src.url}/{src.index}/_search", auth=src.auth, verify=src.verify,
                          json=body, timeout=60)
        r.raise_for_status()
        hits = r.json()["hits"]["hits"]
        if not hits:
            break
        for h in hits:
            s = h["_source"]
            ts = s.get("timestamp")
            lvl = (s.get("rule") or {}).get("level")
            if ts is None or lvl is None:
                continue
            epoch = dt.datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
            out.append((epoch, pj.fused_reading(int(lvl), pj.soc_action_from_level(int(lvl)),
                                                pj.ASSUME_STILL)))
            seen += 1
            if max_docs and seen >= max_docs:
                return sorted(out, key=lambda e: e[0])
        after = hits[-1]["sort"]
    return sorted(out, key=lambda e: e[0])


def events_from_fixture(n=2000, hz=6.0) -> List[Tuple[float, dict]]:
    import random
    rng = random.Random(7)
    out, t = [], 1_000_000.0
    for _ in range(n):
        t += 1.0 / hz
        lvl = rng.choice([3, 3, 3, 7, 8])
        out.append((t, pj.fused_reading(lvl, pj.soc_action_from_level(lvl), pj.ASSUME_STILL)))
    return out


# ------------------------------------------------------------- encoders

def make_encoders(parts):
    def ours(reading) -> str:                       # bit-string, self-framing
        return w.encode_reading(parts, reading)

    def jsonb(reading) -> bytes:                    # compact 4-field JSON + newline
        return (json.dumps(reading, separators=(",", ":"), sort_keys=True) + "\n").encode()
    return ours, jsonb


# ------------------------------------------------------------- the sim

def simulate(events, encode: Callable, is_bits: bool, mode: str, *, overhead: int,
             batch_n=None, batch_ms=None, max_latency_ms=None, attest=0, compress=False) -> dict:
    contribs = [encode(r) for _, r in events]
    times = [t for t, _ in events]
    n = len(events)

    def payload_bytes(idxs) -> int:
        if is_bits:
            raw = pk.pack("".join(contribs[i] for i in idxs))
        else:
            raw = b"".join(contribs[i] for i in idxs)
        if compress:
            raw = _compress(raw)
        return len(raw)

    def est_running_bytes(idxs) -> int:
        if is_bits:
            return math.ceil(sum(len(contribs[i]) for i in idxs) / 8)
        return sum(len(contribs[i]) for i in idxs)

    packets, latencies = [], []
    buf: List[int] = []

    def flush(flush_ts):
        if not buf:
            return
        wire = overhead + payload_bytes(buf) + attest
        packets.append(wire)
        for i in buf:
            latencies.append(flush_ts - times[i])
        buf.clear()

    for i in range(n):
        ts = times[i]
        if buf:
            deadline = None
            if mode == "batch_ms":
                deadline = times[buf[0]] + batch_ms / 1000.0
            elif mode == "mtu" and max_latency_ms:
                deadline = times[buf[0]] + max_latency_ms / 1000.0
            if deadline is not None and ts > deadline:
                flush(deadline)
        if mode == "mtu" and buf:
            budget = MTU_PAYLOAD - overhead - attest
            if est_running_bytes(buf + [i]) > budget:
                flush(ts)                          # packet full -> send now
        if mode == "stream":
            buf.append(i)
            flush(ts)
            continue
        buf.append(i)
        if mode == "batch_n" and len(buf) >= batch_n:
            flush(ts)
    flush(times[-1])

    total = sum(packets)
    span = max(times[-1] - times[0], 1e-9)
    lat_ms = sorted(l * 1000 for l in latencies)
    return {
        "packets": len(packets),
        "total_wire_bytes": total,
        "bytes_per_event": round(total / n, 3),
        "packets_per_day": round(len(packets) / span * 86400),
        "mean_latency_ms": round(sum(lat_ms) / len(lat_ms), 1) if lat_ms else 0,
        "p95_latency_ms": round(lat_ms[int(len(lat_ms) * 0.95)], 1) if lat_ms else 0,
    }


def run(events, corpus: str, overhead_name: str, outdir: Path):
    graph = parse(FLOW.read_text())
    parts = q.build_partitions(graph)
    ours, jsonb = make_encoders(parts)
    ov = OVERHEAD[overhead_name]
    n = len(events)
    span = events[-1][0] - events[0][0]

    configs = [
        ("stream", dict(mode="stream")),
        ("batch:64", dict(mode="batch_n", batch_n=64)),
        ("mtu(+2s cap)", dict(mode="mtu", max_latency_ms=2000)),
    ]
    formats = [
        ("ours O1 (decision)", ours, True, ATTEST_BYTES, False),
        ("JSON B2 (4-field)", jsonb, False, 0, False),
        ("JSON B2 + zstd", jsonb, False, 0, True),
    ]

    rows = []
    for fname, enc, is_bits, attest, comp in formats:
        for cname, cfg in configs:
            m = simulate(events, enc, is_bits, overhead=ov, attest=attest, compress=comp, **cfg)
            rows.append((fname, cname, m))

    md = [f"# Wire-bytes benchmark — {corpus} corpus", "",
          f"n = {n:,} decisions over {span:.0f}s (~{n/span:.1f}/s). Transport overhead: "
          f"{overhead_name} ({ov} B/packet). MTU payload budget {MTU_PAYLOAD} B. Ours carries a "
          f"{ATTEST_BYTES} B Merkle root/packet (tamper-evident); JSON carries none.", "",
          "| format | strategy | wire B/decision | packets | packets/day | p95 latency |",
          "|---|---|---|---|---|---|"]
    for fname, cname, m in rows:
        md.append(f"| {fname} | {cname} | {m['bytes_per_event']} | {m['packets']:,} | "
                  f"{m['packets_per_day']:,} | {m['p95_latency_ms']} ms |")

    ours_stream = next(m for f, c, m in rows if f.startswith("ours") and c == "stream")
    ours_mtu = next(m for f, c, m in rows if f.startswith("ours") and c.startswith("mtu"))
    json_mtu = next(m for f, c, m in rows if f == "JSON B2 (4-field)" and c.startswith("mtu"))
    jz_mtu = next(m for f, c, m in rows if f == "JSON B2 + zstd" and c.startswith("mtu"))
    md += ["", "## Reading", "",
           f"- **The header tax is a batching choice, not a codec limit.** Ours goes from "
           f"**{ours_stream['bytes_per_event']} B/decision** unbatched (one packet each, header "
           f"dominates) to **{ours_mtu['bytes_per_event']} B/decision** MTU-batched — the "
           f"per-packet transport header amortizes to ~0 because the codec is self-framing.",
           f"- **Batched-vs-batched, our advantage persists:** MTU ours {ours_mtu['bytes_per_event']} "
           f"B vs MTU JSON {json_mtu['bytes_per_event']} B "
           f"(**{json_mtu['bytes_per_event']/ours_mtu['bytes_per_event']:.0f}x**) — JSON keeps paying "
           f"its per-record keys inside the batch; ours pays none.",
           f"- **JSON + zstd batched is {jz_mtu['bytes_per_event']} B/decision** — the honest "
           f"'smallest but not streaming, not self-framing, no tamper-evidence' reference; and our "
           f"stream can be zstd'd on top too.",
           f"- MTU batching cost p95 latency {ours_mtu['p95_latency_ms']} ms at this rate — the "
           f"bytes-vs-latency knob, stated.", ""]
    (outdir / f"wire_{corpus}.md").write_text("\n".join(md))
    (outdir / f"wire_{corpus}.json").write_text(json.dumps(
        {"corpus": corpus, "n": n, "span_s": span, "overhead": overhead_name,
         "rows": [{"format": f, "strategy": c, **m} for f, c, m in rows]}, indent=1) + "\n")
    print(f"wrote wire_{corpus}.md ({n:,} decisions)")
    for fname, cname, m in rows:
        print(f"  {fname:22s} {cname:14s} {m['bytes_per_event']:8.3f} B/dec  "
              f"p95 {m['p95_latency_ms']:.0f}ms  {m['packets']:,} pkts")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--imu", action="store_true")
    src.add_argument("--live", action="store_true")
    src.add_argument("--from-fixture", action="store_true")
    ap.add_argument("--min-level", type=int, default=3)
    ap.add_argument("--max-docs", type=int, default=None)
    ap.add_argument("--overhead", choices=list(OVERHEAD), default="tcp_tls")
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--out", default=str(HERE))
    args = ap.parse_args(argv)

    if args.imu:
        events, corpus = events_from_imu(), "imu"
    elif args.live:
        if args.insecure:
            import os
            os.environ.setdefault("SIEM_VERIFY_TLS", "0")
        from siem import source_from_env
        events, corpus = events_from_live(source_from_env(), args.min_level, args.max_docs), "siem"
    else:
        events, corpus = events_from_fixture(), "fixture"

    if len(events) < 2:
        print("not enough events", file=sys.stderr)
        return 1
    run(events, corpus, args.overhead, Path(args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
