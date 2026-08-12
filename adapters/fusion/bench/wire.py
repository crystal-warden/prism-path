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

# --- optional confidentiality layer (TLS 1.3 primitives, composed not hand-rolled) ---
# ChaCha20-Poly1305 AEAD: +16 B tag/packet; nonce is implicit (derived from epoch+index, no wire).
# X25519 ECDHE: 32 B ephemeral public key each way = 64 B, re-keyed once per codec epoch, so the
# forward-secrecy boundary reuses the codec's existing epoch structure. Amortized to ~0 per decision.
AEAD_TAG = 16
ECDHE_HANDSHAKE = 64
REKEY_READINGS = 4096   # matches the telemetry codec's epoch length


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
             batch_n=None, batch_ms=None, max_latency_ms=None, attest=0, compress=False,
             enc_tag=0, rekey_readings=None) -> dict:
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
        wire = overhead + payload_bytes(buf) + attest + enc_tag   # enc_tag=AEAD tag when encrypted
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

    # ECDHE handshake: one 64 B exchange per rekey epoch, amortized across the whole run
    session_bytes = 0
    if rekey_readings:
        session_bytes = math.ceil(n / rekey_readings) * ECDHE_HANDSHAKE
    total = sum(packets) + session_bytes
    span = max(times[-1] - times[0], 1e-9)
    lat_ms = sorted(l * 1000 for l in latencies)
    return {
        "packets": len(packets),
        "total_wire_bytes": total,
        "bytes_per_event": round(total / n, 3),
        "bytes_per_day": round(total / span * 86400),
        "packets_per_day": round(len(packets) / span * 86400),
        "mean_latency_ms": round(sum(lat_ms) / len(lat_ms), 1) if lat_ms else 0,
        "p95_latency_ms": round(lat_ms[int(len(lat_ms) * 0.95)], 1) if lat_ms else 0,
    }


def measure_crypto_cost(payload_len: int, iters: int = 4000) -> dict:
    """Real, measured cost of the confidentiality layer on THIS host: X25519 ECDHE handshake +
    ChaCha20-Poly1305 over a representative packet. Composes the `cryptography` library; falls back
    to a labeled model if it is unavailable so the benchmark still runs."""
    import time
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    except Exception:
        return {"measured": False, "handshake_us": None, "encrypt_us_per_pkt": None,
                "aead_mb_s": None, "payload_len": payload_len}

    hs_iters = max(50, iters // 20)
    t0 = time.perf_counter()
    for _ in range(hs_iters):                       # full ECDHE: both endpoints keygen + exchange
        a, b = X25519PrivateKey.generate(), X25519PrivateKey.generate()
        ap, bp = a.public_key(), b.public_key()
        a.exchange(bp); b.exchange(ap)
    handshake_us = (time.perf_counter() - t0) / hs_iters * 1e6

    key = ChaCha20Poly1305.generate_key()
    aead = ChaCha20Poly1305(key)
    nonce, msg = bytes(12), bytes(payload_len)       # timing microbench (fixed nonce is fine here)
    t0 = time.perf_counter()
    for _ in range(iters):
        aead.encrypt(nonce, msg, None)
    enc_us = (time.perf_counter() - t0) / iters * 1e6
    return {"measured": True, "handshake_us": round(handshake_us, 1),
            "encrypt_us_per_pkt": round(enc_us, 2),
            "aead_mb_s": round(payload_len / (enc_us / 1e6) / 1e6, 1) if enc_us else None,
            "payload_len": payload_len}


def run(events, corpus: str, overhead_name: str, outdir: Path):
    graph = parse(FLOW.read_text())
    parts = q.build_partitions(graph)
    ours, jsonb = make_encoders(parts)
    ov = OVERHEAD[overhead_name]
    n = len(events)
    span = events[-1][0] - events[0][0]

    # Three transmission strategies the product supports interchangeably, plus the latency-cap knob.
    configs = [
        ("stream", dict(mode="stream")),                        # one packet/decision, zero latency
        ("batch:64", dict(mode="batch_n", batch_n=64)),         # count-triggered
        ("mtu-fill", dict(mode="mtu")),                         # size-triggered, NO time cap
        ("mtu+2s cap", dict(mode="mtu", max_latency_ms=2000)),  # same, with a latency bound
    ]
    # (fname, encoder, is_bits, attest, compress, enc_tag, rekey_readings)
    formats = [
        ("ours O1 (decision)", ours, True, ATTEST_BYTES, False, 0, None),
        ("ours O1 +AEAD+ECDHE", ours, True, ATTEST_BYTES, False, AEAD_TAG, REKEY_READINGS),
        ("JSON B2 (4-field)", jsonb, False, 0, False, 0, None),
        ("JSON B2 + zstd", jsonb, False, 0, True, 0, None),
    ]

    rows = []
    for fname, enc, is_bits, attest, comp, etag, rekey in formats:
        for cname, cfg in configs:
            m = simulate(events, enc, is_bits, overhead=ov, attest=attest, compress=comp,
                         enc_tag=etag, rekey_readings=rekey, **cfg)
            rows.append((fname, cname, m))

    by = {(f, c): m for f, c, m in rows}                       # (format, strategy) -> metrics
    o1 = {c: by[("ours O1 (decision)", c)] for c, _ in configs}
    enc = {c: by[("ours O1 +AEAD+ECDHE", c)] for c, _ in configs}
    json_fill = by[("JSON B2 (4-field)", "mtu-fill")]
    jz_fill = by[("JSON B2 + zstd", "mtu-fill")]

    def mb_day(m):
        return m["bytes_per_day"] / 1e6

    md = [f"# Wire-bytes benchmark — {corpus} corpus", "",
          f"n = {n:,} decisions over {span:.0f}s (~{n/span:.1f}/s). Transport overhead: "
          f"{overhead_name} ({ov} B/packet). MTU payload budget {MTU_PAYLOAD} B. Ours carries a "
          f"{ATTEST_BYTES} B Merkle root/packet (tamper-evident); JSON carries none.", "",
          "## Full matrix — 4 formats x 4 strategies", "",
          "| format | strategy | wire B/decision | packets/day | MB/day | p95 latency |",
          "|---|---|---|---|---|---|"]
    for fname, cname, m in rows:
        md.append(f"| {fname} | {cname} | {m['bytes_per_event']} | {m['packets_per_day']:,} | "
                  f"{mb_day(m):.3f} | {m['p95_latency_ms']} ms |")

    # ---- the three strategies over a 24-hour period (the product, ours O1) ----
    md += ["", "## The three strategies over 24 hours (ours O1 — the product)", "",
           "Same decisions, same fidelity; the operator picks the point on the bytes<->latency curve. "
           "All three ship in the box — no commitment to one.", "",
           "| strategy | what triggers a send | packets/day | MB/day | p95 latency |",
           "|---|---|---|---|---|",
           f"| stream | every decision | {o1['stream']['packets_per_day']:,} | "
           f"{mb_day(o1['stream']):.3f} | {o1['stream']['p95_latency_ms']} ms |",
           f"| batch:64 | every 64 decisions | {o1['batch:64']['packets_per_day']:,} | "
           f"{mb_day(o1['batch:64']):.3f} | {o1['batch:64']['p95_latency_ms']} ms |",
           f"| mtu-fill | packet reaches MTU | {o1['mtu-fill']['packets_per_day']:,} | "
           f"{mb_day(o1['mtu-fill']):.3f} | {o1['mtu-fill']['p95_latency_ms']} ms |",
           "",
           f"A timing cap is optional on top of any of these: **mtu+2s cap** bounds the mtu-fill p95 "
           f"from {o1['mtu-fill']['p95_latency_ms']} ms to {o1['mtu+2s cap']['p95_latency_ms']} ms "
           f"for {mb_day(o1['mtu+2s cap']):.3f} MB/day (vs {mb_day(o1['mtu-fill']):.3f}). The cap is a "
           f"knob, not a mode.", ""]

    # ---- fidelity across the three ----
    md += ["## Fidelity across the three strategies", "",
           "Fidelity separates onto two axes, and only one of them moves:", "",
           "| axis | stream | batch:64 | mtu-fill |",
           "|---|---|---|---|",
           "| decision fidelity (*what* was decided) | lossless | lossless | lossless |",
           f"| temporal fidelity (*when*, p95) | {o1['stream']['p95_latency_ms']} ms | "
           f"{o1['batch:64']['p95_latency_ms']} ms | {o1['mtu-fill']['p95_latency_ms']} ms |", "",
           "**Decision fidelity is strategy-invariant and lossless.** Batching, compression, and "
           "encryption are packaging: the routed verdict reconstructs bit-for-bit regardless of how "
           "packets are cut (the quantizer is decision-preserving by construction; proven three ways "
           "in `test_fusion_spiral.py`). The *only* axis a strategy trades is temporal fidelity — how "
           "fresh the decision is when it lands. So the choice is never 'accuracy vs bandwidth'; it is "
           "purely 'latency vs bandwidth', and the operator owns it.", ""]

    # ---- confidentiality layer (measured on this host) ----
    rep_len = max(64, round(o1["mtu-fill"]["total_wire_bytes"] / max(o1["mtu-fill"]["packets"], 1)
                            - ov - ATTEST_BYTES))
    cc = measure_crypto_cost(rep_len)
    enc_fill = enc["mtu-fill"]
    dbytes = enc_fill["bytes_per_event"] - o1["mtu-fill"]["bytes_per_event"]
    md += ["## Optional confidentiality layer — AEAD + ECDHE (composed, not hand-rolled)", "",
           "TLS-1.3 primitives on top of the decision stream, for transports that do not already "
           "provide TLS (LoRa, 802.15.4/Thread, raw UDP, bare-metal MCU links). Over TCP+TLS this is "
           "redundant. Both primitives run on a Cortex-M0+.", "",
           f"- **On the wire it is nearly free when batched:** ours O1 mtu-fill "
           f"{o1['mtu-fill']['bytes_per_event']} B/dec -> +AEAD+ECDHE "
           f"{enc_fill['bytes_per_event']} B/dec (**+{dbytes:.3f} B/decision**). The 16 B Poly1305 tag "
           f"amortizes across a full packet; the 64 B X25519 handshake amortizes across a "
           f"{REKEY_READINGS:,}-reading epoch (nonce is implicit, no wire).",
           f"- **Compute cost (measured, this host, {rep_len} B representative packet):** "
           + (f"ECDHE handshake ~{cc['handshake_us']} us (both endpoints, once/epoch); "
              f"ChaCha20-Poly1305 ~{cc['encrypt_us_per_pkt']} us/packet ({cc['aead_mb_s']} MB/s)."
              if cc["measured"] else "cryptography library unavailable — cost modeled, not measured."),
           "- **Confidentiality is the point, not integrity twice:** the AEAD tag secures the "
           "transport; the 32 B Merkle root is the persistent, cross-session audit chain. Different "
           "jobs. And salting would not help here — a 2-bit verdict is low-entropy, so only keyed "
           "AEAD (semantic security) hides `all_quiet` from `coincident_critical` on the wire.", ""]

    # ---- reading ----
    ours_stream = o1["stream"]
    md += ["## Reading", "",
           f"- **The header tax is a batching choice, not a codec limit.** Ours goes from "
           f"**{ours_stream['bytes_per_event']} B/decision** unbatched to "
           f"**{o1['mtu-fill']['bytes_per_event']} B/decision** at mtu-fill — the per-packet transport "
           f"header amortizes to ~0 because the codec is self-framing.",
           f"- **Batched-vs-batched, our advantage over plain JSON persists:** mtu-fill ours "
           f"{o1['mtu-fill']['bytes_per_event']} B vs JSON {json_fill['bytes_per_event']} B "
           f"(**{json_fill['bytes_per_event']/o1['mtu-fill']['bytes_per_event']:.0f}x**) — JSON keeps "
           f"paying per-record keys inside the batch; ours pays none.",
           f"- **JSON + zstd batched is {jz_fill['bytes_per_event']} B/decision** — the honest "
           f"'smallest bytes, but not streaming, not self-framing, no tamper-evidence' reference. Our "
           f"differentiation there is properties, not raw bytes; and our stream can be zstd'd too.",
           f"- **All three strategies are lossless and ship together.** The operator sets latency vs "
           f"bandwidth; encryption layers on for ~+{dbytes:.3f} B/decision when batched.", ""]

    (outdir / f"wire_{corpus}.md").write_text("\n".join(md))
    (outdir / f"wire_{corpus}.json").write_text(json.dumps(
        {"corpus": corpus, "n": n, "span_s": span, "overhead": overhead_name,
         "crypto_cost": cc,
         "rows": [{"format": f, "strategy": c, **m} for f, c, m in rows]}, indent=1) + "\n")
    print(f"wrote wire_{corpus}.md ({n:,} decisions)")
    for fname, cname, m in rows:
        print(f"  {fname:22s} {cname:12s} {m['bytes_per_event']:8.3f} B/dec  "
              f"p95 {m['p95_latency_ms']:.0f}ms  {mb_day(m):.2f} MB/day")


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
