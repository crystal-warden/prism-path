"""Bandwidth: raw alert JSON vs the fused decision-code wire — measured, overhead counted.

The task frame (stated so the comparison stays honest): *the aggregator needs the fused verdict,
auditably.* Baselines ship the reading and decide centrally; ours decides at the edge and ships
the decision code plus the integrity apparatus. B2 is the apples-to-apples comparator (the same
four decision fields as JSON); B0 is the fidelity-class comparison against what the wire carries
today. The decision streams carry the four fields at partition resolution only — decision-
sufficient telemetry, not a lossless alert record.

Baselines (per alert):
  B0  compact JSON of the full source record          (what is shipped today)
  B1  compact JSON of the normalized alert            (the source's slimmed record)
  B2  compact JSON of the four fused decision fields  (same information, JSON-framed)
  B3  zlib-9 (and zstd-19 when importable) over the batch NDJSON of B0 and B2
      (the buffered-batch bound: batch compressors are not self-framing or line-rate)

Ours (per alert, overhead itemized, never hidden):
  O1  per-field decision stream: encode_readings -> packed words
  O2  band-ID stream: SpiralLayout.encode_decision -> packed words
      + per epoch (default 4096 readings, 1024-bit blocks): 32 B Merkle root,
        32 B chained epoch root, 32 B authenticated ACK on the return channel
      + a loss row: Gilbert-Elliott (the two regimes telemetry already benches),
        retransmitted block + 32*ceil(log2 n_blocks) B inclusion proof per served block

Shared-config assumption (stated): the receiver holds the flow — the policy hash is the
binding — so graph/partitions are not per-stream bytes.

    python adapters/fusion/bench/bandwidth.py --from-ndjson fixtures/alerts_synth.ndjson

The alert stream is fed here from NDJSON. Any decision source that yields {level: int} records
is a valid connector; the archived SIEM connector was the v1 example.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
import time
import zlib
from pathlib import Path
from typing import Dict, Iterator, List, Optional

HERE = Path(__file__).resolve().parent
ADAPTER = HERE.parent
REPO = ADAPTER.parent.parent
for p in (str(REPO / "adapters" / "telemetry"), str(REPO / "adapters" / "telemetry" / "bench"),
          str(REPO), str(ADAPTER)):
    if p not in sys.path:
        sys.path.insert(0, p)

import channel as CH        # noqa: E402  (telemetry's Gilbert-Elliott model)
import decode as D          # noqa: E402
import packed as P          # noqa: E402
import quantizer as q       # noqa: E402
import selfheal as sh       # noqa: E402
import spiral as sp         # noqa: E402
from prismpath.parser import parse  # noqa: E402

import projection as pj     # noqa: E402

FLOW_PATH = ADAPTER / "flows" / "fusion_triage.md"
NODE = "correlate"
BLOCK_BITS = 1024
EPOCH_READINGS = 4096
LOSS_REGIMES = (("light burst", 0.02, 0.5), ("heavy burst", 0.08, 0.3))


# ---------------------------------------------------------------- ingestion

def hits_from_ndjson(path: Path, max_docs: Optional[int] = None) -> Iterator[dict]:
    """Fixture replay: each flat row acts as its own _source (mechanics only — fixture byte
    numbers are never published)."""
    n = 0
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        yield {"_id": row.get("id", str(n)), "_source": row}
        n += 1
        if max_docs is not None and n >= max_docs:
            return


# ------------------------------------------------------------------ helpers

def _stats(sizes: List[int]) -> Dict[str, float]:
    s = sorted(sizes)
    n = len(s)
    return {"n": n, "total_bytes": sum(s), "avg": round(sum(s) / n, 1),
            "median": s[n // 2], "p90": s[int(n * 0.9)], "min": s[0], "max": s[-1]}


def _compact(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()


def collect(hits: Iterator[dict], normalize_hit) -> dict:
    """One pass: baseline sizes + the fused readings (assume-still posture; the physical
    fields' wire cost is identical whichever pairing fills them — the wire is fixed-field)."""
    b0, b1, b2 = [], [], []
    readings = []
    b0_batch, b2_batch = [], []
    for h in hits:
        src_doc = h.get("_source", {})
        raw = _compact(src_doc)
        b0.append(len(raw))
        b0_batch.append(raw)
        norm = normalize_hit(h)
        b1.append(len(_compact(norm)))
        level = int(norm.get("level", src_doc.get("level", 0)))
        reading = pj.fused_reading(level, pj.soc_action_from_level(level), pj.ASSUME_STILL)
        minimal = _compact(reading)
        b2.append(len(minimal))
        b2_batch.append(minimal)
        readings.append(reading)
    return {"b0": b0, "b1": b1, "b2": b2, "readings": readings,
            "b0_ndjson": b"\n".join(b0_batch), "b2_ndjson": b"\n".join(b2_batch)}


def batch_compressed(ndjson: bytes) -> Dict[str, int]:
    out = {"raw_bytes": len(ndjson), "zlib9_bytes": len(zlib.compress(ndjson, 9))}
    try:
        import zstandard  # optional, mirrors benchcodecs' pattern
        out["zstd19_bytes"] = len(zstandard.ZstdCompressor(level=19).compress(ndjson))
    except Exception:
        pass
    return out


def _stream_stats(all_bits: List[str], n: int) -> dict:
    """Pack per-epoch windows; count every byte the transport actually costs."""
    n_epochs = math.ceil(n / EPOCH_READINGS) or 1
    payload_bits = wire_bytes = pad_bits = 0
    roots = 0
    for e in range(n_epochs):
        window = "".join(all_bits[e * EPOCH_READINGS:(e + 1) * EPOCH_READINGS])
        if not window:
            continue
        data = P.pack(window)
        payload_bits += len(window)
        wire_bytes += len(data)
        pad_bits += len(data) * 8 - len(window)
        # the epoch apparatus: Merkle root + chained root (selfheal/epochs semantics)
        blocks = sh.chunk(window, BLOCK_BITS)
        sh.commit(blocks)   # exercised for real; the wire cost is the 32 B root
        roots += 1
    merkle_epoch_bytes = roots * 64          # 32 B Merkle root + 32 B chained root
    ack_bytes = roots * 32                   # authenticated ACK, return channel, itemized
    total = wire_bytes + merkle_epoch_bytes
    return {"n": n, "epochs": roots, "payload_bits": payload_bits, "pad_bits": pad_bits,
            "wire_bytes": wire_bytes, "merkle_epoch_bytes": merkle_epoch_bytes,
            "ack_bytes": ack_bytes, "wire_bytes_total": total,
            "bytes_per_alert": round(total / n, 3)}


def decision_stream_stats(parts, readings: List[dict]) -> dict:
    bits = [D.encode_readings(parts, [r]) for r in readings]
    return _stream_stats(bits, len(readings))


def band_stream_stats(layout, readings: List[dict]) -> dict:
    bits = [layout.encode_decision(r) for r in readings]
    return _stream_stats(bits, len(readings))


def loss_scenario(stream: dict) -> List[dict]:
    """Repair cost under burst loss: retransmitted blocks + their inclusion proofs."""
    total_bits = stream["payload_bits"]
    n_blocks = math.ceil(total_bits / BLOCK_BITS) or 1
    proof_bytes = 32 * math.ceil(math.log2(n_blocks)) if n_blocks > 1 else 0
    rows = []
    for label, p_, r_ in LOSS_REGIMES:
        mask = CH.lost_mask(n_blocks, p_, r_, seed=0)
        lost = int(mask.sum())
        rows.append({"regime": label, "p": p_, "r": r_, "n_blocks": n_blocks,
                     "lost_blocks": lost,
                     "repair_bytes": lost * (BLOCK_BITS // 8 + proof_bytes),
                     "proof_bytes_per_block": proof_bytes})
    return rows


# -------------------------------------------------------------------- report

def write_results(outdir: Path, data: dict) -> None:
    md = ["# Bandwidth — raw alert JSON vs the fused decision wire", "",
          f"Source: {data['source']}  ·  population: rule.level >= {data['min_level']}, "
          f"n = {data['n']:,}", ""]
    if data.get("synthetic"):
        md += ["**SYNTHETIC FIXTURE RUN — mechanics only; these numbers are never published.**", ""]
    md += ["Task frame: the aggregator needs the fused verdict, auditably. Baselines ship the",
           "reading and decide centrally; ours decides at the edge and ships the decision code.",
           "The decision streams are decision-sufficient, not a lossless alert record: B2 is the",
           "apples-to-apples ratio, B0 the fidelity-class one.", "",
           "| line | what | total bytes | bytes/alert |", "|---|---|---|---|"]

    def row(key, what, total, per):
        md.append(f"| {key} | {what} | {total:,} | {per} |")

    b0, b1, b2 = data["b0"], data["b1"], data["b2"]
    row("B0", "full _source JSON", b0["total_bytes"], b0["avg"])
    row("B1", "normalized alert JSON", b1["total_bytes"], b1["avg"])
    row("B2", "4-field minimal JSON", b2["total_bytes"], b2["avg"])
    for name, comp in (("B0", data["b3_full"]), ("B2", data["b3_minimal"])):
        for k, v in comp.items():
            if k != "raw_bytes":
                row("B3", f"{k} over {name} NDJSON batch", v, round(v / data["n"], 2))
    o1, o2 = data["o1"], data["o2"]
    row("O1", "per-field decision stream + epoch apparatus", o1["wire_bytes_total"],
        o1["bytes_per_alert"])
    row("O2", "band-ID stream + epoch apparatus", o2["wire_bytes_total"], o2["bytes_per_alert"])
    md += ["",
           f"O1 detail: payload {o1['payload_bits']:,} bits, pad {o1['pad_bits']:,} bits, "
           f"epochs {o1['epochs']} (Merkle+chain {o1['merkle_epoch_bytes']} B, "
           f"ACK return-channel {o1['ack_bytes']} B).",
           f"O2 detail: payload {o2['payload_bits']:,} bits, pad {o2['pad_bits']:,} bits.", "",
           "## Loss (selective repair, proofs paid on serve)", "",
           "| stream | regime | lost/total blocks | repair bytes |", "|---|---|---|---|"]
    for stream_name in ("o1", "o2"):
        for lr in data[f"{stream_name}_loss"]:
            md.append(f"| {stream_name.upper()} | {lr['regime']} | "
                      f"{lr['lost_blocks']}/{lr['n_blocks']} | {lr['repair_bytes']:,} |")

    r_b2 = b2["total_bytes"] / o1["wire_bytes_total"]
    r_b0 = b0["total_bytes"] / o1["wire_bytes_total"]
    gate = (r_b2 >= 10) and (r_b0 >= 500) and (o2["wire_bytes_total"] <= o1["wire_bytes_total"])
    best_batch = min(v for k, v in data["b3_minimal"].items() if k != "raw_bytes")
    md += ["", "## Reading (go/no-go)", "",
           f"- O1 vs B2 (apples-to-apples): **{r_b2:,.0f}x** smaller (gate: >= 10x).",
           f"- O1 vs B0 (fidelity-class): **{r_b0:,.0f}x** smaller (gate: >= 500x).",
           f"- O2 <= O1: {'yes' if o2['wire_bytes_total'] <= o1['wire_bytes_total'] else 'NO'}.",
           f"- B3 note, stated before anyone else states it: the best batch compressor over the",
           f"  minimal JSON ({best_batch / data['n']:.2f} B/alert) undercuts the streams on pure",
           "  size. It requires buffering the whole batch before a byte ships, is not",
           "  self-framing or per-reading streamable, and carries no tamper-evidence — the",
           "  buffered-batch bound, not a transport. The streams pay their integrity apparatus",
           "  and still land within striking distance of it.",
           "- Overheads are itemized above and included in every ratio; the ACK line is the",
           "  return channel and is reported, not folded in.", "",
           f"## Verdict: **{'PASS' if gate else 'FAIL'}**", "",
           f"_generated in {data['elapsed']:.1f}s_", ""]
    (outdir / "results.md").write_text("\n".join(md))
    (outdir / "results.json").write_text(json.dumps(
        {k: v for k, v in data.items() if k not in ()}, indent=1) + "\n")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--from-ndjson", type=str, required=True,
                    help="replay a flat NDJSON of {level: int} rows (the alert-level backlog connector)")
    ap.add_argument("--min-level", type=int, default=7)
    ap.add_argument("--max-docs", type=int, default=None)
    ap.add_argument("--out", type=str, default=None)
    args = ap.parse_args(argv)

    t0 = time.time()
    graph = parse(FLOW_PATH.read_text())
    parts = q.build_partitions(graph)
    layout = sp.SpiralLayout(graph, NODE)

    path = Path(args.from_ndjson)
    hits = (h for h in hits_from_ndjson(path, args.max_docs)
            if int(h["_source"].get("level", 0)) >= args.min_level)
    col = collect(hits, lambda h: h["_source"])
    source, synthetic = f"fixture:{path.name}", True

    n = len(col["readings"])
    if n == 0:
        print("no documents matched", file=sys.stderr)
        return 1

    o1 = decision_stream_stats(parts, col["readings"])
    o2 = band_stream_stats(layout, col["readings"])
    data = {
        "source": source, "synthetic": synthetic, "min_level": args.min_level, "n": n,
        "block_bits": BLOCK_BITS, "epoch_readings": EPOCH_READINGS,
        "b0": _stats(col["b0"]), "b1": _stats(col["b1"]), "b2": _stats(col["b2"]),
        "b3_full": batch_compressed(col["b0_ndjson"]),
        "b3_minimal": batch_compressed(col["b2_ndjson"]),
        "o1": o1, "o2": o2,
        "o1_loss": loss_scenario(o1), "o2_loss": loss_scenario(o2),
        "elapsed": time.time() - t0,
    }
    outdir = Path(args.out) if args.out else HERE
    write_results(outdir, data)
    print(f"wrote {outdir/'results.md'}  n={n:,}  "
          f"O1={o1['bytes_per_alert']} B/alert vs B0={data['b0']['avg']} B/alert")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
