# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""bench/wire.py  -  fixture-mode checks on the transmission-strategy simulator: schema, the
batching-amortizes property, the self-framing-persists-in-batch property, latency ordering, the
pure MTU-fill strategy (no cap), and the optional AEAD+ECDHE confidentiality layer's cost."""
from pathlib import Path

from adapters.fusion.bench import wire as bench_wire

ADAPTER = Path(__file__).resolve().parent.parent


def _sim(mode, *, enc=False, **kw):
    events = bench_wire.events_from_fixture(event_count=1500, hz=6.0)
    graph = bench_wire.parse(bench_wire.FLOW.read_text())
    parts = bench_wire.quantizer.build_partitions(graph)
    ours, _ = bench_wire.make_encoders(parts)
    return bench_wire.simulate(
        events, ours, True, mode=mode,
        overhead=bench_wire.OVERHEAD["tcp_tls"], attest=bench_wire.ATTEST_BYTES,
        enc_tag=bench_wire.AEAD_TAG if enc else 0,
        rekey_readings=bench_wire.REKEY_READINGS if enc else None, **kw)


STREAM = _sim("stream")
MTU_FILL = _sim("mtu")                       # pure size-triggered, no time cap
MTU_CAP = _sim("mtu", max_latency_ms=2000)
ENC_STREAM = _sim("stream", enc=True)
ENC_FILL = _sim("mtu", enc=True)


def test_schema():
    for metrics in (STREAM, MTU_FILL, MTU_CAP):
        for field in ("packets", "total_wire_bytes", "bytes_per_event", "bytes_per_day",
                  "packets_per_day", "mean_latency_ms", "p95_latency_ms"):
            assert field in metrics


def test_batching_amortizes_the_header_tax():
    # Unbatched, the per-packet header dominates the tiny payload; MTU-batching drops it hard.
    assert STREAM["bytes_per_event"] > 50                     # header-bound per-event
    assert MTU_FILL["bytes_per_event"] < STREAM["bytes_per_event"] / 10


def test_self_framing_advantage_persists_in_a_batch():
    # Batched JSON still pays its per-record keys; the self-framing codec pays none.
    events = bench_wire.events_from_fixture(event_count=1500, hz=6.0)
    graph = bench_wire.parse(bench_wire.FLOW.read_text())
    _, jsonb = bench_wire.make_encoders(bench_wire.quantizer.build_partitions(graph))
    json_fill = bench_wire.simulate(events, jsonb, False, mode="mtu", overhead=bench_wire.OVERHEAD["tcp_tls"])
    assert MTU_FILL["bytes_per_event"] < json_fill["bytes_per_event"] / 3


def test_pure_mtu_fill_is_smaller_but_slower_than_the_capped_variant():
    # The whole point of the cap: trade a few bytes to bound latency. No cap = min bytes, max wait.
    assert MTU_FILL["bytes_per_event"] < MTU_CAP["bytes_per_event"]
    assert MTU_FILL["p95_latency_ms"] > MTU_CAP["p95_latency_ms"]
    assert MTU_CAP["p95_latency_ms"] <= 2000


def test_stream_is_zero_latency_batch_is_not():
    assert STREAM["p95_latency_ms"] == 0
    assert MTU_FILL["p95_latency_ms"] > 0


def test_encryption_is_flat_per_packet_so_nearly_free_when_batched():
    # AEAD tag is a fixed per-PACKET cost: heavy per-decision when streaming (1 pkt/dec),
    # negligible per-decision when a packet holds thousands of decisions.
    stream_delta = ENC_STREAM["bytes_per_event"] - STREAM["bytes_per_event"]
    fill_delta = ENC_FILL["bytes_per_event"] - MTU_FILL["bytes_per_event"]
    assert stream_delta >= bench_wire.AEAD_TAG - 0.5                   # ~16 B/decision when unbatched
    assert fill_delta < 1.0                                   # sub-byte/decision when MTU-batched
    assert fill_delta < stream_delta / 10


def test_measured_crypto_cost_runs_on_this_host():
    # `cryptography` is an OPTIONAL dep (the signing tier): present in the control-plane test job,
    # absent in the bare adapters job. measure_crypto_cost honors that with a labeled loud-absence
    # fallback, so the bench runs either way  -  assert the actual contract on whichever host we're on.
    cc = bench_wire.measure_crypto_cost(1005, iters=200)
    assert cc["payload_len"] == 1005
    try:
        import cryptography  # noqa: F401
        have_crypto = True
    except Exception:
        have_crypto = False
    if have_crypto:
        assert cc["measured"] is True
        assert cc["handshake_us"] > 0 and cc["encrypt_us_per_pkt"] > 0
    else:
        assert cc["measured"] is False
        assert cc["handshake_us"] is None and cc["encrypt_us_per_pkt"] is None


def test_committed_wire_results_are_aggregate_only():
    import json
    for results_file in (ADAPTER / "bench").glob("wire_*.json"):
        blob = json.loads(results_file.read_text())
        # only counts/sizes/latencies/crypto-timings  -  no alert content ever enters this artifact
        assert set(blob) <= {"corpus", "n", "span_s", "overhead", "crypto_cost", "rows"}
        for row in blob["rows"]:
            assert set(row) >= {"format", "strategy", "bytes_per_event", "packets"}
