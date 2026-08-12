"""bench/wire.py — fixture-mode checks on the transmission-strategy simulator: schema, the
batching-amortizes property, the self-framing-persists-in-batch property, and latency ordering."""
import importlib.util
from pathlib import Path

ADAPTER = Path(__file__).resolve().parent.parent

# Load bench/wire.py under a distinct name: the file is itself called wire.py and does
# `import wire as w` for the telemetry codec, so importing it AS `wire` would shadow the codec.
_spec = importlib.util.spec_from_file_location("fusion_wire_bench", ADAPTER / "bench" / "wire.py")
W = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(W)


def _rows():
    events = W.events_from_fixture(n=1500, hz=6.0)
    graph = W.parse(W.FLOW.read_text())
    parts = W.q.build_partitions(graph)
    ours, jsonb = W.make_encoders(parts)
    ov = W.OVERHEAD["tcp_tls"]
    out = {}
    for label, enc, is_bits, attest, comp in [
        ("ours", ours, True, W.ATTEST_BYTES, False),
        ("json", jsonb, False, 0, False),
        ("json_z", jsonb, False, 0, True),
    ]:
        out[(label, "stream")] = W.simulate(events, enc, is_bits, mode="stream",
                                            overhead=ov, attest=attest, compress=comp)
        out[(label, "mtu")] = W.simulate(events, enc, is_bits, mode="mtu", max_latency_ms=2000,
                                         overhead=ov, attest=attest, compress=comp)
    return out


R = _rows()


def test_schema():
    for m in R.values():
        for k in ("packets", "total_wire_bytes", "bytes_per_event", "packets_per_day",
                  "mean_latency_ms", "p95_latency_ms"):
            assert k in m


def test_batching_amortizes_the_header_tax():
    # Unbatched, the per-packet header dominates the tiny payload; MTU-batching drops it hard.
    assert R[("ours", "stream")]["bytes_per_event"] > 50   # header-bound per-event
    assert R[("ours", "mtu")]["bytes_per_event"] < R[("ours", "stream")]["bytes_per_event"] / 3


def test_self_framing_advantage_persists_in_a_batch():
    # Batched JSON still pays its per-record keys; the self-framing codec pays none.
    assert R[("ours", "mtu")]["bytes_per_event"] < R[("json", "mtu")]["bytes_per_event"] / 3


def test_stream_is_zero_latency_batch_is_not():
    assert R[("ours", "stream")]["p95_latency_ms"] == 0
    assert R[("ours", "mtu")]["p95_latency_ms"] > 0


def test_committed_wire_results_are_aggregate_only():
    import json
    for f in (ADAPTER / "bench").glob("wire_*.json"):
        blob = json.loads(f.read_text())
        # only counts/sizes/latencies — no alert content ever enters this artifact
        assert set(blob) <= {"corpus", "n", "span_s", "overhead", "rows"}
        for row in blob["rows"]:
            assert set(row) >= {"format", "strategy", "bytes_per_event", "packets"}
