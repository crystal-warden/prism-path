"""The inspect path: decoding a captured bitstream against its flow reproduces each reading's routing
decision (the .md is the decoder), renders categorical 'other' readably, and survives a partial final
frame."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent))   # repo root
import decode as dec    # noqa: E402
import quantizer as q   # noqa: E402
import wire as w        # noqa: E402
from prismpath.parser import parse  # noqa: E402

CAT = """---
name: cat
start: classify
---
## classify
-> urgent: when kind == 'urgent'
-> batch: when kind in ('nightly', 'weekly')
-> blocked: when status != 'ok'
-> normal: else
## urgent
## batch
## blocked
## normal
"""


def test_decode_reproduces_routes():
    g = parse(CAT)
    parts = q.build_partitions(g)
    readings = [{"kind": "urgent", "status": "ok"},
                {"kind": "nightly", "status": "ok"},
                {"kind": "adhoc", "status": "bad"},
                {"kind": "weekly", "status": "degraded"}]
    bits = dec.encode_readings(parts, readings)
    rep = dec.inspect(g, bits)
    assert rep["n_readings"] == 4 and rep["trailing_ints"] == 0
    # each decoded reading routes exactly as the original did
    for orig, row in zip(readings, rep["readings"]):
        assert row["routes"]["classify"] == w.route_node(g, "classify", orig)


def test_other_renders_readably():
    g = parse(CAT)
    parts = q.build_partitions(g)
    bits = dec.encode_readings(parts, [{"kind": "adhoc", "status": "bad"}])
    rep = dec.inspect(g, bits)
    # 'adhoc' is not a listed kind -> the reconstructed representative shows as <other>, not a control char
    assert rep["readings"][0]["reading"]["kind"] == "<other>"


def test_partial_final_frame_is_reported_not_crashed():
    g = parse(CAT)
    parts = q.build_partitions(g)
    bits = dec.encode_readings(parts, [{"kind": "urgent", "status": "ok"}])
    rep = dec.inspect(g, bits + "0")           # a dangling bit = incomplete final frame
    assert rep["n_readings"] == 1              # the complete reading still decodes
