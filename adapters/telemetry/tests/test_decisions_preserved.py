"""The differentiated proof, frozen. For every flow + reading in the corpus:
  * the engine still routes to the frozen target at every decision node (drift guard on flow + engine);
  * the wire round-trip — quantize -> Fibonacci-code -> decode -> reconstruct — routes to the SAME
    target at every decision node (decision preservation end-to-end, through the real codec).
A single divergence means telemetry compression changed a routing decision — the one thing this adapter
must never do.
"""
import json
import sys
from pathlib import Path

import pytest

_ADAPTER = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ADAPTER))
import quantizer as q  # noqa: E402
import wire as w       # noqa: E402

from prismpath.parser import parse  # noqa: E402

_CORPUS = _ADAPTER / "conformance" / "decisions.json"


def _cases():
    return json.loads(_CORPUS.read_text())["cases"]


def test_corpus_pinned():
    cases = _cases()
    assert len(cases) == 4
    assert sum(len(c["readings"]) for c in cases) >= 50


@pytest.mark.parametrize("case", _cases(), ids=lambda c: c["name"])
def test_engine_matches_frozen_routes(case):
    """Drift guard: the flow + engine still produce the recorded full-precision routes."""
    g = parse(case["flow"])
    for entry in case["readings"]:
        reading, routes = entry["reading"], entry["routes"]
        for node, target in routes.items():
            got = w.route_node(g, node, reading)
            assert got == target, f"[{case['name']}] engine drift at {node} on {reading}: {got} != {target}"


@pytest.mark.parametrize("case", _cases(), ids=lambda c: c["name"])
def test_wire_round_trip_preserves_decisions(case):
    """The proof: quantize -> Fibonacci -> decode -> reconstruct routes identically at every node."""
    g = parse(case["flow"])
    parts = q.build_partitions(g)
    for entry in case["readings"]:
        reading, routes = entry["reading"], entry["routes"]
        recon = w.decode_reading(parts, w.encode_reading(parts, reading))
        for node, target in routes.items():
            got = w.route_node(g, node, recon)
            assert got == target, (
                f"[{case['name']}] DECISION CHANGED at {node} on {reading} "
                f"(reconstructed {recon}): {got} != {target}")


def test_wire_round_trip_is_stable():
    """A reading's bitstream decodes to a reading that re-encodes to the same bits (idempotent wire)."""
    g = parse(_cases()[0]["flow"])
    parts = q.build_partitions(g)
    reading = _cases()[0]["readings"][0]["reading"]
    bits = w.encode_reading(parts, reading)
    recon = w.decode_reading(parts, bits)
    assert w.encode_reading(parts, recon) == bits
