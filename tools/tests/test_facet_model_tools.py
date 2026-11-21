# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The Facet model tools decode what the encoder wrote, refuse another policy's hash, and refuse a stream that
does not fit the codebook."""
import json
import random
from pathlib import Path

from tools.facet_model_tools import FacetServer, Policy

ROOT = Path(__file__).resolve().parents[2]
FUSION = ROOT / "adapters/fusion/flows/fusion_triage.md"
INPUT = ROOT / "prismpath-hw/demo/flows/demo_input.md"


def _setup():
    fusion, small = Policy(str(FUSION)), Policy(str(INPUT))
    rng = random.Random(7)
    readings = [{f: rng.choice(fusion.parts[f].cells)["rep"] for f in fusion.order} for _ in range(8)]
    return fusion, small, readings


def test_decode_matches_the_engine_and_describe_lists_every_field():
    fusion, small, readings = _setup()
    server = FacetServer([fusion, small], fusion.sha256)
    out = json.loads(server.call("facet_decode", {"stream_hex": fusion.encode(readings).hex(),
                                                  "policy_hash": fusion.sha256}))
    assert [r["decision"] for r in out["readings"]] == [fusion.decision(r) for r in readings]
    desc = json.loads(server.call("facet_describe", {"policy_hash": fusion.sha256}))
    assert desc["field_order"] == sorted(fusion.parts)


def test_wrong_hash_is_refused_for_both_tools():
    fusion, small, readings = _setup()
    server = FacetServer([fusion, small], fusion.sha256)
    for name, args in (("facet_decode", {"stream_hex": fusion.encode(readings).hex()}), ("facet_describe", {})):
        out = json.loads(server.call(name, {**args, "policy_hash": small.sha256}))
        assert out["error"] == "refused" and "mismatch" in out["reason"]


def test_a_stream_that_does_not_fit_the_codebook_is_refused():
    fusion, small, readings = _setup()
    server = FacetServer([fusion, small], fusion.sha256)
    data = fusion.encode(readings)
    refused = 0
    for bit in range(len(data) * 8):
        flipped = bytearray(data)
        flipped[bit // 8] ^= 0x80 >> (bit % 8)
        out = json.loads(server.call("facet_decode", {"stream_hex": bytes(flipped).hex(),
                                                      "policy_hash": fusion.sha256}))
        refused += out.get("error") == "refused"
    assert refused > len(data) * 8 * 0.9
