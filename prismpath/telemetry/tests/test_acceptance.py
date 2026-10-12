# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The Facet acceptance, pinned by the frozen corpus conformance/inputs.json that the Rust crate
reads too: every case's value is accepted to the recorded symbol or refused for the recorded reason,
by the permissive symbol() and the checked encoder alike, since October 2026 one rule; every accepted
value takes the route it would take as it arrived; and an unsupported input never becomes a valid
reading through either path. Version 2 of the corpus marks each expectation it changed."""
import json
from pathlib import Path

import pytest

from prismpath.kernel import engine
from prismpath.kernel.parser import parse
from prismpath.telemetry import quantizer, wire

CORPUS = json.loads((Path(__file__).resolve().parent.parent / "conformance" / "inputs.json").read_text(encoding="utf-8"))
GRAPH = parse(CORPUS["flow"])
PARTS = quantizer.build_partitions(GRAPH)
# a reading every field of which is accepted, into which each case substitutes its own value
BASE = {"error_rate": 7, "region": "us", "user_facing": False}


def _case_id(case):
    return f"{case['field']}={json.dumps(case['input'])}"


@pytest.mark.parametrize("case", CORPUS["cases"], ids=_case_id)
@pytest.mark.parametrize("path", ["symbol", "checked_symbol"])
def test_both_paths_follow_the_corpus(case, path):
    encode = getattr(PARTS[case["field"]], path)
    if "symbol" in case["expect"]:
        assert encode(case["input"]) == case["expect"]["symbol"]
    else:
        with pytest.raises(quantizer.InputRefused) as caught:
            encode(case["input"])
        assert (caught.value.field, caught.value.reason) == (case["field"], case["expect"]["refuse"])


@pytest.mark.parametrize("case", [case for case in CORPUS["cases"] if "symbol" in case["expect"]], ids=_case_id)
def test_every_accepted_value_decides_as_it_arrives(case):
    raw = dict(BASE, **{case["field"]: case["input"]})
    decoded = wire.decode_reading(PARTS, wire.encode_reading(PARTS, raw))
    assert engine.first_deterministic(GRAPH.nodes["assess"].edges, raw)[0] \
        == engine.first_deterministic(GRAPH.nodes["assess"].edges, decoded)[0]


@pytest.mark.parametrize("entry", CORPUS["readings"], ids=lambda entry: json.dumps(entry["reading"]))
@pytest.mark.parametrize("encode", [wire.encode_reading_checked, wire.encode_reading], ids=["checked", "permissive"])
def test_encoding_follows_the_corpus(entry, encode):
    if "symbols" in entry["expect"]:
        bits = encode(PARTS, entry["reading"])
        assert wire.decode_reading(PARTS, bits) == quantizer.reconstruct(PARTS, entry["expect"]["symbols"])
        assert quantizer.checked_quantize(PARTS, entry["reading"]) == entry["expect"]["symbols"]
    else:
        with pytest.raises(quantizer.InputRefused) as caught:
            encode(PARTS, entry["reading"])
        assert caught.value.field == entry["expect"]["refuse"]["field"]
        assert caught.value.reason == entry["expect"]["refuse"]["reason"]


def test_a_string_is_never_a_number_on_either_path():
    for text in ("5", "+5", "abc", ""):
        for encode in (PARTS["error_rate"].symbol, PARTS["error_rate"].checked_symbol):
            with pytest.raises(quantizer.InputRefused, match="wrong_type"):
                encode(text)
    assert PARTS["error_rate"].symbol(5) == 1, "the parsed number is accepted; parsing is the adapter's"


def test_every_change_from_version_1_is_marked():
    changed = [entry for entry in CORPUS["cases"] + CORPUS["readings"] if "changed" in entry]
    assert CORPUS["version"] == 2 and len(changed) == 12
    for entry in changed:
        assert entry["changed"]["version"] == 2 and entry["changed"]["was"] != entry["expect"]


def test_corpus_covers_every_reason_and_kind():
    reasons = {case["expect"].get("refuse") for case in CORPUS["cases"] if "refuse" in case["expect"]}
    assert reasons == {"missing", "wrong_type", "fractional", "out_of_range"}
    assert {PARTS[case["field"]].kind for case in CORPUS["cases"]} == {"numeric", "boolean", "categorical"}
