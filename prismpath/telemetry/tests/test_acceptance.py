# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The Facet acceptance, pinned by the frozen corpus conformance/inputs.json that the Rust crate
reads too: every case's value is accepted to the recorded symbol or refused for the recorded
reason, by checked_symbol and by the checked encoder; the permissive symbol() agrees on every
accepted value; and the one thing the contract exists to prevent, an unsupported input becoming a
valid zero reading, cannot happen through either path."""
import json
from pathlib import Path

import pytest

from prismpath.kernel.parser import parse
from prismpath.telemetry import quantizer, wire

CORPUS = json.loads((Path(__file__).resolve().parent.parent / "conformance" / "inputs.json").read_text(encoding="utf-8"))
PARTS = quantizer.build_partitions(parse(CORPUS["flow"]))


def _case_id(case):
    return f"{case['field']}={json.dumps(case['input'])}"


@pytest.mark.parametrize("case", CORPUS["cases"], ids=_case_id)
def test_checked_symbol_follows_the_corpus(case):
    partition = PARTS[case["field"]]
    if "symbol" in case["expect"]:
        assert partition.checked_symbol(case["input"]) == case["expect"]["symbol"]
    else:
        with pytest.raises(quantizer.InputRefused) as caught:
            partition.checked_symbol(case["input"])
        assert caught.value.reason == case["expect"]["refuse"]
        assert caught.value.field == case["field"]


@pytest.mark.parametrize("case", [case for case in CORPUS["cases"] if "symbol" in case["expect"]], ids=_case_id)
def test_permissive_symbol_agrees_on_every_accepted_value(case):
    partition = PARTS[case["field"]]
    _reason, converted = quantizer.accept_value(partition.kind, case["input"])
    assert partition.symbol(converted) == case["expect"]["symbol"]


@pytest.mark.parametrize("entry", CORPUS["readings"], ids=lambda entry: json.dumps(entry["reading"]))
def test_checked_encoding_follows_the_corpus(entry):
    if "symbols" in entry["expect"]:
        bits = wire.encode_reading_checked(PARTS, entry["reading"])
        assert wire.decode_reading(PARTS, bits) == quantizer.reconstruct(PARTS, entry["expect"]["symbols"])
        assert quantizer.checked_quantize(PARTS, entry["reading"]) == entry["expect"]["symbols"]
    else:
        with pytest.raises(quantizer.InputRefused) as caught:
            wire.encode_reading_checked(PARTS, entry["reading"])
        assert caught.value.field == entry["expect"]["refuse"]["field"]
        assert caught.value.reason == entry["expect"]["refuse"]["reason"]


def test_an_unparseable_string_is_never_a_zero_reading():
    zero_symbol = PARTS["error_rate"].symbol(0)
    with pytest.raises(quantizer.InputRefused):
        PARTS["error_rate"].checked_symbol("abc")
    with pytest.raises(ValueError):
        PARTS["error_rate"].symbol("abc")
    assert zero_symbol == 0, "the zero cell exists, and neither path reaches it from a string that is not a number"


def test_corpus_covers_every_reason_and_kind():
    reasons = {case["expect"].get("refuse") for case in CORPUS["cases"] if "refuse" in case["expect"]}
    assert reasons == {"missing", "wrong_type", "unparseable_string", "fractional", "out_of_range"}
    assert {PARTS[case["field"]].kind for case in CORPUS["cases"]} == {"numeric", "boolean", "categorical"}
