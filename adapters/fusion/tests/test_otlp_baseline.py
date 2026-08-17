# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""bench/otlp_baseline.py — the OTLP industry-baseline mechanics.

Guards the claims the artifact makes so they can't silently rot: every record is a VALID
`opentelemetry.proto` LogRecord (round-trips), OTLP is genuinely *larger* than minimal JSON for this
payload (the honest finding), and epoching pays overhead (we don't cherry-pick the single-batch
number). Uses a small population — the full 64,484-row run lives in the bench, not pytest."""
import sys
from pathlib import Path

import pytest

# opentelemetry is an OPTIONAL bench dependency (the industry-baseline codec), not a base CI dep —
# skip cleanly when it's absent, matching the loud-absence convention the other benches use.
pytest.importorskip("opentelemetry")

ADAPTER = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ADAPTER / "bench"))

import otlp_baseline as ob  # noqa: E402
from opentelemetry.proto.logs.v1.logs_pb2 import LogRecord  # noqa: E402

POP = ob._representative_population(256)


def test_records_are_valid_otlp_and_round_trip():
    for reading in (POP[0], POP[100], POP[255]):
        lr = ob._log_record(reading, ob.BASE_TS, faithful=True)
        rt = LogRecord()
        rt.ParseFromString(lr.SerializeToString())
        keys = {kv.key for kv in rt.attributes}
        assert keys == {"stability", "dev_mg", "rule_level", "soc_action"}
        # the int fields survive the round-trip as ints (not stringified)
        got = {kv.key: kv.value for kv in rt.attributes}
        assert got["rule_level"].int_value == reading["rule_level"]


def test_otlp_is_larger_than_minimal_json():
    # the honest finding: OTLP is a telemetry envelope, so a faithful record exceeds the 68 B of
    # minimal 4-field JSON — the win over OTLP is structural, not a compression trick.
    marginal = (len(ob._logs_data(POP[:2], True)) - len(ob._logs_data(POP[:1], True)))
    assert marginal >= 68, f"faithful OTLP record ({marginal} B) should exceed minimal JSON (68 B)"


def test_faithful_exceeds_minimal_encoding():
    assert (len(ob._logs_data(POP, True)) > len(ob._logs_data(POP, False)))


def test_epoching_pays_overhead_not_cherry_picked():
    # shipped in epochs, Resource+Scope is paid per batch -> total is >= one giant batch, never less.
    epoched = ob._epoched_bytes(POP, True, 64)
    one = len(ob._logs_data(POP, True))
    assert epoched >= one
