# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The wire profile corpora (receipt_stream, replay, refresh, concentrator) are what the Python modules do,
frozen. Regenerating them from the live reference must reproduce the committed files,
so a change to a profile shows up as a diff; if it is intended, run
telemetry/gen_profile_corpora.py and review that diff, which is the profile change. The Rust crate replays
the same files (prismpath-telemetry-rs/tests/test_receipts.rs, test_replay.rs, test_refresh.rs,
test_concentrator.rs). The frozen receipts.json stays as adopted."""
import importlib.util
import json
import time
from pathlib import Path

import pytest

from prismpath.telemetry import concentrator, receipts, replay
from prismpath.telemetry import zeckendorf as zeck

ADAPTER = Path(__file__).resolve().parent.parent
REPO = ADAPTER.parent.parent
CONFORMANCE = ADAPTER / "conformance"
NAMES = ("receipt_stream", "replay", "refresh", "concentrator")


def _generator():
    spec = importlib.util.spec_from_file_location("gen_profile_corpora", ADAPTER / "gen_profile_corpora.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_committed_corpora_are_what_the_reference_does_now():
    live = _generator().corpora()
    for name in NAMES:
        committed = json.loads((CONFORMANCE / f"{name}.json").read_text(encoding="utf-8"))
        assert json.loads(json.dumps(live[f"{name}.json"])) == committed, (
            f"{name}.json no longer matches the Python module; if the change is intended, run "
            f"telemetry/gen_profile_corpora.py and commit the diff")


def test_the_corpora_cover_what_the_profiles_refuse():
    receipt_doc = json.loads((CONFORMANCE / "receipt_stream.json").read_text(encoding="utf-8"))
    assert {case["refusal_cause"] for case in receipt_doc["decode"]} == {
        receipts.OK, receipts.RECEIPT_TRUNCATED, receipts.RECEIPT_FIELD_MISMATCH, receipts.RECEIPT_INVALID_CAUSE}
    assert sum(1 for case in receipt_doc["encode"] if "refuse" in case) >= 10
    registered = {case["fields"]["cause"] for case in receipt_doc["encode"] if isinstance(case["fields"]["cause"], int)}
    from prismpath.kernel import causes
    assert {code for code, *_ in causes._REGISTRY} <= registered, "every registered cause code is an encode case"
    window_doc = json.loads((CONFORMANCE / "replay.json").read_text(encoding="utf-8"))
    seen = {cause for case in window_doc["cases"] for _ok, cause in case["expect"]}
    assert seen == {replay.ACCEPT, replay.REPLAY_DUPLICATE, replay.REPLAY_STALE}
    refresh_doc = json.loads((CONFORMANCE / "refresh.json").read_text(encoding="utf-8"))
    kinds = {kind for case in refresh_doc["trackers"] for _when, kind in case["transitions"]}
    assert kinds == {"stale", "recovered"}
    concentrator_doc = json.loads((CONFORMANCE / "concentrator.json").read_text(encoding="utf-8"))
    assert {case["cause"] for case in concentrator_doc["demux"]} == {
        concentrator.OK, concentrator.CONCENTRATOR_TRUNCATED, concentrator.CONCENTRATOR_UNKNOWN_STREAM}


def test_python_demux_stays_linear_on_a_long_hostile_datagram():
    from prismpath.telemetry import packed
    started = time.monotonic()
    for frame in (bytes(5000), b"\xff" * 5000, packed.pack("0" * 40000 + "11", 8)):
        concentrator.demux(frame, {1: 2})
    assert time.monotonic() - started < 5.0


def test_python_decodes_a_code_of_any_width_which_is_why_the_rust_crate_lists_wide_cases():
    wide = 2**100
    decoded = receipts.decode_receipt_bits(zeck.encode_stream([1, 1, 1, 1, wide]))
    assert decoded.refusal_cause == receipts.OK and decoded.receipt["seq"] == wide - 1
