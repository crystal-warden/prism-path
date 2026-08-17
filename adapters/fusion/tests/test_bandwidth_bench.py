# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""bench/bandwidth.py — fixture-mode mechanics (the bench itself stays out of pytest;
this drives main() on the synthetic fixture and checks the accounting identities)."""
import json
import sys
from pathlib import Path

import pytest

ADAPTER = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ADAPTER / "bench"))

import bandwidth as bw  # noqa: E402

FIXTURE = ADAPTER / "fixtures" / "alerts_synth.ndjson"


@pytest.fixture(scope="module")
def results(tmp_path_factory):
    out = tmp_path_factory.mktemp("bench")
    rc = bw.main(["--from-ndjson", str(FIXTURE), "--out", str(out)])
    assert rc == 0
    return (json.loads((out / "results.json").read_text()),
            (out / "results.md").read_text())


def test_schema_and_labels(results):
    data, md = results
    for key in ("b0", "b1", "b2", "b3_full", "b3_minimal", "o1", "o2", "o1_loss", "o2_loss"):
        assert key in data
    assert data["synthetic"] is True
    assert "SYNTHETIC FIXTURE RUN" in md
    assert "## Reading (go/no-go)" in md
    assert "## Verdict" in md


def test_population_is_the_triage_slice(results):
    data, _ = results
    # fixture: 25+15+7+3 = 50 rows at level >= 7
    assert data["n"] == 50
    assert data["b0"]["n"] == data["b2"]["n"] == 50


def test_padding_identity(results):
    data, _ = results
    for key in ("o1", "o2"):
        s = data[key]
        assert s["payload_bits"] + s["pad_bits"] == s["wire_bytes"] * 8
        assert s["wire_bytes_total"] == s["wire_bytes"] + s["merkle_epoch_bytes"]
        assert s["merkle_epoch_bytes"] == s["epochs"] * 64
        assert s["ack_bytes"] == s["epochs"] * 32


def test_band_stream_never_beats_per_field_stream_backwards(results):
    data, _ = results
    assert data["o2"]["wire_bytes_total"] <= data["o1"]["wire_bytes_total"]


def test_overheads_are_present_not_hidden(results):
    data, _ = results
    assert data["o1"]["epochs"] >= 1
    assert data["o1"]["merkle_epoch_bytes"] > 0
    for row in data["o1_loss"]:
        assert {"regime", "lost_blocks", "repair_bytes", "proof_bytes_per_block"} <= set(row)
