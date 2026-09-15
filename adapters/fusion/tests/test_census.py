# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""census.py  -  fixture-mode end-to-end, pairing arithmetic, and the privacy regression
against the ACTUAL committed evidence artifact."""
import json
import re
from pathlib import Path

import pytest

from adapters.fusion import census as cs
from adapters.fusion import projection

ADAPTER = Path(__file__).resolve().parent.parent
FIXTURE = ADAPTER / "fixtures" / "alerts_synth.ndjson"

# The fixture's deterministic distribution (see fixtures/README.md).
FIXTURE_DIST = {3: 100, 4: 50, 7: 25, 8: 15, 10: 7, 12: 3}


@pytest.fixture(scope="module")
def artifact():
    hist, meta = cs.cyber_marginal_ndjson(FIXTURE)
    return cs.build_artifact(hist, meta, min_level=7)


# ------------------------------------------------------------ fixture end-to-end

def test_fixture_marginal_reproduces_distribution():
    hist, meta = cs.cyber_marginal_ndjson(FIXTURE)
    assert hist == FIXTURE_DIST
    assert meta["index_pattern"].startswith("fixture:")


def test_assume_still_arithmetic(artifact):
    assume_still = artifact["pairings"]["assume_still"]
    assert assume_still["n"] == 50  # levels >= 7 in the fixture
    # Under assume-still, watch-grade levels land in cyber_watch, containment-grade in
    # cyber_containment, and every fusion band stays empty. That emptiness is the finding.
    assert assume_still["bands"]["cyber_watch"] == 47
    assert assume_still["bands"]["cyber_containment"] == 3
    for band in ("coincident_critical", "physical_escalation", "tandem_watch",
                 "physical_watch", "all_quiet"):
        assert assume_still["bands"][band] == 0
    assert sum(assume_still["bands"].values()) == assume_still["n"]
    assert assume_still["rounding_residual"] == 0
    assert sum(assume_still["cells"]) == assume_still["n"] and len(assume_still["cells"]) == 108


def test_independence_expected_sums_to_cyber_n(artifact):
    independence = artifact["pairings"]["independence_expected"]
    assert independence["n"] == 50
    assert abs(sum(independence["bands"].values()) - independence["n"]) <= len(independence["bands"])  # rounding only
    assert abs(independence["rounding_residual"]) <= len(independence["bands"])
    assert "NOT time-coincident" in independence["label"]


def test_artifact_carries_the_honesty_apparatus(artifact):
    assert artifact["projection_rule"].startswith("soc_action =")
    assert "NOT an adjudicator verdict" in artifact["projection_rule"]
    assert len(artifact["caveats"]) >= 3
    assert artifact["flow_sha256"]
    assert artifact["query"]["min_level"] == 7


# ------------------------------------------------------------------ IMU marginal

def test_imu_marginal_uses_real_sessions(artifact):
    imu = artifact["imu_marginal"]
    if imu["rows_seen"] == 0:
        pytest.skip("sensor sessions not present in this checkout")
    assert imu["rows_used"] > 0
    assert imu["include_derived"] is False
    # Every posture row is either used or excluded-as-derived; nothing vanishes silently.
    assert imu["rows_used"] + imu["derived_excluded"] == imu["rows_seen"]
    # All keys canonicalize: "stability|symbol"
    for key in imu["counts"]:
        stability, sym = key.split("|")
        assert stability in projection.CANONICAL_STABILITY
        assert 0 <= int(sym) <= 3


# ------------------------------------------------------------- privacy regression

FORBIDDEN_KEYS = {"agent", "agents", "srcip", "src_ip", "description", "full_log", "hostname"}
FORBIDDEN_SUBSTRINGS = ["gx10", "warden-node", "opnsense", "vm101"]
IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


def _walk(obj, path="$"):
    if isinstance(obj, dict):
        for key, value in obj.items():
            assert key.lower() not in FORBIDDEN_KEYS, f"forbidden key {key!r} at {path}"
            _walk(value, f"{path}.{key}")
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            _walk(value, f"{path}[{index}]")
    elif isinstance(obj, str):
        low = obj.lower()
        for forbidden in FORBIDDEN_SUBSTRINGS:
            assert forbidden not in low, f"forbidden substring {forbidden!r} at {path}"
        assert not IP_RE.search(obj), f"IP-like value at {path}"


def test_fixture_artifact_is_aggregate_only(artifact):
    _walk(artifact)


def test_committed_artifacts_are_aggregate_only():
    committed = sorted((ADAPTER / "evidence").glob("census_*.json"))
    if not committed:
        pytest.skip("no committed census artifact yet (pre-live-run checkout)")
    for path in committed:
        _walk(json.loads(path.read_text()))
