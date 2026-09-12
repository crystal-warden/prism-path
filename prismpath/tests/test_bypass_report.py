# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Tests for bypass_report module."""

import json
import sys
from prismpath.safety import bypass_report


def test_rate_helper():
    assert bypass_report._rate([0, 10]) == 0.0
    assert bypass_report._rate([5, 10]) == 0.5
    assert bypass_report._rate([10, 10]) == 1.0
    assert bypass_report._rate([0, 0]) == 0.0


def test_measure():
    rep = bypass_report.measure()
    assert isinstance(rep, dict)
    required_keys = {"variants", "rules", "strata", "strata_class", "cells", "per_stratum", "rollup", "examples"}
    assert required_keys.issubset(set(rep.keys()))
    assert rep["variants"] > 0
    assert "control" in rep["rollup"]
    # Control stratum should have 0 bypassed
    assert rep["rollup"]["control"][0] == 0


def test_measure_collisions():
    col = bypass_report.measure_collisions()
    assert isinstance(col, dict)
    assert col["cases"] > 0
    assert col["false_matches"] == 0
    assert "per_stratum" in col
    assert "per_split" in col


def test_render():
    rep = bypass_report.measure()
    rendered = bypass_report.render(rep)
    assert isinstance(rendered, str)
    assert "P0 FLOOR" in rendered
    assert "control stratum is 0.00" in rendered


def test_main(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["bypass_report"])
    res = bypass_report.main()
    assert res == 0
    captured = capsys.readouterr()
    assert "P0 FLOOR" in captured.out


def test_main_json(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["bypass_report", "--json"])
    res = bypass_report.main()
    assert res == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "variants" in data
    assert "collisions" in data
