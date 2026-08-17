# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Both engines, one frozen corpus. The Python reference (model_check.flow_level_m) and the JS
kernel (prismpath.mjs flowLevelM) are each certified against portable/conformance/level_m.json —
this pins the Python side; `node prismpath/portable/run_level_m.mjs` pins the JS side."""
import json
import os

from prismpath import model_check
from prismpath.parser import parse

CORPUS = os.path.join(os.path.dirname(__file__), "..", "portable", "conformance", "level_m.json")


def _norm(bad):
    return [{"node": r["node"], "target": r["target"], "condition": r["condition"], "reason": r["reason"]}
            for r in bad]


def test_python_level_m_matches_frozen_vectors():
    data = json.load(open(CORPUS, encoding="utf-8"))
    assert len(data["cases"]) >= 15
    for c in data["cases"]:
        all_in, bad = model_check.flow_level_m(parse(c["flow"]))
        got = {"level_m": all_in, "non_member_edges": _norm(bad)}
        assert got == c["expected"], f"{c['key']}: {got} != {c['expected']}"
