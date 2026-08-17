# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Three-valued reachability, one frozen corpus, both engines. Python (model_check.check_reach) is
pinned here; `node prismpath/portable/run_reach.mjs` pins the JS (checkReach) against the same
reach.json — so the CLI's reachability verdict and the playground's can never disagree. Witnesses are
not frozen (BFS tie-order is an implementation detail); the {reachable, proven} contract is."""
import json
import os

from prismpath import model_check as mc
from prismpath.parser import parse

CORPUS = os.path.join(os.path.dirname(__file__), "..", "portable", "conformance", "reach.json")


def test_python_reach_matches_frozen_vectors():
    data = json.load(open(CORPUS, encoding="utf-8"))
    assert len(data["cases"]) >= 11
    for c in data["cases"]:
        res = mc.check_reach(
            parse(c["flow"]), c["targets"],
            assume=c.get("assume"), bound=c.get("bound", 25),
            include_errors=c.get("include_errors", True),
            include_events=c.get("include_events", True),
        )
        got = {t: {"reachable": res[t].reachable, "proven": res[t].proven} for t in c["targets"]}
        assert got == c["expected"], f"{c['key']}: {got} != {c['expected']}"
