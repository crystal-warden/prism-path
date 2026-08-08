"""The capability matrix, one frozen corpus, both engines. Python (model_check.capability_report) is
pinned here; `node prismpath/portable/run_capability.mjs` pins the JS (capabilityReport) — so the CLI's
answer and the playground's answer to "where does this flow run?" can never disagree."""
import json
import os

from prismpath import model_check as mc
from prismpath.parser import parse

CORPUS = os.path.join(os.path.dirname(__file__), "..", "portable", "conformance", "capability.json")


def test_python_capability_matches_frozen_vectors():
    data = json.load(open(CORPUS, encoding="utf-8"))
    assert len(data["cases"]) >= 6
    for c in data["cases"]:
        got = mc.capability_report(parse(c["flow"]))
        assert got == c["expected"], f"{c['key']}: {got} != {c['expected']}"
