# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The verified core's differential harness, at CI size (docs/design/spec-verified-core.md, section 8).

A seeded run of `formal/diff/core_diff.py`: random policy images and readings through the Lean oracle,
the Python reference and the Rust port. The large run is the documented command

    python formal/diff/core_diff.py --cases 100000 --seed 1

Every difference must be a reader gap, a scope difference, or one of the disagreements the
specification records in section 9 (KNOWN below). A new kind of finding fails, and so does a
disagreement on any reading. The oracle is built by `lake build` in formal/; without it the test skips,
unless PRISMPATH_REQUIRE_CORE_ORACLE is set, when a missing oracle is a failure.
"""
import os
import shutil
import sys
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if not (ROOT / "formal" / "diff" / "core_diff.py").exists():
    # an installed wheel carries the tests but not the research tree the harness lives in
    pytest.skip("formal/diff is not beside this package (an installed wheel)", allow_module_level=True)
sys.path.insert(0, str(ROOT / "formal" / "diff"))
import core_diff  # noqa: E402

CASES = 5000
SEED = 7

# The disagreements of spec section 9 that this step records and does not fix: D1 (the reference does
# not apply the depth bound to a defined flow), D2 (Rust bounds depth by its own measure), D3 (Rust does
# not treat U+001F as whitespace in a definition).
KNOWN = {
    ("python", "depth-bound-not-applied"),
    ("rust", "depth-bound-not-applied"),
    ("rust", "definition-whitespace-u001f"),
}


def _legs():
    if not core_diff.ORACLE.exists():
        if os.environ.get("PRISMPATH_REQUIRE_CORE_ORACLE"):
            pytest.fail(f"PRISMPATH_REQUIRE_CORE_ORACLE is set and {core_diff.ORACLE} is not built")
        pytest.skip("the Lean oracle is not built (cd formal && lake build)")
    if core_diff.rust_binary().exists() or shutil.which("cargo"):
        return ("python", "rust")
    if os.environ.get("PRISMPATH_REQUIRE_CORE_ORACLE"):
        pytest.fail("PRISMPATH_REQUIRE_CORE_ORACLE is set and there is no cargo for the Rust leg")
    return ("python",)


@pytest.fixture(scope="module")
def run():
    legs = _legs()
    cases = core_diff.generate(CASES, SEED)
    lean, results, counts, findings = core_diff.run(cases, legs)
    return legs, lean, counts, findings


def test_every_difference_is_known(run):
    legs, _lean, counts, findings = run
    kinds = Counter((leg, core_diff.finding_kind(detail)) for leg, _cls, detail, _case in findings)
    unknown = {kind: count for kind, count in kinds.items() if kind not in KNOWN}
    assert not unknown, f"new kinds of disagreement with the oracle: {unknown}"
    for leg in legs:
        assert counts[leg]["agree"] > CASES, counts[leg]


def test_no_reading_disagrees_and_nothing_crashes(run):
    legs, _lean, counts, _findings = run
    for leg in legs:
        assert counts[leg]["finding:reading"] == 0, counts[leg]
        assert counts[leg]["finding:crash"] == 0, counts[leg]
        assert counts[leg]["finding:harness"] == 0, counts[leg]


def test_the_run_reaches_every_stage(run):
    _legs_, lean, _counts, _findings = run
    seen = Counter()
    for row in lean.values():
        seen["accepted" if row["policy"]["policy"] == "accepted" else row["policy"]["cause"]] += 1
        for verdict in row["readings"]:
            seen[verdict.get("cause", "route")] += 1
    for stage in ("accepted", "route", "route:no-matching-edge", "route:contract-violation", "reading:unreadable",
                  "policy:unreadable", "policy:shape", "policy:definition", "image:field-index-oob",
                  "policy:threshold", "policy:not-level-m", "policy:kind-mismatch", "policy:rounding",
                  "policy:none", "policy:absence-untested", "image:unknown-op", "image:unknown-type"):
        assert seen[stage] > 0, (stage, seen)


def test_the_oracle_on_the_spec_example(tmp_path):
    if not core_diff.ORACLE.exists():
        pytest.skip("the Lean oracle is not built")
    import json
    import subprocess
    image = {"format": "prismpath.core/1",
             "fields": {"error_rate": "fixed scale=10000 unit=ratio rounding=floor min=0 max=10000",
                        "label": "category absent=allowed"},
             "rules": [{"target": "hit", "when": ["cmp", "error_rate", ">=", ["num", "0.85"]]},
                       {"target": "gone", "when": ["cmp", "label", "==", ["none"]]},
                       {"target": "low", "when": ["and", ["cmp", "error_rate", "<", ["num", "0.25"]],
                                                  ["cmp", "label", "==", ["str", "a"]]]},
                       {"target": "miss", "when": ["always"]}]}
    (tmp_path / "p.json").write_text(json.dumps(image))
    readings = ['{"error_rate": 8500, "label": "b"}', '{"error_rate": 100}', '{"error_rate": 2499, "label": "a"}',
                '{"error_rate": "8500"}', '{"error_rate": 1.5}', '{"label": "a"}', "[]"]
    for index, text in enumerate(readings):
        (tmp_path / f"r{index}.json").write_text(text)
    out = subprocess.run([str(core_diff.ORACLE), str(tmp_path / "p.json")] +
                         [str(tmp_path / f"r{index}.json") for index in range(len(readings))],
                         capture_output=True, text=True, check=True).stdout.splitlines()
    assert [json.loads(line) for line in out] == [
        {"policy": "accepted"},
        {"verdict": "route", "target": "hit"},
        {"verdict": "route", "target": "gone"},
        {"verdict": "route", "target": "low"},
        {"verdict": "refuse", "cause": "route:contract-violation", "code": 37, "field": "error_rate", "reason": "wrong_type"},
        {"verdict": "refuse", "cause": "reading:unreadable", "code": None, "reason": "float"},
        {"verdict": "refuse", "cause": "route:contract-violation", "code": 37, "field": "error_rate", "reason": "missing"},
        {"verdict": "refuse", "cause": "reading:not-object", "code": None},
    ]
