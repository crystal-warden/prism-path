# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The verified core's differential harness, at CI size (docs/design/spec-verified-core.md, section 8).

A seeded run of `formal/diff/core_diff.py`: random policy images and readings through the Lean oracle,
the Python reference and the Rust port. The large run is the documented command

    python formal/diff/core_diff.py --cases 100000 --seed 1

Every difference must be a scope difference, a target limit, or one of the disagreements the
specification records in section 9 (KNOWN below, empty since step 3). A new kind of finding fails, and so
does a disagreement on any reading. Since the JavaScript and Go kernels took the core there are no reader
gaps and no refusing kernels: every leg reads canon/2 and decides. The oracle is built by `lake build` in formal/; without it the test skips,
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

# The disagreements of spec section 9 that step 1 recorded, D1 (the reference did not apply the depth
# bound to a defined flow), D2 (Rust bounded depth by its own measure) and D3 (Rust did not split a
# definition on U+001F), are fixed in step 2: none is known any more, so each would fail this test.
KNOWN = set()
# D7 is resolved in step 3: the reference and the Rust port name the first problem in the order of spec
# section 4, the oracle's, so a policy both refuse for different causes is a finding like any other.
KNOWN_PREFIXES = ()

def _legs():
    if not core_diff.ORACLE.exists():
        if os.environ.get("PRISMPATH_REQUIRE_CORE_ORACLE"):
            pytest.fail(f"PRISMPATH_REQUIRE_CORE_ORACLE is set and {core_diff.ORACLE} is not built")
        pytest.skip("the Lean oracle is not built (cd formal && lake build)")
    legs = ["python"]
    if core_diff.rust_binary().exists() or shutil.which("cargo"):
        legs.append("rust")
    for leg, tool in (("js", "node"), ("go", "go"), ("c-interp", "cc"), ("c-hdr", "cc"), ("ebpf", "cc")):
        if shutil.which(tool):
            legs.append(leg)
    missing = set(core_diff.ALL_LEGS) - set(legs)
    if missing and os.environ.get("PRISMPATH_REQUIRE_CORE_ORACLE"):
        pytest.fail(f"PRISMPATH_REQUIRE_CORE_ORACLE is set and these legs have no toolchain: {sorted(missing)}")
    return tuple(legs)


@pytest.fixture(scope="module")
def run():
    legs = _legs()
    cases = core_diff.generate(CASES, SEED)
    lean, results, counts, findings = core_diff.run(cases, legs)
    return legs, lean, counts, findings


def test_every_difference_is_known(run):
    legs, _lean, counts, findings = run
    kinds = Counter((leg, core_diff.finding_kind(detail)) for leg, _cls, detail, _case in findings)
    unknown = {kind: count for kind, count in kinds.items()
               if kind not in KNOWN and not kind[1].startswith(KNOWN_PREFIXES)}
    assert not unknown, f"new kinds of disagreement with the oracle: {unknown}"
    for leg in legs:
        assert counts[leg]["agree"] > CASES, counts[leg]


def test_no_reading_disagrees_and_nothing_crashes(run):
    legs, _lean, counts, _findings = run
    for leg in legs:
        assert counts[leg]["finding:cause"] == 0, counts[leg]     # D7: one cause per refused policy
        assert counts[leg]["finding:reading"] == 0, counts[leg]
        assert counts[leg]["finding:crash"] == 0, counts[leg]
        assert counts[leg]["finding:harness"] == 0, counts[leg]
        assert counts[leg]["finding:uncoded"] == 0, counts[leg]


def test_every_refusal_carries_a_registered_code(run):
    """Every refusal the oracle prints carries the registry's code for its cause (spec section 5); the
    legs' refusals are held to the same in the classification (finding:uncoded)."""
    from prismpath.kernel import causes
    _legs_, lean, _counts, _findings = run
    for row in lean.values():
        refusals = [row["policy"]] if row["policy"]["policy"] != "accepted" else []
        refusals += [verdict for verdict in row["readings"] if verdict["verdict"] == "refuse"]
        for refusal in refusals:
            assert refusal["code"] is not None and causes.name(refusal["code"]) == refusal["cause"], refusal


def test_the_second_tier_and_table_legs(run):
    """The JavaScript and Go kernels decide the core as the oracle does: they read canon/2, check the policy
    in the core's order and route every reading (no refusing kernel and no reader gap is left). D6: the C
    table targets and the eBPF evaluator (on its userspace path) route every compiled policy's readings as
    the oracle does, and the compiler's 32 bit limit and the eBPF loader's declared subset show only as
    refusals (target-limit), never as a different route."""
    legs, _lean, counts, _findings = run
    for leg in ("js", "go"):
        if leg in legs:
            assert counts[leg]["agree"] > CASES, counts[leg]
            assert not [key for key in counts[leg] if key.startswith(("finding", "refusing-kernel", "reader-gap"))], counts[leg]
    for leg in ("c-interp", "c-hdr", "ebpf"):
        if leg in legs:
            assert counts[leg]["target-limit:compile"] > 0 and counts[leg]["target-limit:reading"] > 0, counts[leg]
            assert not [key for key in counts[leg] if key.startswith("finding")], counts[leg]
            assert counts[leg]["agree"] > CASES, counts[leg]


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
        {"verdict": "refuse", "cause": "reading:unreadable", "code": 99, "reason": "float"},
        {"verdict": "refuse", "cause": "route:contract-violation", "code": 37, "field": "error_rate", "reason": "missing"},
        {"verdict": "refuse", "cause": "reading:not-object", "code": 100},
    ]


# D7 (spec section 4 and 9): policies with several problems, each refused for the first in the order of
# section 4, with the cause the oracle proves (`Core.loadPolicy_first_problem`) and every leg names.
D7_IMAGES = [
    ({"x": "int"}, [["and", ["cmp", "x", "==", ["num", "9007199254740992"]], ["cmp", "x", "==", ["num", "2.5"]]]],
     "policy:threshold"),
    ({"x": "int min=5 max=4", "y": "int"}, [["cmp", "x", "==", ["field", "y"]]], "image:unknown-type"),
    ({"x": "int", "k": "category"}, [["cmp", "x", "==", ["num", "2.5"]], ["cmp", "k", "<", ["str", "a"]]],
     "image:unknown-op"),
    ({"x": "int", "d": "fixed scale=100 rounding=floor"},
     [["and", ["cmp", "x", "==", ["bool", True]], ["cmp", "d", ">=", ["num", "0.001"]]]], "policy:kind-mismatch"),
    ({"d": "fixed scale=100 rounding=floor min=0 max=100"}, [["in", "d", [["num", 5]]]], "policy:threshold"),
    ({"b": "int min=5 max=4", "a": "float"}, [["cmp", "a", ">", ["num", 1]]], "policy:definition"),
    ({"c": "category absent=allowed", "x": "int"}, [["cmp", "x", "==", ["str", "s"]]], "policy:kind-mismatch"),
    ({"x": "int"}, [["or", ["cmp", "ghost", "==", ["num", 1]], ["cmp", "x", "<", ["str", "a"]]]], "image:unknown-op"),
]


def test_d7_one_cause_per_refused_policy():
    legs = _legs()
    import json
    cases = []
    for index, (fields, conds, _cause) in enumerate(D7_IMAGES):
        image = {"format": "prismpath.core/1", "fields": fields,
                 "rules": [{"target": "hit", "when": cond} for cond in conds] + [{"target": "miss", "when": ["always"]}]}
        for seed in range(8):
            cases.append({"id": f"d7-{index}-{seed}", "image": json.dumps(image).encode(), "readings": [b"{}"],
                          "render_seed": seed})
    lean, results, counts, findings = core_diff.run(cases, legs)
    for case in cases:
        expected = D7_IMAGES[int(case["id"].split("-")[1])][2]
        assert lean[case["id"]]["policy"]["cause"] == expected, (case["id"], lean[case["id"]]["policy"])
    assert not findings, findings[:3]
    for leg in legs:
        if leg in core_diff.CODED:
            for case in cases:
                assert results[leg][case["id"]]["cause"] == lean[case["id"]]["policy"]["cause"], (leg, case["id"])
