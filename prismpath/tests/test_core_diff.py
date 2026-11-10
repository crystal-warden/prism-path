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

# The disagreements of spec section 9 that step 1 recorded, D1 (the reference did not apply the depth
# bound to a defined flow), D2 (Rust bounded depth by its own measure) and D3 (Rust did not split a
# definition on U+001F), are fixed in step 2: none is known any more, so each would fail this test.
KNOWN = set()
# D7: on a policy with several problems both sides refuse, each with a registered cause, but the leg's
# own phases name another problem first than the specification's order (section 4). Any pair of causes.
KNOWN_PREFIXES = ("policy-cause ",)


def _legs():
    if not core_diff.ORACLE.exists():
        if os.environ.get("PRISMPATH_REQUIRE_CORE_ORACLE"):
            pytest.fail(f"PRISMPATH_REQUIRE_CORE_ORACLE is set and {core_diff.ORACLE} is not built")
        pytest.skip("the Lean oracle is not built (cd formal && lake build)")
    legs = ["python"]
    if core_diff.rust_binary().exists() or shutil.which("cargo"):
        legs.append("rust")
    for leg, tool in (("js", "node"), ("go", "go"), ("c-interp", "cc"), ("c-hdr", "cc")):
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
        # the second tier kernels agree only where no field is defined (D5), so their bar is lower
        assert counts[leg]["agree"] > (CASES if leg in core_diff.CODED else CASES // 2), counts[leg]


def test_no_reading_disagrees_and_nothing_crashes(run):
    legs, _lean, counts, _findings = run
    for leg in legs:
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
    """D5: the JavaScript and Go kernels refuse every flow that defines its fields and agree elsewhere,
    differing only by reader gaps (they have no canon/2 reader). D6: the C table targets route every
    compiled policy's readings as the oracle does, and the compiler's 32 bit limit shows only as a
    refusal (target-limit), never as a different route."""
    legs, _lean, counts, _findings = run
    for leg in ("js", "go"):
        if leg in legs:
            assert counts[leg]["refusing-kernel"] > 0 and counts[leg]["agree"] > 0, counts[leg]
            assert not [key for key in counts[leg] if key.startswith("finding")], counts[leg]
    for leg in ("c-interp", "c-hdr"):
        if leg in legs:
            assert counts[leg]["target-limit:compile"] > 0 and counts[leg]["target-limit:reading"] > 0, counts[leg]
            assert not [key for key in counts[leg] if key.startswith("finding") and key != "finding:cause"], counts[leg]


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
