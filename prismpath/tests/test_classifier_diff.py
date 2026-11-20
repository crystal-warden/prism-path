# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The classifier's differential harness, at CI size (docs/design/spec-verified-classifier.md).

A seeded run of `formal/diff/classifier_diff.py`: the recorded Claude Code hook inputs and the governed harness's
adversary probes on a real throwaway disk, and generated calls on a synthetic disk, each through the Python
classifier and mappings and through the Lean oracle. Every case must agree, and every shipped agent policy's field
definitions must fit every reading. The full run is the documented command

    python formal/diff/classifier_diff.py --cases 20000 --seed 1

The oracle is built by `lake build` in formal/; without it the test skips, unless
PRISMPATH_REQUIRE_CLASSIFIER_ORACLE is set, when a missing oracle is a failure.
"""
import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if not (ROOT / "formal" / "diff" / "classifier_diff.py").exists():
    pytest.skip("formal/diff is not beside this package (an installed wheel)", allow_module_level=True)
sys.path.insert(0, str(ROOT / "formal" / "diff"))
import classifier_diff  # noqa: E402

CASES = 4000
SEED = 7


@pytest.fixture(scope="module")
def oracle():
    if not classifier_diff.ORACLE.exists():
        if os.environ.get("PRISMPATH_REQUIRE_CLASSIFIER_ORACLE"):
            pytest.fail(f"PRISMPATH_REQUIRE_CLASSIFIER_ORACLE is set and {classifier_diff.ORACLE} is not built")
        pytest.skip("the classifier oracle is not built (cd formal && lake build)")
    return classifier_diff.ORACLE


def test_recorded_inputs_agree(oracle):
    with tempfile.TemporaryDirectory() as tmp:
        cases = classifier_diff.recorded_cases(Path(tmp))
        result = classifier_diff.run(cases)
    assert result["kinds"] == {"hook": 154, "call": 54}
    assert result["disagreements"] == {}


def test_generated_calls_agree(oracle):
    result = classifier_diff.run(classifier_diff.generated_cases(CASES, SEED))
    assert result["cases"] == CASES and result["disagreements"] == {}
    assert result["nonscalar"] > 0                       # the transport's domain edge was met
    kinds = {key[0] for key in result["readings"]}
    assert {"run_command", "git", "read_file", "write_file", "list_dir", "delete_path", "unknown"} <= kinds


def test_policies_fit_every_reading(oracle):
    assert classifier_diff.check_policies() == []
