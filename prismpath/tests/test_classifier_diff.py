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
    assert result["kinds"] == {"hook": 174, "call": 54}
    assert result["disagreements"] == {}


def test_generated_calls_agree(oracle):
    result = classifier_diff.run(classifier_diff.generated_cases(CASES, SEED))
    assert result["cases"] == CASES and result["disagreements"] == {}
    assert result["nonscalar"] > 0                       # the transport's domain edge was met
    kinds = {key[0] for key in result["readings"]}
    assert {"run_command", "git", "read_file", "write_file", "list_dir", "delete_path", "unknown"} <= kinds


def test_policies_fit_every_reading(oracle):
    assert classifier_diff.check_policies() == []


# ------------------------------------------------------------------------------ state across calls (the `session` starter)
SESSION_IMAGE = classifier_diff.SESSION_POLICIES[0][0]
SESSION_BASE = classifier_diff.SESSION_POLICIES[0][1]


def test_session_images_are_kept_out_of_the_stateless_checks():
    assert SESSION_IMAGE.name == "agent_session.core.json" and SESSION_IMAGE not in classifier_diff.POLICIES
    assert len(classifier_diff.POLICIES) == 3


def test_the_session_starter_only_adds_restriction_in_every_state(oracle):
    """Over every reading and every state: at least as restrictive as the default starter, at most as restrictive as its
    own top state, and never a contract violation (Session.session_restricts); so the default's safety theorems hold in
    every state. It enumerates the whole reading space, which takes about two minutes."""
    assert classifier_diff.check_session() == []


def test_a_state_that_relaxes_a_decision_is_named_by_the_oracle(oracle, tmp_path):
    from prismpath.kernel import canon2
    doc = canon2.loads(SESSION_IMAGE.read_bytes().rstrip(b"\n"))
    doc["rules"].insert(0, {"target": "allow", "when": ["cmp", "session_shell_runs", "==", ["str", "many"]]})
    relaxed = tmp_path / "relaxed.core.json"
    relaxed.write_bytes(canon2.dumps(doc) + b"\n")
    assert len(classifier_diff.check_session([(relaxed, SESSION_BASE)])) == 1
    doc = canon2.loads(SESSION_IMAGE.read_bytes().rstrip(b"\n"))
    doc["rules"].insert(0, {"target": "refuse_104", "when": ["cmp", "session_protected_changes", "==", ["str", "none"]]})
    stricter_when_fresh = tmp_path / "fresh.core.json"        # a state that relaxes by being refused only when nothing happened
    stricter_when_fresh.write_bytes(canon2.dumps(doc) + b"\n")
    assert len(classifier_diff.check_session([(stricter_when_fresh, SESSION_BASE)])) == 1


def test_the_session_starter_decides_alike_in_python_and_lean_in_every_state(oracle):
    """The reference decision path and the Lean core, on the classifier's own readings with each of the six states."""
    sys.path.insert(0, str(ROOT / "formal" / "diff"))
    import core_diff
    from prismpath.agent import session_state
    from prismpath.agent.policy import Policy
    if not core_diff.ORACLE.exists():
        if os.environ.get("PRISMPATH_REQUIRE_CORE_ORACLE"):
            pytest.fail(f"PRISMPATH_REQUIRE_CORE_ORACLE is set and {core_diff.ORACLE} is not built")
        pytest.skip("the core oracle is not built (cd formal && lake build)")
    policy = Policy.load(SESSION_IMAGE)
    readings, seen = [], set()
    for case in classifier_diff.generated_cases(6000, SEED):
        case.run_python()
        base = case.python["reading"]
        for changes in session_state.CHANGES_VALUES:
            for shell in session_state.SHELL_VALUES:
                raw = policy.reading_bytes({**base, session_state.CHANGES: changes, session_state.SHELL: shell})
                if raw not in seen:
                    seen.add(raw)
                    readings.append(raw)
    assert len(readings) > 3000
    rows = core_diff.lean_leg([{"id": "x", "image": policy.image, "readings": readings}])["x"]["readings"]
    causes = {}
    for raw, row in zip(readings, rows):
        verdict = policy.verdict(raw)
        assert (row["verdict"], row.get("target")) == (verdict["verdict"], verdict.get("target")), raw
        if verdict["verdict"] == "route":
            causes[verdict["target"]] = causes.get(verdict["target"], 0) + 1
    assert causes.get("escalate_133", 0) > 0 and causes.get("escalate_134", 0) > 0     # both state rules were exercised
