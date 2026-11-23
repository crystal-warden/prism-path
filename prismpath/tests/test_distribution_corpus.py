# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The policy distribution corpus (portable/conformance/distribution.json, spec-policy-distribution.md I1) is
what the Python verifier decides, frozen. This is Python's replay of it: every case is run again and must
give the recorded result, and regenerating the corpus from the live reference must reproduce the committed
file byte for byte. If a change is intended, run portable/gen_distribution_corpus.py and review the diff.
Rust and the C core replay the same file."""
import importlib.util
import json
from pathlib import Path

import pytest

from prismpath.tests._repo import repo_file

pytest.importorskip("cryptography")

REPO = Path(__file__).resolve().parent.parent
CORPUS_PATH = REPO / "portable" / "conformance" / "distribution.json"


def _generator():
    spec = importlib.util.spec_from_file_location("gen_distribution_corpus",
                                                  REPO / "portable" / "gen_distribution_corpus.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GEN = _generator()
CORPUS = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", CORPUS["cases"], ids=[case["name"] for case in CORPUS["cases"]])
def test_every_python_case_replays_to_its_recorded_result(case):
    if "P" not in case["runs_on"]:
        pytest.skip(f"{case['name']} does not run in Python")
    assert GEN.replay(case) == case["expect"]


@pytest.mark.parametrize("entry", CORPUS["frames"], ids=[entry["name"] for entry in CORPUS["frames"]])
def test_every_frame_case_replays_to_its_recorded_events(entry):
    """The frame binding's cases (B6, B7, B9, B10), which the C core replays on a mesh node as well."""
    assert "P" in entry["runs_on"] and entry["pep"]["kind"] == "mesh"
    assert GEN.replay_frames(entry) == entry["expect"]


@pytest.mark.parametrize("entry", CORPUS["widening"], ids=[entry["name"] for entry in CORPUS["widening"]])
def test_every_widening_case_replays_to_its_recorded_cause(entry):
    """V12 and W2 to W4 on a PEP that cannot decide, which Rust replays on a host and the C core on a mesh node."""
    assert GEN.replay_widening(entry) == entry["expect"]


def test_the_committed_corpus_is_what_the_reference_writes_and_it_is_byte_stable():
    repo_file("docs", "design", "spec-policy-distribution.md")       # the generator reads each case's row
    first, second = GEN.build(), GEN.build()
    rendered = json.dumps(first, indent=1, sort_keys=True) + "\n"
    assert rendered == json.dumps(second, indent=1, sort_keys=True) + "\n"
    assert rendered == CORPUS_PATH.read_text(encoding="utf-8"), (
        "distribution.json no longer matches the Python verifier; if the change is intended, run "
        "portable/gen_distribution_corpus.py and commit the diff")


def test_every_case_names_its_inputs_and_one_result():
    names = [case["name"] for case in CORPUS["cases"]]
    assert len(names) == len(set(names))
    for case in CORPUS["cases"]:
        assert set(case) == {"case", "name", "runs_on", "trust", "pep", "now", "sealed", "body", "expect"}
        assert set(case["expect"]) == {"cause", "unchanged", "time_floor", "envelope_id"}
    for vector in CORPUS["release_ids"]:
        assert set(vector) == {"case", "name", "runs_on", "artifacts", "release"}
    for entry in CORPUS["widening"]:
        assert set(entry) == {"case", "name", "runs_on", "kind", "active_policy", "active_table", "table", "sealed",
                              "statement", "expect"}
    for entry in CORPUS["frames"]:
        assert set(entry) == {"case", "name", "runs_on", "trust", "pep", "now", "limit", "ordered", "steps", "expect"}
        assert {entry["case"] for entry in CORPUS["frames"]} == {35, 36, 37, 120, 121}
        assert all(set(step) == {"at", "frame"} for step in entry["steps"])
