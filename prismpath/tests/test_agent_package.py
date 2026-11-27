# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The governed agent core ships in the wheel: a decision, a signed run and its verification through the
reference kernel, with nothing from the research tree."""
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from prismpath.agent import classifier, evidence, policy  # noqa: E402


def test_policy_files_sit_beside_the_package_and_agree():
    from prismpath.kernel import canon2
    image = policy.POLICY_PATH.read_bytes()
    assert policy.SOURCE_PATH.parent == policy.POLICY_PATH.parent == Path(policy.__file__).parent / "policy"
    from prismpath.kernel import policy_source
    assert policy_source.compile_source(policy.SOURCE_PATH.read_text(encoding="utf-8")) + b"\n" == image
    assert canon2.canonicalize(image) == image.rstrip(b"\n")


def test_the_core_modules_need_no_research_path():
    for name in ("prismpath.agent.classifier", "prismpath.agent.policy", "prismpath.agent.evidence"):
        assert name in sys.modules
    for module in (classifier, policy, evidence):
        assert "sys.path" not in Path(module.__file__).read_text()


def test_a_signed_run_verifies_through_the_reference_kernel(tmp_path):
    pol = policy.Policy.load()
    reading = classifier.classify({"tool": "list_dir", "args": {"path": "."}}, classifier.Config.for_workspace(tmp_path))
    raw = pol.reading_bytes(reading)
    decision = pol.decide(raw)
    keys = tmp_path / "keys"
    run = evidence.EpisodeRun(tmp_path / "run", "e1", pol.image, keys)
    run.record(raw, decision.verdict)
    run.close()
    summary = evidence.verify(tmp_path / "run", keys)
    assert summary["replayed"] == 1 and summary["disagree"] == 0 and summary["against"] == "the reference kernel"
    assert evidence.replay(tmp_path / "run", keys)
