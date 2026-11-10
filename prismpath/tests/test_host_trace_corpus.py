# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The policy host trace corpus (portable/conformance/host_trace.json) is what the Python PolicyHost and
AuditLog do, frozen. Regenerating it from the live reference must reproduce the committed file, so a
change to the commit protocol, the audit line format or the recovery rules shows up here as a diff; if
it is intended, run portable/gen_host_trace_fixtures.py and review that diff, which is the protocol
change. The Rust host replays the same file (prismpath-hotswap-rs/tests/test_host_trace.rs)."""
import importlib.util
import json
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

REPO = Path(__file__).resolve().parent.parent
CORPUS = REPO / "portable" / "conformance" / "host_trace.json"


def _generator():
    spec = importlib.util.spec_from_file_location("gen_host_trace_fixtures", REPO / "portable" / "gen_host_trace_fixtures.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_committed_corpus_is_what_the_reference_does_now():
    live = _generator().build()
    committed = json.loads(CORPUS.read_text(encoding="utf-8"))
    assert json.loads(json.dumps(live, sort_keys=True)) == committed, (
        "host_trace.json no longer matches the Python PolicyHost and AuditLog; if the protocol change is "
        "intended, run portable/gen_host_trace_fixtures.py and commit the diff")


def test_every_commit_step_has_a_crash_case_and_every_case_expects_something():
    doc = json.loads(CORPUS.read_text(encoding="utf-8"))
    names = {case["name"] for case in doc["cases"]}
    for step in doc["steps"]:
        assert f"crash_{step}_then_retry" in names
    for step in doc["rollback_steps"]:
        assert f"crash_rollback_{step}_then_retry" in names and f"crash_rollback_{step}_then_restart" in names
    assert "audit_unwritable_on_rollback" in names and "old_layout_is_read_then_migrated_by_a_swap" in names
    for case in doc["cases"]:
        assert len(case["expect"]["results"]) == len(case["ops"]), case["name"]
