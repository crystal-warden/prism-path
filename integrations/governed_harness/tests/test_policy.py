# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The agent policy: a checked core image in its canonical bytes, every target naming a registered cause,
and on EVERY reading of its field space the decision the owner's rules give (owner_rules.py), by the
Python reference and, when it is built, by the Lean oracle."""
import itertools
import json
import os
import subprocess
from pathlib import Path

import pytest

from integrations.governed_harness import classifier, owner_rules, policy
from prismpath.kernel import canon2, causes

ENUMS = {"tool": ["list_dir", "read_file", "write_file", "delete_path", "run_command", "git", "unknown"],
         "path_scope": ["none", "workspace", "outside", "unknown"],
         "command_class": ["none", "read_only", "mutating", "network", "git", "unknown"],
         "git_op": ["none", "local_read", "local_write", "mutating", "push", "network", "unknown"],
         "remote_class": ["none", "allowed", "other"]}
BOOLS = ["path_in_toolchain", "path_glob", "path_traversal", "path_symlink", "kill_by_pattern"]


def field_space():
    names = list(ENUMS) + BOOLS
    for values in itertools.product(*ENUMS.values(), *([[False, True]] * len(BOOLS))):
        yield {"classifier_version": classifier.CLASSIFIER_VERSION, **dict(zip(names, values))}


@pytest.fixture(scope="module")
def agent_policy():
    return policy.Policy.load()


def test_the_image_is_its_canonical_bytes_and_the_source_canonicalizes_to_it():
    image = policy.POLICY_PATH.read_bytes()
    assert image.endswith(b"\n") and canon2.dumps(canon2.loads(image[:-1])) == image[:-1]
    assert canon2.canonicalize(policy.SOURCE_PATH.read_bytes()) + b"\n" == image


def test_the_lean_port_accepts_the_image_and_every_target_names_a_registered_cause(agent_policy):
    import core_policy
    assert core_policy.load_policy(agent_policy.image) is None
    seen = set()
    for rule in agent_policy.doc["rules"]:
        kind, cause, code = policy.target_decision(rule["target"])
        if kind != "allow":
            assert causes.code(cause) == code and causes.cause_class(code) == "routing"
            seen.add(cause)
    assert seen == {name for code, name, _k, _d in causes._REGISTRY if 104 <= code <= 113}


def test_the_reading_fields_are_the_policy_fields(agent_policy):
    assert sorted(classifier.base_reading()) == agent_policy.fields


def test_an_unknown_target_or_cause_is_no_decision():
    assert policy.target_decision("refuse_250") is None
    assert policy.target_decision("run") is None
    assert policy.target_decision("refuse_108") == ("refuse", "agent:glob-path", 108)
    assert policy.target_decision("escalate_113") == ("escalate", "agent:push-escalated", 113)


def _want(reading):
    kind, cause = owner_rules.expected(reading)
    return kind, cause


def test_every_reading_decides_as_the_owner_rules_say(agent_policy):
    """The whole field space, 112,896 readings, through the reference: the image and the rules agree."""
    disagree, count = [], 0
    for reading in field_space():
        count += 1
        decision = agent_policy.decide(agent_policy.reading_bytes(reading))
        if (decision.kind, decision.cause) != _want(reading):
            disagree.append((reading, decision))
    assert count == 7 * 4 * 6 * 7 * 3 * 2 ** 5
    assert disagree == []


def _oracle():
    path = os.environ.get("PRISMPATH_CORE_ORACLE") or str(policy.REPO / "formal" / ".lake" / "build" / "bin" / "core-oracle")
    if not Path(path).exists():
        pytest.skip("the Lean oracle is not built (cd formal && lake build core-oracle)")
    return path


def test_the_lean_oracle_decides_every_reading_as_the_reference(agent_policy):
    oracle = _oracle()
    readings = [agent_policy.reading_bytes(reading) for reading in field_space()]
    image = agent_policy.image
    data = bytearray(f"case all {len(readings)}\n{len(image)}\n".encode() + image + b"\n")
    for raw in readings:
        data += f"{len(raw)}\n".encode() + raw + b"\n"
    out = subprocess.run([oracle, "--batch"], input=bytes(data), capture_output=True, check=True).stdout
    row = json.loads(out.decode())     # the oracle's own output, not a hashed document
    assert row["policy"] == {"policy": "accepted"}
    for raw, lean in zip(readings, row["readings"]):
        mine = agent_policy.verdict(raw)
        assert (lean["verdict"], lean.get("target"), lean.get("cause")) == \
            (mine["verdict"], mine.get("target"), mine.get("cause"))


@pytest.mark.parametrize("change,cause", [
    ({"classifier_version": 2}, "route:contract-violation"),
    ({"path_glob": 1}, "route:contract-violation"),
    ({"tool": None}, "route:contract-violation"),
])
def test_a_reading_the_boundary_refuses_never_runs(agent_policy, change, cause):
    reading = {**classifier.base_reading(), "tool": "list_dir", "path_scope": "workspace", **change}
    decision = agent_policy.decide(canon2.dumps(reading))
    assert (decision.kind, decision.cause) == ("refuse", cause) and not decision.runs


def test_a_missing_field_is_refused_and_an_undefined_one_changes_nothing(agent_policy):
    reading = {**classifier.base_reading(), "tool": "list_dir", "path_scope": "workspace"}
    del reading["path_glob"]
    assert agent_policy.decide(canon2.dumps(reading)).cause == "route:contract-violation"
    extra = {**classifier.base_reading(), "tool": "list_dir", "path_scope": "workspace", "trust_me": True}
    assert agent_policy.decide(canon2.dumps(extra)).kind == "allow"


def test_a_reading_not_in_its_canonical_bytes_or_with_a_float_is_refused(agent_policy):
    reading = {**classifier.base_reading(), "tool": "list_dir", "path_scope": "workspace"}
    spaced = canon2.dumps(reading).replace(b",", b", ")
    assert agent_policy.decide(spaced).cause == "reading:not-canonical"
    floated = canon2.dumps(reading).replace(b'"classifier_version":1', b'"classifier_version":1.0')
    assert agent_policy.decide(floated).cause == "reading:unreadable"
    assert agent_policy.decide(b"[1]").cause == "reading:not-object"


def test_what_no_rule_allows_is_refused_by_the_core(agent_policy):
    reading = {**classifier.base_reading(), "tool": "run_command", "command_class": "none"}
    decision = agent_policy.decide(canon2.dumps(reading))
    assert (decision.kind, decision.cause, decision.cause_code) == ("refuse", "route:no-matching-edge", 32)
