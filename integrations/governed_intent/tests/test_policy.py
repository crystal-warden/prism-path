# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The two intent images: current, accepted by the Lean port, the floor's rules verbatim, every target a
registered cause, and union-only on a random sample of the whole field space (the exhaustive check is
union_check.py; set PRISMPATH_INTENT_FULL=1 to run it here)."""
import json
import os
import random
from pathlib import Path

import pytest

from integrations.governed_harness import owner_rules as harness_rules
from integrations.governed_harness import policy as harness_policy
from integrations.governed_intent import intent_reader as ir
from integrations.governed_intent import owner_rules, policy, union_check
from prismpath.kernel import canon2, causes


@pytest.fixture(scope="module")
def images():
    return policy.load_calls(), policy.load_responses()


def test_the_images_are_current_and_canonical():
    for path, raw in policy.images().items():
        assert path.read_bytes() == raw, f"{path.name} is stale: python -m integrations.governed_intent.policy"
    for path in (policy.CALLS_CORE, policy.RESPONSES_CORE):
        image = path.read_bytes()[:-1]
        assert canon2.dumps(canon2.loads(image)) == image


def test_the_floor_is_copied_verbatim(images):
    calls, _responses = images
    floor = json.loads(harness_policy.SOURCE_PATH.read_text())
    rules = calls.doc["rules"]
    floor_rules = canon2.loads(canon2.canonicalize(json.dumps(floor).encode()))["rules"]
    assert rules[:10] == floor_rules[:10] and rules[15:] == floor_rules[10:]
    assert all(calls.doc["fields"][name] == definition
               for name, definition in canon2.loads(canon2.canonicalize(json.dumps(floor).encode()))["fields"].items())


def test_every_target_names_a_registered_cause(images):
    import core_policy
    for image in images:
        assert core_policy.load_policy(image.image) is None
        for rule in image.doc["rules"]:
            kind, cause, code = policy.target_decision(rule["target"])
            if kind != "allow":
                assert causes.code(cause) == code and causes.cause_class(code) == "routing"
    assert causes.name(114) == owner_rules.HARM and causes.name(115) == owner_rules.MISMATCH
    allows = [rule for image in images for rule in image.doc["rules"] if rule["target"] == "allow"]
    for rule in allows:          # no allow reads a semantic field: the semantic signal never grants
        read = {atom[1] for atom in union_check.atoms(rule["when"])}
        assert not read & {"harm_bp", "intent_class", "intent_margin_bp", "semantic_status", "semantic_lock",
                           "probing_count"}


def test_the_atoms_on_the_class_fields_are_only_the_thresholds(images):
    thresholds = policy.load_thresholds()
    union_check.audit(images[0].doc, thresholds["harm_threshold"], thresholds["intent_margin_bp"], policy.lock_id(),
                      probing_n=thresholds["probing_count_escalate"])


def _random_reading(rng, lock, thresholds):
    floor = {"classifier_version": 1, **{name: rng.choice(values) for name, values in union_check.ENUMS.items()},
             **{name: rng.random() < 0.5 for name in union_check.BOOLS}}
    harm = rng.choice([0, rng.randrange(0, 10001), thresholds["harm_bp"] - 1, thresholds["harm_bp"], 10000])
    margin = rng.choice([0, rng.randrange(0, 10001), thresholds["intent_margin_bp"] - 1,
                         thresholds["intent_margin_bp"], 10000])
    return {**floor, "intent_reader_version": ir.READER_VERSION, "semantic_status": rng.choice([ir.VERIFIED, ir.DISABLED]),
            "semantic_lock": rng.choice([lock, lock, "none", "f" * 64]), "harm_bp": harm,
            "intent_class": rng.choice(union_check.INTENTS), "intent_margin_bp": margin,
            "probing_count": rng.choice([0, 1, thresholds["probing_count_escalate"], rng.randrange(0, 1001)])}


def test_union_only_on_a_random_sample_of_the_field_space(images):
    calls, _responses = images
    thresholds, lock = policy.load_thresholds(), policy.lock_id()
    rng = random.Random(20261114)
    seen = {}
    for _ in range(20000):
        reading = _random_reading(rng, lock, thresholds)
        decision = calls.decide(calls.reading_bytes(reading))
        floor = calls.decide(calls.reading_bytes(policy.zeroed(reading)))
        decided, floored = (decision.kind, decision.cause), (floor.kind, floor.cause)
        assert floored == harness_rules.expected({key: reading[key] for key in policy.FLOOR_FIELDS})
        assert owner_rules.at_least_as_strict(decided, floored), reading
        assert decided == owner_rules.expected_call(reading, thresholds["harm_bp"], thresholds["intent_margin_bp"], lock,
                                                    thresholds["probing_count_escalate"])
        unprobed = calls.decide(calls.reading_bytes({**reading, "probing_count": 0}))
        assert owner_rules.RANK[decided[0]] >= owner_rules.RANK[unprobed.kind]   # the count only ever adds
        seen[f"{floored[0]}->{decided[0]}"] = seen.get(f"{floored[0]}->{decided[0]}", 0) + 1
    assert seen.get("allow->refuse") and seen.get("allow->escalate") and not seen.get("refuse->allow")


def test_a_disabled_or_foreign_reading_is_the_floor(images):
    calls, responses = images
    lock = policy.lock_id()
    reading = {"classifier_version": 1, "tool": "delete_path", "path_scope": "workspace", "path_in_toolchain": False,
               "path_control": False, "path_glob": False, "path_traversal": False, "path_symlink": False, "command_class": "none",
               "kill_by_pattern": False, "git_op": "none", "remote_class": "none", "intent_reader_version": ir.READER_VERSION,
               "semantic_status": ir.VERIFIED, "semantic_lock": lock, "harm_bp": 9000, "intent_class": "inspect",
               "intent_margin_bp": 9000, "probing_count": 0}
    assert calls.decide(calls.reading_bytes(reading)).cause == "semantic:harm"
    for change in ({"semantic_status": ir.DISABLED}, {"semantic_lock": "none"}, {"semantic_lock": "0" * 64}):
        assert calls.decide(calls.reading_bytes({**reading, **change})).kind == "allow"
    reading["harm_bp"] = 0
    assert calls.decide(calls.reading_bytes(reading)).cause == "semantic:intent-mismatch"
    assert calls.decide(calls.reading_bytes({**reading, "probing_count": 2})).cause == "semantic:probing-episode"
    assert calls.decide(calls.reading_bytes({**reading, "probing_count": 2, "semantic_status": ir.DISABLED})).kind == "allow"
    assert calls.decide(calls.reading_bytes({**reading, "intent_class": "unknown"})).kind == "allow"
    answer = {"intent_reader_version": ir.READER_VERSION, "semantic_status": ir.VERIFIED, "semantic_lock": lock, "harm_bp": 9000}
    assert responses.decide(responses.reading_bytes(answer)).cause == "semantic:harm"
    assert responses.decide(responses.reading_bytes({**answer, "semantic_status": ir.DISABLED})).kind == "allow"


@pytest.mark.parametrize("change,cause", [
    ({"harm_bp": 10001}, "route:contract-violation"), ({"harm_bp": -1}, "route:contract-violation"),
    ({"intent_margin_bp": 10001}, "route:contract-violation"), ({"intent_reader_version": 1}, "route:contract-violation"),
    ({"intent_reader_version": 3}, "route:contract-violation"),
    ({"harm_bp": True}, "route:contract-violation"),
])
def test_a_semantic_field_out_of_its_definition_is_refused(images, change, cause):
    calls, _responses = images
    reading = {"classifier_version": 1, "tool": "list_dir", "path_scope": "workspace", "path_in_toolchain": False,
               "path_control": False, "path_glob": False, "path_traversal": False, "path_symlink": False, "command_class": "none",
               "kill_by_pattern": False, "git_op": "none", "remote_class": "none", **ir.zero_fields(), **change}
    assert calls.decide(canon2.dumps(reading)).cause == cause


def test_a_float_harm_value_is_unreadable(images):
    calls, _responses = images
    reading = {"classifier_version": 1, "tool": "list_dir", "path_scope": "workspace", "path_in_toolchain": False,
               "path_control": False, "path_glob": False, "path_traversal": False, "path_symlink": False, "command_class": "none",
               "kill_by_pattern": False, "git_op": "none", "remote_class": "none", **ir.zero_fields()}
    raw = canon2.dumps(reading).replace(b'"harm_bp":0', b'"harm_bp":0.5')
    assert calls.decide(raw).kind == "refuse"


@pytest.mark.skipif(os.environ.get("PRISMPATH_INTENT_FULL") != "1", reason="the exhaustive check takes minutes")
def test_union_only_exhaustively(tmp_path):
    oracle = union_check.oracle_path()
    if not Path(oracle).exists():
        pytest.skip("the Lean oracle is not built")
    assert union_check.run(tmp_path, workers=int(os.environ.get("PRISMPATH_INTENT_WORKERS", "8")))["passed"]
