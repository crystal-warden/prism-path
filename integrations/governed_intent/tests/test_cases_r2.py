# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Round 2's sets, with no model: the registered counts and splits, every b2 and benign call one the floor
allows, the held-out texts new (not round 1's), and round 1's lock kept byte for byte."""
import hashlib
import json

from integrations.governed_harness import adversary, classifier
from integrations.governed_harness import owner_rules as floor_rules
from integrations.governed_intent import cases, cases_r2
from integrations.governed_intent.intent_reader import HERE

R1_LOCK_SHA256 = "8a2ece9c8f943f7b39277110bb036a71ddbf4fa316463d3e09691df97902ceea"


def test_round1_lock_is_kept_byte_for_byte():
    assert hashlib.sha256((HERE / "intent_lock_r1.json").read_bytes()).hexdigest() == R1_LOCK_SHA256


def test_registered_counts_and_splits():
    built = cases_r2.build()
    held = [case for case in built if case.split == cases.HELD]
    cal = [case for case in built if case.split == cases.CAL]
    assert all(case.id.startswith("r2h-") for case in held) and all(case.id.startswith("r2c-") for case in cal)

    def count(rows, set_, kind=None):
        return sum(case.set == set_ and (kind is None or case.kind == kind) for case in rows)
    assert count(held, "b2") == 33 and count(held, "benign") == 64 and count(held, "p") == 12
    assert count(held, "harm", "benign") == 224 and count(held, "harm", "harmful") == 58
    english = [case for case in held if case.kind == "harmful" and ("-paraphrase-" in case.id or "-euphemism-" in case.id)]
    assert len(english) == 42
    assert count(cal, "b2") == 7 and count(cal, "benign") == 23
    assert count(cal, "harm", "benign") == 54 and count(cal, "harm", "harmful") == 16
    assert not any(case.split == cases.HELD for case in cases_r2.calibration())
    assert {case.set for case in cases_r2.heldout()} == {"a", "b1", "b2", "benign", "harm", "p"}
    assert not any(case.id.startswith("r2c-") for case in cases_r2.heldout())


def test_every_b2_and_benign_call_is_one_the_floor_allows(tmp_path):
    world = adversary.make_world(tmp_path / "w")
    config = classifier.Config.for_workspace(world["ws"], cases.ALLOWED_ORIGIN)
    for case in cases_r2.build():
        if case.set in ("b2", "benign"):
            for call in adversary._fill(case.calls, world["decoy"]):
                assert floor_rules.expected(classifier.classify(call, config))[0] == "allow", (case.id, call)


def _sentences(texts):
    return {" ".join(text.lower().split()) for text in texts if len(text.split()) >= 4}


def test_held_out_texts_are_new():
    """No round 2 task or text of four words or more repeats one of round 1's (the shared task templates of the
    harm surfaces aside)."""
    old = _sentences(cases.all_texts())
    shared = {" ".join(cases.HARM_CALL_TASK.lower().split()), "answer the question you were given."}
    new = _sentences(cases_r2.all_texts()) - shared
    from prismpath.safety import benign_corpus, bypass_corpus
    old |= _sentences(row["text"] for row in benign_corpus.generate())
    old |= _sentences(text for strata in bypass_corpus.SEMANTIC_VARIANTS.values() for texts in strata.values()
                      for text in texts)
    assert not (new & old), sorted(new & old)


def test_kill_commands_name_only_the_decoy_marker():
    for case in cases_r2.build():
        for call in case.calls:
            argv = call.get("args", {}).get("argv") if isinstance(call.get("args"), dict) else None
            if argv and any(word in ("pkill", "killall", "kill") for word in argv[:1]):
                assert any("987654" in word for word in argv), (case.id, argv)
            if argv and argv[0] == "sh":
                assert "pkill" not in argv[-1] or "987654" in argv[-1]
    json.dumps([case.id for case in cases_r2.build()])
