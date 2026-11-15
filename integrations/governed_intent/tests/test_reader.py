# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The intent reader with no model: integer fields by the stated rounding, deterministic, and fail to floor,
loudly, whenever the embedder, the lock or the P1 lockfile does not verify."""
import hashlib
import json
import math
import shutil
from pathlib import Path

import pytest

from integrations.governed_intent import cases, exemplars, intent_reader as ir

P1 = json.loads(ir.P1_LOCK_PATH.read_text())


def _unit(values):
    norm = math.sqrt(sum(value * value for value in values))
    return [value / norm for value in values]


def stub(texts):
    """The P1 fingerprint for the P1 probe, a deterministic unit vector for anything else."""
    out = []
    for text in texts:
        if text == P1["fingerprint_probe"]:
            out.append(list(P1["fingerprint"]))
            continue
        digest = hashlib.sha256(text.encode()).digest()
        out.append(_unit([(digest[at % 32] - 127.5) + at % 7 for at in range(384)]))
    return out


@pytest.fixture
def stub_lock(tmp_path):
    """The committed lock with its reference readings recomputed by the stub (so the stub verifies)."""
    lock = json.loads(ir.LOCK_PATH.read_text())
    reader = ir.IntentReader(embed=stub, loud=False)
    reader.lock = lock
    lock["reference_readings"] = [{**ref, **reader._measure(ref["text"], task=ref["kind"] == "task")}
                                  for ref in lock["reference_readings"]]
    path = tmp_path / "intent_lock.json"
    path.write_text(json.dumps(lock, indent=1, sort_keys=True) + "\n")
    return path


@pytest.mark.parametrize("cosine,want", [(-0.3, 0), (0.0, 0), (0.00009, 0), (0.0001, 1), (0.72999, 7299),
                                         (0.73, 7300), (0.999999, 9999), (1.0, 10000), (1.2, 10000),
                                         (float("nan"), 0), (float("inf"), 0)])
def test_bp_is_floor_of_basis_points_clamped(cosine, want):
    assert ir.bp(cosine) == want and isinstance(ir.bp(cosine), int)


def test_chunks_cover_every_word_and_overlap():
    words = [f"w{at}" for at in range(130)]
    got = ir.chunks(" ".join(words))
    assert all(len(chunk.split()) <= ir.CHUNK_WORDS for chunk in got)
    assert set(" ".join(got).split()) == set(words)
    assert ir.chunks("   ") == [] and ir.chunks("a  b\nc") == ["a b c"]


def test_the_call_strings_are_read_for_harm():
    call = {"tool": "write_file", "args": {"path": "x", "content": "some text"}}
    assert ir.harm_texts("reply", call) == ["reply", "some text", "x"]
    assert ir.harm_texts("r", {"tool": "run_command", "args": {"argv": ["echo", "a", "b"]}}) == ["r", "echo a b"]


def test_round2_reads_a_call_string_only_when_it_has_enough_words():
    call = {"tool": "list_dir", "args": {"path": "build"}}
    assert ir.harm_texts("reply", call, 2) == ["reply"]
    write = {"tool": "write_file", "args": {"path": "build/x.txt", "content": "two words"}}
    assert ir.harm_texts("r", write, 2) == ["r", "two words"]
    argv = {"tool": "run_command", "args": {"argv": ["stat", "build/out.o"]}}
    assert ir.harm_texts("r", argv, 2) == ["r", "stat build/out.o"] and ir.harm_texts("r", argv, 3) == ["r"]


def test_the_committed_lock_carries_the_chosen_fixes_and_round1_reads_as_round1():
    lock = json.loads(ir.LOCK_PATH.read_text())
    assert lock["fields"].get("arg_min_words", 0) == exemplars.FIXES["arg_min_words"]
    assert ("benign" in lock) == bool(exemplars.FIXES["benign_contrast"])
    r1 = json.loads((ir.HERE / "intent_lock_r1.json").read_text())
    assert "arg_min_words" not in r1["fields"] and "benign" not in r1
    reader = ir.IntentReader(embed=stub, lock_path=ir.HERE / "intent_lock_r1.json", loud=False)
    reader.lock = r1
    assert reader.arg_min_words == 0


def test_a_chunk_nearer_a_benign_centroid_adds_nothing():
    def unit(at):
        return [1.0 if index == at else 0.0 for index in range(4)]

    def embed(texts):
        return [{"harmish": _unit([0.9, 0.1, 0, 0]), "benignish": _unit([0.6, 0.8, 0, 0])}[text] for text in texts]
    reader = ir.IntentReader(embed=embed, loud=False)
    reader.lock = {"harm": {"centroids": {"h": unit(0)}}, "fields": {}}
    assert reader._harm_bp(["harmish"]) == ir.bp(_unit([0.9, 0.1, 0, 0])[0])
    assert reader._harm_bp(["benignish"]) == ir.bp(0.6)
    reader.lock["benign"] = {"centroids": {"b": unit(1)}}
    assert reader._harm_bp(["harmish"]) == ir.bp(_unit([0.9, 0.1, 0, 0])[0])
    assert reader._harm_bp(["benignish"]) == 0 and reader._harm_bp(["harmish", "benignish"]) > 0


def test_a_stub_that_reproduces_the_lock_verifies_and_reads_integers(stub_lock):
    reader = ir.IntentReader(embed=stub, lock_path=stub_lock, loud=False)
    assert reader.verify() == ir.VERIFIED, reader.reason
    fields = reader.read_call("Read notes.txt.", '{"tool": "read_file"}', {"tool": "read_file", "args": {"path": "notes.txt"}})
    assert set(fields) == set(ir.SEMANTIC_FIELDS)
    assert fields["semantic_status"] == ir.VERIFIED and fields["semantic_lock"] == hashlib.sha256(stub_lock.read_bytes()).hexdigest()
    for key in ("harm_bp", "intent_margin_bp", "intent_reader_version"):
        assert type(fields[key]) is int and 0 <= fields[key] <= ir.BP
    assert fields["intent_class"] in exemplars.INTENT_CLASSES
    assert fields == reader.read_call("Read notes.txt.", '{"tool": "read_file"}', {"tool": "read_file", "args": {"path": "notes.txt"}})


def test_no_embedder_is_the_floor(capsys):
    reader = ir.IntentReader(embed=None)
    assert reader.verify() == ir.DISABLED
    assert "SEMANTIC LAYER DISABLED" in capsys.readouterr().err
    fields = reader.read_call("Delete everything.", "{}", {"tool": "delete_path", "args": {"path": "x"}})
    assert {**fields, "semantic_lock": "none"} == ir.zero_fields()
    assert reader.read_response("text")["harm_bp"] == 0


def test_a_fingerprint_mismatch_disables(stub_lock, capsys):
    def drifted(texts):
        return [[value * -1 for value in vector] for vector in stub(texts)]
    reader = ir.IntentReader(embed=drifted, lock_path=stub_lock)
    assert reader.verify() == ir.DISABLED and "fingerprint" in reader.reason
    assert "DISABLED" in capsys.readouterr().err
    assert reader.read_call("t", "r", {"tool": "list_dir", "args": {}})["semantic_status"] == ir.DISABLED


def test_a_reference_reading_not_reproduced_disables(stub_lock):
    lock = json.loads(stub_lock.read_text())
    lock["reference_readings"][2]["intent_margin_bp"] += 2
    stub_lock.write_text(json.dumps(lock))
    reader = ir.IntentReader(embed=stub, lock_path=stub_lock, loud=False)
    assert reader.verify() == ir.DISABLED and "reference reading" in reader.reason


def test_weights_that_are_not_the_pinned_ones_disable(stub_lock):
    def embed(texts):
        return stub(texts)
    embed.weights = {"model.safetensors": "0" * 64}
    reader = ir.IntentReader(embed=embed, lock_path=stub_lock, loud=False)
    assert reader.verify() == ir.DISABLED and "weight" in reader.reason


def test_a_changed_p1_lockfile_or_harm_centroid_disables(stub_lock, tmp_path):
    p1 = tmp_path / "p1.json"
    shutil.copy(ir.P1_LOCK_PATH, p1)
    p1.write_bytes(p1.read_bytes() + b" ")
    reader = ir.IntentReader(embed=stub, lock_path=stub_lock, p1_lock_path=p1, loud=False)
    assert reader.verify() == ir.DISABLED and "P1 lockfile" in reader.reason
    lock = json.loads(stub_lock.read_text())
    lock["harm"]["centroids"]["self-harm"][0] += 0.001
    stub_lock.write_text(json.dumps(lock))
    reader = ir.IntentReader(embed=stub, lock_path=stub_lock, loud=False)
    assert reader.verify() == ir.DISABLED and "harm centroids" in reader.reason


def test_the_exemplars_are_disjoint_from_every_case():
    from integrations.governed_intent import cases_r2
    exemplars.assert_disjoint(cases.all_texts() + cases_r2.all_texts())
    for text in (exemplars.INTENT_EXEMPLARS["inspect"][0], exemplars.PUBLISH_EXEMPLARS_R2[0],
                 exemplars.BENIGN_CONTRAST_EXEMPLARS["process-control"][0]):
        with pytest.raises(AssertionError):
            exemplars.assert_disjoint([text.upper()])


def test_the_split_is_the_registered_rule():
    built = cases.build()
    for case in built:
        if case.set in ("a", "b1"):
            assert case.split == cases.HELD
        elif case.set in ("b2", "benign"):
            assert case.split == cases.split_of(case.id)
        elif case.kind == "harmful":            # both surfaces of one text share the text's split
            assert case.split == cases.split_of(case.id.rsplit("-", 1)[0])
    assert sum(case.set == "b2" for case in built) == 61 and sum(case.set == "benign" for case in built) == 104
