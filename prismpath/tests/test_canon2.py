# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The canon/2 strict reader, writer and canonicalize path (docs/design/spec-verified-core.md, sections 3
and 3.2): the frozen vectors are what the reference produces now, the writer's bytes read back to the same
value and are a fixed point, every other spelling is refused as not canonical and canonicalized to those
bytes, and the Lean oracle refuses every vector with the same rule and cause (when the oracle is built)."""
import json
import os
import random
import subprocess
from pathlib import Path

import pytest

from prismpath.kernel import canon2
from prismpath.portable import gen_canon2_fixtures

ROOT = Path(__file__).resolve().parents[2]
ORACLE = ROOT / "formal" / ".lake" / "build" / "bin" / "core-oracle"
ALWAYS = b'{"fields":{},"format":"prismpath.core/1","rules":[{"target":"t","when":["always"]}]}'


def test_the_vectors_are_current():
    assert gen_canon2_fixtures.OUT.read_text() == gen_canon2_fixtures.text()


def test_every_rule_is_exercised():
    rules = {case.get("refuse") for case in gen_canon2_fixtures.build()["cases"]}
    assert set(canon2.RULES) <= rules


@pytest.mark.parametrize("value", [None, True, 0, -1, 2 ** 53 - 1, "", "é\U0001f600\x00\x1f\x7f\\\"",
                                   [], {}, [[], {}], {"b": 1, "a": [1, {"": 2, "\U0001f600": 3}]}])
def test_the_writer_round_trips(value):
    data = canon2.dumps(value)
    assert canon2.loads(data) == value
    assert canon2.dumps(canon2.loads(data)) == data


@pytest.mark.parametrize("value,rule", [(0.5, "float"), (1.0, "float"), (2 ** 53, "integer-range"),
                                        (-(2 ** 53), "integer-range"), ("\ud800", "lone-surrogate"),
                                        ({"k": "\udc00"}, "lone-surrogate")])
def test_the_writer_refuses_what_the_reader_would(value, rule):
    with pytest.raises(canon2.Canon2Error) as raised:
        canon2.dumps(value)
    assert raised.value.rule == rule


def test_the_writer_refuses_depth_past_128():
    value = []
    for _ in range(128):
        value = [value]
    with pytest.raises(canon2.Canon2Error):
        canon2.dumps(value)
    assert canon2.loads(canon2.dumps(value[0])) == value[0]


def test_members_sort_by_utf16_code_units():
    assert canon2.dumps({"￿": 1, "\U0001f600": 2, "": 3}) == \
        '{"\U0001f600":2,"":3,"￿":1}'.encode()


def test_random_documents_round_trip():
    rng = random.Random(5)

    def value(depth):
        roll = rng.random()
        if depth > 4 or roll < 0.4:
            return rng.choice([None, True, False, 0, -7, 2 ** 53 - 1, "", "a\"b", "\U0001f600", "\x01"])
        if roll < 0.7:
            return [value(depth + 1) for _ in range(rng.randint(0, 3))]
        return {rng.choice(["a", "b", "", "é", "\U0001f600"]) + str(index): value(depth + 1) for index in range(rng.randint(0, 3))}

    respelled = 0
    for _ in range(2000):
        item = value(0)
        canonical = canon2.dumps(item)
        text = json.dumps(item, ensure_ascii=rng.random() < 0.5, indent=rng.choice([None, 1])).encode()
        assert canon2.canonicalize(text) == canonical
        if text != canonical:
            respelled += 1
            with pytest.raises(canon2.Canon2Error) as raised:
                canon2.loads(text)
            assert raised.value.rule == "not-canonical"
        assert canon2.loads(canonical) == item
        assert canon2.canonicalize(canonical) == canonical
    assert respelled > 800


@pytest.mark.parametrize("text", [b'{"a": 1}', b'{"b":1,"a":2}', b'"\\u0041"', b'"\\/"', b"{}\n", b" 0", b"[1, 2]",
                                  b'"\\u00e9"', b'"\\ud83d\\ude00"', b'"\\u001F"'])
def test_the_reader_refuses_every_other_spelling(text):
    with pytest.raises(canon2.Canon2Error) as raised:
        canon2.loads(text)
    assert raised.value.rule == "not-canonical"
    assert canon2.loads(canon2.canonicalize(text)) == canon2.loads(canon2.canonicalize(canon2.canonicalize(text)))


@pytest.mark.parametrize("text,rule", [(b"[1.5]", "float"), (b'{"a":1,"a":2}', "duplicate-key"), (b"-0", "negative-zero"),
                                       (b"9007199254740992", "integer-range"), (b'"\\ud800"', "lone-surrogate"),
                                       (b"\xff", "utf8"), (b"[" * 129 + b"]" * 129, "depth"), (b"{", "syntax")])
def test_canonicalize_holds_every_other_rule(text, rule):
    with pytest.raises(canon2.Canon2Error) as raised:
        canon2.canonicalize(text)
    assert raised.value.rule == rule


@pytest.mark.cross_language
def test_the_lean_reader_agrees_on_every_vector():
    if not ORACLE.exists():
        if os.environ.get("PRISMPATH_REQUIRE_CORE_ORACLE"):
            pytest.fail(f"PRISMPATH_REQUIRE_CORE_ORACLE is set and {ORACLE} is not built")
        pytest.skip("the Lean oracle is not built (cd formal && lake build)")
    cases = gen_canon2_fixtures.build()["cases"]
    frames = bytearray()
    for index, case in enumerate(cases):
        data = bytes.fromhex(case["hex"])
        frames += f"case {index} 1\n{len(ALWAYS)}\n".encode() + ALWAYS + f"\n{len(data)}\n".encode() + data + b"\n"
    out = subprocess.run([str(ORACLE), "--batch"], input=bytes(frames), capture_output=True, check=True).stdout
    for line, case in zip(out.decode().splitlines(), cases):
        verdict = json.loads(line)["readings"][0]
        lean = verdict.get("reason") if verdict.get("cause") in ("reading:unreadable", "reading:not-canonical") else None
        assert lean == case.get("refuse"), (case["name"], verdict)
        if lean is not None:
            # a spelling that is not canonical has its own registered cause, every reader rule the other
            want = ("reading:not-canonical", 102) if lean == "not-canonical" else ("reading:unreadable", 99)
            assert (verdict["cause"], verdict["code"]) == want, (case["name"], verdict)
