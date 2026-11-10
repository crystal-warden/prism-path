# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The canon/2 reader and writer (docs/design/spec-verified-core.md, section 3): the frozen vectors are
what the reference produces now, the writer's bytes read back to the same value and are a fixed point,
and the Lean oracle's reader refuses every vector with the same rule (when the oracle is built)."""
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
ALWAYS = b'{"format":"prismpath.core/1","fields":{},"rules":[{"target":"t","when":["always"]}]}'


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

    for _ in range(2000):
        item = value(0)
        text = json.dumps(item, ensure_ascii=rng.random() < 0.5, indent=rng.choice([None, 1]))
        assert canon2.loads(text.encode()) == item
        assert canon2.loads(canon2.dumps(item)) == item


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
        lean = verdict.get("reason") if verdict.get("cause") == "reading:unreadable" else None
        assert lean == case.get("refuse"), (case["name"], verdict)
