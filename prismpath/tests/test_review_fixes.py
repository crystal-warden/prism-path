# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Regression tests for fixes from the adversarial code review."""
import numpy as np
import pytest

from prismpath import checkpoint, flow_test, predicates, prefilter
from prismpath.parser import parse, parse_file


def test_utf8_flow_parses(tmp_path):
    # em-dashes and other non-ASCII must parse regardless of the platform's default locale
    p = tmp_path / "u.md"
    p.write_text("---\nstart: a\n---\n## a\nDo — a thing with ünïcode.\n-> b: when always\n## b\n",
                 encoding="utf-8")
    assert parse_file(str(p)).nodes["a"].instruction.startswith("Do —")


def test_predicate_compare_survives_nontypeerror(monkeypatch):
    class Bomb:
        def __gt__(self, other): raise ValueError("nope")
        def __lt__(self, other): raise ValueError("nope")
    # a ctx value whose comparison raises ValueError must be treated as unsatisfied, not crash
    assert predicates.eval_condition("when x > 3", {"x": Bomb()}) is False


def test_parse_tests_without_separator_keeps_first_row():
    cases = flow_test.parse_tests("| node | expect |\n| a | b |\n")   # no |---| separator
    assert len(cases) == 1 and cases[0] == {"node": "a", "outcome": "", "fields": {}, "expect": "b"}


def test_prefilter_migrate_defaults_action(tmp_path):
    cache = prefilter.PrefilterCache(tmp_path / "c", embed_fn=lambda t: np.ones((len(t), 3), "float32"))
    import json
    cache.dir.mkdir(parents=True)
    np.save(cache._emb_path, np.ones((1, 3), "float32"))
    (cache._meta_path).write_text(json.dumps([{"confidence": 0.9}]))   # no action / recommended_action
    assert cache.stats()["by_action"] == {"": 1}                       # no KeyError


def test_prefilter_save_is_atomic(tmp_path):
    cache = prefilter.PrefilterCache(tmp_path / "c", embed_fn=lambda t: np.ones((len(t), 3), "float32"))
    cache.learn("doc", "contain", 0.9, key="k")
    assert len(cache) == 1
    assert not (cache.dir / "embeddings.npy.tmp.npy").exists()         # no temp left behind


ROUTE = """---
start: fetch
---
## fetch
-> idle: when no_item
-> check: when always
## check
@checkpoint(unit=item_id, gate=ok)
-> done: when always
## done
## idle
"""


def test_ledger_gate_red_does_not_head_of_line_block(tmp_path):
    import subprocess
    if subprocess.run(["git", "--version"], capture_output=True).returncode != 0:
        pytest.skip("git")
    from prismpath.ledger import Ledger
    from prismpath.ledger_runner import run_ledgered_loop
    flow = tmp_path / "q.md"
    flow.write_text(ROUTE)
    led = Ledger(flow="q", run_id="01H", state_dir=tmp_path / "ledger")

    # item "bad" always gate-reds; "good" passes. bad must not block good.
    class A:
        def __call__(self, node, instr, state):
            if node == "fetch":
                done = state.get("_done_units", set())
                nxt = next((i for i in ["bad", "good"] if i not in done), None)
                if nxt is None:
                    return {"text": "idle", "no_item": True}
                state["item_id"] = nxt
                return {"text": f"fetched {nxt}", "no_item": False}
            return {"text": "checked", "ok": state["item_id"] == "good", "always": True}

    committed = run_ledgered_loop(str(flow), A(), led)
    assert committed == ["good"]                                       # bad skipped, good still proven
    assert set(led.done_set()) == {"good"}


def test_double_resume_keeps_full_path(tmp_path):
    # crash -> resume (which itself checkpoints) -> crash again -> resume: full path is preserved
    flow = tmp_path / "lin.md"
    flow.write_text("---\nstart: a\n---\n## a\n-> b: when always\n## b\n-> c: when always\n"
                    "## c\n-> d: when always\n## d\n-> done: when always\n## done\n")
    ckpt = str(tmp_path / "ck.json")

    class CrashAt:
        def __init__(self, at): self.at = at
        def __call__(self, n, i, s):
            if n == self.at: raise RuntimeError("x")
            return {"text": n, "always": True}

    with pytest.raises(RuntimeError):
        checkpoint.run_durable(str(flow), CrashAt("b"), ckpt)
    with pytest.raises(RuntimeError):
        checkpoint.resume(ckpt, CrashAt("c"))                         # resumes b, crashes at c
    res = checkpoint.resume(ckpt, CrashAt(None))                      # resumes c onward
    assert res.path == ["a", "b", "c", "d", "done"]                  # nothing dropped across resumes
    assert [s.node for s in res.steps] == ["a", "b", "c", "d"]        # steps consistent with path
