"""Tests for `prismpath test` — the Markdown routing-fixture runner.

Deterministic-tier cases need no model (and prove it — the router is never constructed). Embed-tier
cases use a stub embedder. Also covers the fixture parser and the --emit-labels side output.
"""
import json

import numpy as np
import pytest

from prismpath import embedder, flow_test
from prismpath.router import EmbeddingRouter

DET_FLOW = """---
name: gate
start: gate
---
## gate
-> pass: when ok
-> fail: when not ok
## pass
-> done: when always
## fail
-> done: when always
## done
"""

DET_TESTS = """# tests
| node | outcome    | fields   | expect |
|------|------------|----------|--------|
| gate | looks good | ok=true  | pass   |
| gate | broken     | ok=false | fail   |
"""

SEM_FLOW = """---
name: triage
start: classify
---
## classify
Decide the kind of request.
-> bug: something is broken
-> billing: about a payment or refund
## bug
-> done: when always
## billing
-> done: when always
## done
"""


def _unit(v):
    v = np.asarray(v, "float32")
    return v / (np.linalg.norm(v) or 1)


def _write(tmp_path, flow, tests, stem="f"):
    fp = tmp_path / f"{stem}.md"
    fp.write_text(flow)
    tp = tmp_path / f"{stem}.tests.md"
    tp.write_text(tests)
    return str(fp), str(tp)


# --- parser -----------------------------------------------------------------------------

def test_parse_tests_columns_and_fields():
    cases = flow_test.parse_tests(DET_TESTS)
    assert len(cases) == 2
    assert cases[0] == {"node": "gate", "outcome": "looks good",
                        "fields": {"ok": True}, "expect": "pass"}
    assert cases[1]["fields"] == {"ok": False}


def test_parse_tests_ignores_non_table_and_bad_headers():
    assert flow_test.parse_tests("no table here") == []
    assert flow_test.parse_tests("| a | b |\n|---|---|\n| 1 | 2 |") == []   # no node/expect cols


# --- deterministic tier: no model touched ----------------------------------------------

def test_deterministic_cases_pass_without_a_model(tmp_path, monkeypatch):
    # make any embedder use explode, to prove the deterministic path never calls it
    monkeypatch.setattr(embedder, "embed", lambda *a, **k: (_ for _ in ()).throw(AssertionError("embedded!")))
    fp, tp = _write(tmp_path, DET_FLOW, DET_TESTS)
    report = flow_test.run_tests(fp, tp)
    assert report.ok and report.passed == 2
    assert all(r.how == "deterministic" for r in report.results)


# --- embed tier: stub embedder ----------------------------------------------------------

@pytest.fixture
def stub_embed(monkeypatch):
    vecs = {"something is broken": _unit([1, 0]), "about a payment or refund": _unit([0, 1]),
            "the app crashes on save": _unit([0.95, 0.05]), "i want my money back": _unit([0.05, 0.95])}
    monkeypatch.setattr(embedder, "embed",
                        lambda texts, is_query=False: np.asarray([vecs[t] for t in texts], "float32"))


def test_embed_cases_route_and_report(tmp_path, stub_embed):
    tests = ("| node | outcome | expect |\n|---|---|---|\n"
             "| classify | the app crashes on save | bug |\n"
             "| classify | i want my money back | billing |\n")
    fp, tp = _write(tmp_path, SEM_FLOW, tests)
    report = flow_test.run_tests(fp, tp, router=EmbeddingRouter())
    assert report.ok and report.passed == 2
    assert all(r.how == "embed" for r in report.results)


def test_failing_case_is_reported(tmp_path, stub_embed):
    tests = ("| node | outcome | expect |\n|---|---|---|\n"
             "| classify | the app crashes on save | billing |\n")   # wrong expectation
    fp, tp = _write(tmp_path, SEM_FLOW, tests)
    report = flow_test.run_tests(fp, tp, router=EmbeddingRouter())
    assert not report.ok and report.failed == 1
    assert report.results[0].got == "bug" and report.results[0].expect == "billing"


def test_unknown_node_is_an_error(tmp_path, monkeypatch):
    monkeypatch.setattr(embedder, "embed", lambda *a, **k: np.zeros((1, 2), "float32"))
    tests = "| node | outcome | expect |\n|---|---|---|\n| nope | x | y |\n"
    fp, tp = _write(tmp_path, DET_FLOW, tests)
    report = flow_test.run_tests(fp, tp)
    assert not report.ok and report.results[0].how == "error"


# --- labeled-data side output -----------------------------------------------------------

def test_emit_labels_writes_jsonl(tmp_path, monkeypatch):
    monkeypatch.setattr(embedder, "embed", lambda *a, **k: (_ for _ in ()).throw(AssertionError))
    fp, tp = _write(tmp_path, DET_FLOW, DET_TESTS)
    report = flow_test.run_tests(fp, tp)
    out = tmp_path / "labels.jsonl"
    n = flow_test.emit_labels(report, "gate", str(out))
    assert n == 2
    recs = [json.loads(l) for l in out.read_text().splitlines()]
    assert recs[0]["label"] == "pass" and recs[0]["label_source"] == "flow_test"
    assert recs[0]["chosen"] == "pass" and recs[0]["correct"] is True


def test_default_tests_path():
    assert flow_test.default_tests_path("flows/bugfix.md") == "flows/bugfix.tests.md"
