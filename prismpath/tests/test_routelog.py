"""Routing-decision-log tests (Sprint 0) — durable log of semantic decisions + label workbench."""
import json

import numpy as np

from prismpath import embedder, routelog
from prismpath.parser import parse
from prismpath.router import EmbeddingRouter

FLOW = """---
name: triage
start: classify
---
## classify
Decide the kind of request.
-> bug: something is broken
-> billing: about a payment
## bug
-> done: when always
## billing
-> done: when always
## done
"""


def _unit(v):
    v = np.asarray(v, "float32")
    return v / (np.linalg.norm(v) or 1)


def _stub(monkeypatch):
    vecs = {"something is broken": _unit([1, 0]), "about a payment": _unit([0, 1]),
            "the app crashes": _unit([0.95, 0.05])}
    monkeypatch.setattr(embedder, "embed",
                        lambda texts, is_query=False: np.asarray([vecs[t] for t in texts], "float32"))


def test_run_logged_emits_a_record_per_semantic_decision(tmp_path, monkeypatch):
    _stub(monkeypatch)
    g = parse(FLOW)
    log = str(tmp_path / "routes.jsonl")
    agent = lambda n, i, s: {"text": "the app crashes" if n == "classify" else n, "always": True}
    routelog.run_logged(g, agent, log, router=EmbeddingRouter(), run_id="R1")
    recs = routelog.load_records(log)
    assert len(recs) == 1                                   # one semantic node (classify); the rest deterministic
    r = recs[0]
    assert r["node"] == "classify" and r["flow"] == "triage" and r["run_id"] == "R1"
    assert r["chosen"] == "bug" and r["mechanism"] == "embed" and r["escalated"] is False
    assert {c["target"] for c in r["candidates"]} == {"bug", "billing"}
    assert r["top1"] >= r["top2"] and r["label"] is None


def test_load_save_roundtrip(tmp_path):
    recs = [{"node": "a", "label": None}, {"node": "b", "label": "x"}]
    p = str(tmp_path / "r.jsonl")
    routelog.save_records(p, recs)
    assert routelog.load_records(p) == recs


def test_label_records_fills_unlabeled(tmp_path):
    recs = [
        {"node": "n1", "candidates": [{"target": "a"}, {"target": "b"}], "chosen": "a", "label": None},
        {"node": "n2", "candidates": [{"target": "x"}, {"target": "y"}], "chosen": "x", "label": "x"},
        {"node": "n3", "candidates": [{"target": "p"}, {"target": "q"}], "chosen": "p", "label": None},
    ]
    # scripted ask: label n1 -> b, skip n3
    answers = {"n1": "b", "n3": None}
    n = routelog.label_records(recs, lambda r, targets: answers[r["node"]])
    assert n == 1                                           # only n1 newly labeled (n2 already, n3 skipped)
    assert recs[0]["label"] == "b" and recs[0]["label_source"] == "human"
    assert recs[2]["label"] is None
    stats = routelog.label_stats(recs)
    assert stats == {"total": 3, "labeled": 2, "unlabeled": 1, "router_correct_on_labeled": 1}


def test_jsonl_sink_appends(tmp_path):
    p = str(tmp_path / "s.jsonl")
    sink = routelog.jsonl_sink(p)
    sink({"a": 1})
    sink({"a": 2})
    assert [json.loads(l) for l in open(p)] == [{"a": 1}, {"a": 2}]
