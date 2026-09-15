# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Routing-decision-log tests (Sprint 0) — durable log of semantic decisions + label workbench."""
import json

import numpy as np

from prismpath.routing import embedder
from prismpath.routing import routelog
from prismpath.kernel.parser import parse
from prismpath.routing.router import EmbeddingRouter

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


def _unit(vector):
    vector = np.asarray(vector, "float32")
    return vector / (np.linalg.norm(vector) or 1)


def _stub(monkeypatch):
    vecs = {"something is broken": _unit([1, 0]), "about a payment": _unit([0, 1]),
            "the app crashes": _unit([0.95, 0.05])}
    monkeypatch.setattr(embedder, "embed",
                        lambda texts, is_query=False: np.asarray([vecs[text] for text in texts], "float32"))


def test_run_logged_emits_a_record_per_semantic_decision(tmp_path, monkeypatch):
    _stub(monkeypatch)
    graph = parse(FLOW)
    log = str(tmp_path / "routes.jsonl")
    agent = lambda node, instruction, state: {"text": "the app crashes" if node == "classify" else node, "always": True}
    routelog.run_logged(graph, agent, log, router=EmbeddingRouter(), run_id="R1")
    recs = routelog.load_records(log)
    assert len(recs) == 1                                   # one semantic node (classify); the rest deterministic
    record = recs[0]
    assert record["node"] == "classify" and record["flow"] == "triage" and record["run_id"] == "R1"
    assert record["chosen"] == "bug" and record["mechanism"] == "embed" and record["escalated"] is False
    assert {candidate["target"] for candidate in record["candidates"]} == {"bug", "billing"}
    assert record["top1"] >= record["top2"] and record["label"] is None


def test_load_save_roundtrip(tmp_path):
    recs = [{"node": "a", "label": None}, {"node": "b", "label": "x"}]
    path = str(tmp_path / "r.jsonl")
    routelog.save_records(path, recs)
    assert routelog.load_records(path) == recs


def test_label_records_fills_unlabeled(tmp_path):
    recs = [
        {"node": "n1", "candidates": [{"target": "a"}, {"target": "b"}], "chosen": "a", "label": None},
        {"node": "n2", "candidates": [{"target": "x"}, {"target": "y"}], "chosen": "x", "label": "x"},
        {"node": "n3", "candidates": [{"target": "p"}, {"target": "q"}], "chosen": "p", "label": None},
    ]
    # scripted ask: label n1 -> b, skip n3
    answers = {"n1": "b", "n3": None}
    labeled_count = routelog.label_records(recs, lambda record, targets: answers[record["node"]])
    assert labeled_count == 1                                           # only n1 newly labeled (n2 already, n3 skipped)
    assert recs[0]["label"] == "b" and recs[0]["label_source"] == "human"
    assert recs[2]["label"] is None
    stats = routelog.label_stats(recs)
    assert stats == {"total": 3, "labeled": 2, "unlabeled": 1, "router_correct_on_labeled": 1}


def test_jsonl_sink_appends(tmp_path):
    path = str(tmp_path / "s.jsonl")
    sink = routelog.jsonl_sink(path)
    sink({"a": 1})
    sink({"a": 2})
    assert [json.loads(line) for line in open(path)] == [{"a": 1}, {"a": 2}]
