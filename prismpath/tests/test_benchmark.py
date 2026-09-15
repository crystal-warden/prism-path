# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Benchmark dataset + reproducer tests (Area 4)."""
import json
import os

from prismpath.kernel.parser import parse_file

from prismpath.tests._repo import repo_file

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = str(repo_file("prismpath", "benchmark", "routing_bench.jsonl"))
FLOWS = os.path.join(HERE, "flows")


def test_dataset_wellformed_and_labels_are_real_edges():
    cases = [json.loads(line) for line in open(DATA, encoding="utf-8") if line.strip()]
    assert len(cases) >= 17
    graphs = {}
    for case in cases:
        assert set(case) >= {"flow", "node", "outcome", "label", "stratum"}
        graph = graphs.setdefault(case["flow"], parse_file(os.path.join(FLOWS, f"{case['flow']}.md")))
        assert case["node"] in graph.nodes
        targets = [target for target, _ in graph.nodes[case["node"]].edges]
        assert case["label"] in targets, f"label {case['label']!r} is not an edge of {case['node']!r}"


def test_reproduce_aggregates_with_stub_embedder(monkeypatch):
    import numpy as np
    from prismpath.routing import embedder
    # a deterministic stub so the reproducer runs without the model; correctness of the numbers is
    # not asserted (that needs the real embedder) — only that aggregation runs and returns strata.
    monkeypatch.setattr(embedder, "embed",
                        lambda texts, is_query=False: np.ones((len(texts), 3), dtype="float32"))
    from prismpath.benchmark import reproduce
    per = reproduce.main()
    assert "ALL" in per and per["ALL"]["n"] >= 17
    assert {"intent", "polarity", "abstraction"} <= set(per)
