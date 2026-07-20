"""Benchmark dataset + reproducer tests (Area 4)."""
import json
import os

from prismpath.parser import parse_file

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(HERE, "benchmark", "routing_bench.jsonl")
FLOWS = os.path.join(HERE, "flows")


def test_dataset_wellformed_and_labels_are_real_edges():
    cases = [json.loads(l) for l in open(DATA, encoding="utf-8") if l.strip()]
    assert len(cases) >= 17
    graphs = {}
    for c in cases:
        assert set(c) >= {"flow", "node", "outcome", "label", "stratum"}
        g = graphs.setdefault(c["flow"], parse_file(os.path.join(FLOWS, f"{c['flow']}.md")))
        assert c["node"] in g.nodes
        targets = [t for t, _ in g.nodes[c["node"]].edges]
        assert c["label"] in targets, f"label {c['label']!r} is not an edge of {c['node']!r}"


def test_reproduce_aggregates_with_stub_embedder(monkeypatch):
    import numpy as np
    from prismpath import embedder
    # a deterministic stub so the reproducer runs without the model; correctness of the numbers is
    # not asserted (that needs the real embedder) — only that aggregation runs and returns strata.
    monkeypatch.setattr(embedder, "embed",
                        lambda texts, is_query=False: np.ones((len(texts), 3), dtype="float32"))
    from prismpath.benchmark import reproduce
    per = reproduce.main()
    assert "ALL" in per and per["ALL"]["n"] >= 17
    assert {"intent", "polarity", "abstraction"} <= set(per)
