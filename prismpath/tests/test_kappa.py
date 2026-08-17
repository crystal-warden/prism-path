# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Gate-zero tooling tests — Cohen's κ, adjudication, and blind benchmark annotation."""
import json
import os

from prismpath import annotate, kappa
from prismpath.parser import parse_file

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH = os.path.join(HERE, "benchmark", "routing_bench.jsonl")


# --- Cohen's κ math --------------------------------------------------------------------
def test_cohen_kappa_bounds():
    assert kappa.cohen_kappa([], []) is None
    assert kappa.cohen_kappa(["a", "b", "a"], ["a", "b", "a"]) == 1.0        # perfect
    assert kappa.cohen_kappa(["a", "a", "a"], ["a", "a", "a"]) == 1.0        # degenerate marginals
    assert kappa.cohen_kappa(["a", "a", "b", "b"], ["a", "b", "a", "b"]) == 0.0   # chance-level
    # worse-than-chance is negative
    assert kappa.cohen_kappa(["a", "b", "a", "b"], ["b", "a", "b", "a"]) < 0
    # a strong-but-imperfect case lands between 0 and 1
    k = kappa.cohen_kappa(["a"] * 8 + ["b", "b"], ["a"] * 9 + ["b"])
    assert 0.0 < k < 1.0


def test_band_names():
    assert kappa.band(1.0) == "almost perfect"
    assert kappa.band(0.7) == "substantial"
    assert kappa.band(0.5) == "moderate"
    assert kappa.band(-0.1) == "poor"
    assert kappa.band(None) == "n/a"


# --- align / report / adjudicate -------------------------------------------------------
def _rec(node, outcome, label, stratum="intent", flow="f"):
    return {"flow": flow, "node": node, "outcome": outcome, "label": label, "stratum": stratum}


def test_align_is_order_independent_and_drops_unmatched():
    a = [_rec("n", "o1", "x"), _rec("n", "o2", "y"), _rec("n", "only_a", "z")]
    b = [_rec("n", "o2", "y"), _rec("n", "o1", "w")]                          # reversed; missing only_a
    pairs = kappa.align(a, b)
    assert len(pairs) == 2                                                    # only_a dropped
    assert {(ra["outcome"], ra["label"], rb["label"]) for ra, rb in pairs} == {("o1", "x", "w"), ("o2", "y", "y")}


def test_adjudicate_splits_gold_and_disagreements():
    a = [_rec("n", "o1", "x"), _rec("n", "o2", "y")]
    b = [_rec("n", "o1", "x"), _rec("n", "o2", "z")]
    gold, dis = kappa.adjudicate(a, b)
    assert len(gold) == 1 and gold[0]["label"] == "x"                        # agreement -> gold, benchmark-shaped
    assert set(gold[0]) == {"flow", "node", "outcome", "label", "stratum"}
    assert len(dis) == 1 and dis[0]["label_a"] == "y" and dis[0]["label_b"] == "z"


def test_report_shape_and_per_stratum():
    a = [_rec("n", "o1", "x", "intent"), _rec("n", "o2", "y", "polarity")]
    b = [_rec("n", "o1", "x", "intent"), _rec("n", "o2", "z", "polarity")]
    rep = kappa.report(a, b, by_stratum=True)
    assert rep["n"] == 2 and rep["observed_agreement"] == 0.5
    assert "intent" in rep["per_stratum"] and "polarity" in rep["per_stratum"]


def test_roundtrip_through_files(tmp_path):
    a = [_rec("n", "o1", "x")]
    kappa.dump(a, str(tmp_path / "a.jsonl"))
    assert kappa.load(str(tmp_path / "a.jsonl")) == a


# --- blind annotation ------------------------------------------------------------------
def test_blind_cases_strip_label_and_resolve_edges():
    cases = list(annotate.blind_cases(BENCH))
    assert len(cases) >= 300
    c = cases[0]
    assert "label" not in c and c["edges"] and c["targets"]                  # label hidden, edges resolved
    assert all(t in c["targets"] for t, _ in c["edges"])


def test_resolve_pick():
    assert annotate._resolve("2", ["a", "b", "c"]) == "b"
    assert annotate._resolve("b", ["a", "b", "c"]) == "b"
    assert annotate._resolve("9", ["a", "b"]) is None                        # out of range -> skip
    assert annotate._resolve("nope", ["a", "b"]) is None


def test_annotate_loop_writes_benchmark_shape_and_is_resumable(tmp_path):
    out = str(tmp_path / "ann.jsonl")
    n1 = annotate.annotate_loop(BENCH, out, input_fn=lambda p: "1", print_fn=lambda *a: None, limit=5)
    assert n1 == 5
    recs = [json.loads(l) for l in open(out)]
    assert all(set(r) == {"flow", "node", "outcome", "label", "stratum"} for r in recs)
    # resumable: a second run skips the 5 already done and labels the next 3
    n2 = annotate.annotate_loop(BENCH, out, input_fn=lambda p: "1", print_fn=lambda *a: None, limit=3)
    assert n2 == 3 and len([1 for _ in open(out)]) == 8


def test_gold_is_a_valid_benchmark_dataset(tmp_path):
    # two annotators who always agree -> gold whose labels are all REAL edges (drop-in for reproduce.py)
    out_a, out_b = str(tmp_path / "a.jsonl"), str(tmp_path / "b.jsonl")
    for out in (out_a, out_b):
        annotate.annotate_loop(BENCH, out, input_fn=lambda p: "1", print_fn=lambda *a: None, limit=10)
    gold, _ = kappa.adjudicate(kappa.load(out_a), kappa.load(out_b))
    assert gold
    graphs = {}
    for g in gold:
        graphs.setdefault(g["flow"], parse_file(os.path.join(HERE, "flows", f"{g['flow']}.md")))
        targets = [t for t, _ in graphs[g["flow"]].nodes[g["node"]].edges]
        assert g["label"] in targets
