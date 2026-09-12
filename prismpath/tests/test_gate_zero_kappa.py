# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Machine-check the routing benchmark's headline grading number.

gate_zero/findings.md reports a human-vs-gold Cohen's kappa of 0.961 (a maintainer blind-relabeled all
301 cases with the AI gold hidden). That number is the strongest evidence behind the routing-quality
claims, so it must not live only as prose: this recomputes it from the committed annotation files and
fails if it drifts. Catches a silently edited annotation set or a corpus/label change that would move
the grading number the papers rest on.
"""
import json
from collections import Counter
from pathlib import Path

from prismpath.tests._repo import repo_file

BENCH = repo_file("prismpath", "benchmark", "routing_bench.jsonl")
HUMAN = repo_file("prismpath", "benchmark", "gate_zero", "annot_human.jsonl")


def _load(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _cohen_kappa(labels_a, labels_b):
    count = len(labels_a)
    labels = set(labels_a) | set(labels_b)
    po = sum(label_a == label_b for label_a, label_b in zip(labels_a, labels_b)) / count
    ca, cb = Counter(labels_a), Counter(labels_b)
    pe = sum((ca[label] / count) * (cb[label] / count) for label in labels)
    return (po - pe) / (1 - pe)


def _aligned_pairs():
    gold = {(bench_row["flow"], bench_row["node"], bench_row["outcome"]): bench_row["label"] for bench_row in _load(BENCH)}
    pairs = []
    for human_row in _load(HUMAN):
        key = (human_row["flow"], human_row["node"], human_row["outcome"])
        assert key in gold, f"human annotation has no matching gold case: {key[:2]}"
        pairs.append((gold[key], human_row["label"], human_row.get("stratum")))
    return pairs


def test_every_human_annotation_aligns_to_gold():
    pairs = _aligned_pairs()
    assert len(pairs) == 301, f"expected 301 aligned cases, got {len(pairs)}"


def test_human_vs_gold_kappa_matches_findings():
    pairs = _aligned_pairs()
    kappa = _cohen_kappa([pair[0] for pair in pairs], [pair[1] for pair in pairs])
    # findings.md claims 0.961 ("almost perfect"); assert it stays in the almost-perfect band.
    assert kappa >= 0.95, f"human-vs-gold kappa dropped to {kappa:.3f} (findings.md: 0.961)"


def test_every_stratum_kappa_at_least_0_94():
    by = {}
    for gold, human, stratum in _aligned_pairs():
        by.setdefault(stratum, ([], []))
        by[stratum][0].append(gold)
        by[stratum][1].append(human)
    for stratum, (gold_labels, human_labels) in by.items():
        agreement = _cohen_kappa(gold_labels, human_labels)
        assert agreement >= 0.94, f"stratum {stratum} kappa fell to {agreement:.3f} (findings.md: all >= 0.945)"
