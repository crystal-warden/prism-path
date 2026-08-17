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

BASE = Path(__file__).resolve().parent.parent.parent
BENCH = BASE / "prismpath" / "benchmark" / "routing_bench.jsonl"
HUMAN = BASE / "prismpath" / "benchmark" / "gate_zero" / "annot_human.jsonl"


def _load(p):
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]


def _cohen_kappa(a, b):
    n = len(a)
    labels = set(a) | set(b)
    po = sum(x == y for x, y in zip(a, b)) / n
    ca, cb = Counter(a), Counter(b)
    pe = sum((ca[c] / n) * (cb[c] / n) for c in labels)
    return (po - pe) / (1 - pe)


def _aligned_pairs():
    gold = {(b["flow"], b["node"], b["outcome"]): b["label"] for b in _load(BENCH)}
    pairs = []
    for h in _load(HUMAN):
        key = (h["flow"], h["node"], h["outcome"])
        assert key in gold, f"human annotation has no matching gold case: {key[:2]}"
        pairs.append((gold[key], h["label"], h.get("stratum")))
    return pairs


def test_every_human_annotation_aligns_to_gold():
    pairs = _aligned_pairs()
    assert len(pairs) == 301, f"expected 301 aligned cases, got {len(pairs)}"


def test_human_vs_gold_kappa_matches_findings():
    pairs = _aligned_pairs()
    kappa = _cohen_kappa([p[0] for p in pairs], [p[1] for p in pairs])
    # findings.md claims 0.961 ("almost perfect"); assert it stays in the almost-perfect band.
    assert kappa >= 0.95, f"human-vs-gold kappa dropped to {kappa:.3f} (findings.md: 0.961)"


def test_every_stratum_kappa_at_least_0_94():
    by = {}
    for gold, human, stratum in _aligned_pairs():
        by.setdefault(stratum, ([], []))
        by[stratum][0].append(gold)
        by[stratum][1].append(human)
    for stratum, (g, h) in by.items():
        k = _cohen_kappa(g, h)
        assert k >= 0.94, f"stratum {stratum} kappa fell to {k:.3f} (findings.md: all >= 0.945)"
