# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""kappa.py — inter-annotator agreement (Cohen's κ) + adjudication for the routing benchmark.

Gate zero for a release claim is a HUMAN-annotated benchmark with reported Cohen's κ: our N=301 labels
were AI-generated and AI-blind-confirmed (agreement 0.979), but both annotators are the same model
family, so that is an upper bound, not chance-corrected human agreement. This module closes the loop.

Everything is benchmark-shaped — records are `{flow, node, outcome, label, stratum}` (the same schema
`prismpath annotate` writes and `benchmark/reproduce.py` reads), so any two annotation files (human vs
human, or the adjudicated gold vs the original AI labels) compare uniformly, and the gold this emits is
a drop-in dataset for `reproduce.py`.

    a = load("alice.jsonl"); b = load("bob.jsonl")
    rep = report(a, b, by_stratum=True)          # {n, observed_agreement, kappa, band, confusion, ...}
    gold, disagreements = adjudicate(a, b)        # gold = agreements (benchmark-shaped); rest for a 3rd pass

Cohen's κ = (p_o − p_e)/(1 − p_e): observed agreement minus the agreement expected by chance from each
annotator's marginal label frequencies. κ=1 perfect, ~0 chance-level; the Landis–Koch band names it.
"""
from __future__ import annotations

import json
from collections import Counter
from typing import Dict, List, Optional, Tuple

# Landis & Koch (1977) interpretation bands.
_BANDS = [(-1.0, "poor"), (0.0, "slight"), (0.21, "fair"), (0.41, "moderate"),
          (0.61, "substantial"), (0.81, "almost perfect")]


def band(k: Optional[float]) -> str:
    if k is None:
        return "n/a"
    name = "poor"
    for lo, nm in _BANDS:
        if k >= lo:
            name = nm
    return name


def load(path: str) -> List[dict]:
    return [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]


def _key(r: dict) -> Tuple[str, str, str]:
    return (r.get("flow", ""), r.get("node", ""), (r.get("outcome") or "").strip())


def align(a: List[dict], b: List[dict]) -> List[Tuple[dict, dict]]:
    """Pair records that describe the SAME decision (flow, node, outcome). Order-independent; unmatched
    records on either side are dropped (κ is only defined over co-labeled items)."""
    bi = {}
    for r in b:
        bi.setdefault(_key(r), r)
    return [(ra, bi[_key(ra)]) for ra in a if _key(ra) in bi]


def cohen_kappa(labels_a: List[str], labels_b: List[str]) -> Optional[float]:
    """Cohen's κ for two aligned label sequences. None if empty; 1.0 if both are the single same label
    (perfect + degenerate marginals); may be negative for worse-than-chance agreement."""
    n = len(labels_a)
    if n == 0:
        return None
    ca, cb = Counter(labels_a), Counter(labels_b)
    po = sum(1 for x, y in zip(labels_a, labels_b) if x == y) / n
    pe = sum((ca[c] / n) * (cb[c] / n) for c in set(ca) | set(cb))
    if pe >= 1.0:                                    # both annotators used exactly one (same) category
        return 1.0 if po >= 1.0 else 0.0
    return (po - pe) / (1.0 - pe)


def report(a: List[dict], b: List[dict], by_stratum: bool = False) -> dict:
    pairs = align(a, b)
    la = [ra.get("label") for ra, _ in pairs]
    lb = [rb.get("label") for _, rb in pairs]
    k = cohen_kappa(la, lb)
    confusion = Counter((x, y) for x, y in zip(la, lb) if x != y)
    out = {
        "n": len(pairs),
        "n_a": len(a), "n_b": len(b),
        "observed_agreement": round(sum(1 for x, y in zip(la, lb) if x == y) / len(pairs), 4)
        if pairs else None,
        "kappa": round(k, 4) if k is not None else None,
        "band": band(k),
        "disagreements": [f"{x} vs {y}: {n}" for (x, y), n in confusion.most_common()],
    }
    if by_stratum:
        strata: Dict[str, List[Tuple[dict, dict]]] = {}
        for ra, rb in pairs:
            strata.setdefault(ra.get("stratum", "?"), []).append((ra, rb))
        out["per_stratum"] = {
            s: {"n": len(ps),
                "kappa": (lambda kk: round(kk, 4) if kk is not None else None)(
                    cohen_kappa([x.get("label") for x, _ in ps], [y.get("label") for _, y in ps]))}
            for s, ps in sorted(strata.items())}
    return out


def adjudicate(a: List[dict], b: List[dict]) -> Tuple[List[dict], List[dict]]:
    """Split aligned cases into GOLD (the two annotators agree -> a benchmark-shaped record whose label
    is the agreed edge) and DISAGREEMENTS (need a third pass; both picks retained). Cases only one
    annotator labeled are not adjudicable and are omitted from both."""
    gold, disagree = [], []
    for ra, rb in align(a, b):
        if ra.get("label") == rb.get("label"):
            gold.append({"flow": ra.get("flow"), "node": ra.get("node"), "outcome": ra.get("outcome"),
                         "label": ra.get("label"), "stratum": ra.get("stratum")})
        else:
            disagree.append({"flow": ra.get("flow"), "node": ra.get("node"),
                             "outcome": ra.get("outcome"), "stratum": ra.get("stratum"),
                             "label_a": ra.get("label"), "label_b": rb.get("label")})
    return gold, disagree


def dump(records: List[dict], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
