# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""prefilter.tune — the risk-controlled operating point, on synthetic geometry.

Corpus: two tight clusters (benign / malicious, cos > 0.99 internally) plus a handful of
"poison" entries near the benign cluster (~0.94) labeled malicious — the label-noise shape that
makes threshold choice matter: a low threshold reuses across the poison gap (errors), a high
one doesn't. The tuner must certify only what the Wilson bound supports, prefer the safer of
equal points, refuse to choose when the evidence can't clear the risk, and slot its answer into
the documented precedence (explicit > env > tuning.json > default)."""
import json

import numpy as np
import pytest

from prismpath import prefilter
from prismpath.prefilter import PrefilterCache, tune


def _no_embed(texts):
    raise AssertionError("the tuner must not embed when vectors are supplied")


def _unit(v):
    v = np.asarray(v, dtype=np.float32)
    return v / np.linalg.norm(v)


def build_corpus(dir_path, n_per=60, n_poison=6, dim=8, seed=7):
    rng = np.random.default_rng(seed)
    cache = PrefilterCache(dir_path, embed_fn=_no_embed)
    a = np.zeros(dim); a[0] = 1.0                        # benign centre
    b = np.zeros(dim); b[1] = 1.0                        # malicious centre
    for i in range(n_per):
        cache.learn(_unit(a + rng.normal(0, 0.01, dim)), "benign", 0.9, key=f"b{i}")
        cache.learn(_unit(b + rng.normal(0, 0.01, dim)), "malicious", 0.9, key=f"m{i}")
    # poison: near the benign cluster (~0.94) but labeled malicious; mutually spread so each
    # poison's best match is a BENIGN neighbour, not another poison
    for i in range(n_poison):
        off = np.zeros(dim); off[2 + i % (dim - 2)] = 0.36
        cache.learn(_unit(a + off), "malicious", 0.9, key=f"p{i}")
    return cache


def test_tuner_certifies_the_safe_point(tmp_path):
    corpus = str(tmp_path / "corpus")
    build_corpus(corpus)
    out = tune(corpus, risk=0.05, embed_fn=_no_embed)
    ch = out["chosen"]
    assert ch is not None, out["warning"]
    assert ch["threshold"] >= 0.95, "the poison gap sits at ~0.94 — a certified point must clear it"
    assert ch["errors"] == 0 and ch["err_upper"] <= 0.05
    # the clusters are tight (cos > 0.999), so 0.95/0.97/0.99 share the same auto-resolve —
    # equal points tie-break to the SAFEST (highest) threshold
    assert ch["threshold"] == pytest.approx(0.99)
    low = [r for r in out["grid"] if r["threshold"] == 0.90]
    assert any(r["errors"] > 0 for r in low), "the low threshold must actually reuse across the gap"
    assert all(not r["certified"] for r in low)


def test_tuner_refuses_when_evidence_cannot_clear_risk(tmp_path):
    corpus = str(tmp_path / "small")
    build_corpus(corpus, n_per=8, n_poison=0)            # tiny n -> Wilson can't certify 0.1%
    out = tune(corpus, risk=0.001, embed_fn=_no_embed)
    assert out["chosen"] is None and "risk=0.001" in out["warning"]
    assert (tmp_path / "small" / "tuning.json").exists(), \
        "the refusal is still recorded — an honest tuning.json with chosen=null"


def test_precedence_explicit_env_tuning_default(tmp_path, monkeypatch):
    corpus = str(tmp_path / "corpus")
    build_corpus(corpus)
    tune(corpus, risk=0.05, embed_fn=_no_embed)
    monkeypatch.delenv("PREFILTER_THRESHOLD", raising=False)
    monkeypatch.delenv("PREFILTER_MIN_CONF", raising=False)

    tuned = PrefilterCache(corpus, embed_fn=_no_embed)
    assert tuned.threshold == pytest.approx(0.99) and tuned._threshold_source == "tuning.json"
    assert tuned.stats()["threshold_source"] == "tuning.json"

    monkeypatch.setenv("PREFILTER_THRESHOLD", "0.93")
    env_cache = PrefilterCache(corpus, embed_fn=_no_embed)
    assert env_cache.threshold == pytest.approx(0.93) and env_cache._threshold_source == "env"

    explicit = PrefilterCache(corpus, threshold=0.91, embed_fn=_no_embed)
    assert explicit.threshold == pytest.approx(0.91) and explicit._threshold_source == "explicit"

    plain = PrefilterCache(str(tmp_path / "no_tuning"), embed_fn=_no_embed)
    monkeypatch.delenv("PREFILTER_THRESHOLD", raising=False)
    plain = PrefilterCache(str(tmp_path / "no_tuning"), embed_fn=_no_embed)
    assert plain.threshold == pytest.approx(0.97) and plain._threshold_source == "default"


def test_labeled_replay_stream(tmp_path):
    corpus = str(tmp_path / "corpus")
    cache = build_corpus(corpus, n_poison=0)
    emb, meta = cache.load()
    # replay half the corpus as external labels, one with a deliberately WRONG oracle
    labels = [{"vec": emb[i].tolist(), "action": meta[i]["action"]} for i in range(0, 40)]
    labels.append({"vec": emb[0].tolist(), "action": "malicious"})     # oracle disagrees
    out = tune(corpus, labels=labels, risk=0.5, embed_fn=_no_embed)
    assert out["labels"] == "labels" and out["n_eval"] == 41
    top = [r for r in out["grid"] if r["threshold"] == 0.99 and r["min_conf"] == 0.5][0]
    assert top["errors"] == 1, "exactly the mislabeled replay row disagrees"


def test_tuning_json_shape(tmp_path):
    corpus = str(tmp_path / "corpus")
    build_corpus(corpus, n_per=10, n_poison=0)
    out = tune(corpus, risk=0.5, embed_fn=_no_embed)
    on_disk = json.load(open(tmp_path / "corpus" / "tuning.json"))
    assert on_disk["chosen"] == out["chosen"]
    assert {"risk", "confidence", "labels", "grid", "generated_at"} <= set(on_disk)


def test_wilson_upper_sanity():
    assert prefilter._wilson_upper(0, 0) == 1.0            # no evidence -> worst case
    assert prefilter._wilson_upper(0, 1000) < 0.006        # lots of clean evidence -> tight
    assert prefilter._wilson_upper(5, 10) > 0.5            # half-bad -> bad
    assert prefilter._wilson_upper(0, 20) > 0.02, \
        "20 clean reuses can NOT certify a 2% bound — the n matters, not just zero errors"
