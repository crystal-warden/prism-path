# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Prefilter tests — exercise PrefilterCache / match_arrays WITHOUT loading any real model.

Every cache gets a stub embed_fn (list[str] -> [n,d] unit-normalized float32) and a tmp_path
corpus dir, so no sentence-transformers / torch / network. The stub maps known documents to
hand-picked unit vectors, which lets tests dial in exact cosines (e.g. a just-below-threshold
pair) instead of hoping a real embedder lands where the test needs it.
"""
import json
import math

import numpy as np

from prismpath.prefilter import CacheResult, PrefilterCache, match_arrays

# hand-picked unit vectors: DOC_A/DOC_B are identical direction; DOC_NEAR is at a controlled
# angle to DOC_A (cos ~0.95 — above 0.9, below 0.97); DOC_FAR is orthogonal.
_COS = 0.95
_VECS = {
    "doc a": np.array([1.0, 0.0], dtype="float32"),
    "doc a again": np.array([1.0, 0.0], dtype="float32"),
    "doc near a": np.array([_COS, math.sqrt(1 - _COS**2)], dtype="float32"),
    "doc far": np.array([0.0, 1.0], dtype="float32"),
}


def stub_embed(texts):
    return np.vstack([_VECS[t] for t in texts])


def make_cache(tmp_path, **kw):
    kw.setdefault("threshold", 0.97)
    kw.setdefault("min_conf", 0.8)
    return PrefilterCache(tmp_path / "corpus", embed_fn=stub_embed, **kw)


def test_empty_corpus_misses_and_returns_reusable_vector(tmp_path):
    c = make_cache(tmp_path)
    r = c.lookup("doc a")
    assert isinstance(r, CacheResult)
    assert r.hit is False and r.record is None and r.similarity == 0.0
    assert r.vector.shape == (2,)          # reusable by learn() — no re-embed
    assert len(c) == 0


def test_learn_then_identical_lookup_hits_with_record_fields(tmp_path):
    c = make_cache(tmp_path)
    r = c.lookup("doc a")
    c.learn(r.vector, "contain", 0.95, key="k1", description="desc one")
    r2 = c.lookup("doc a again")           # identical direction -> cosine 1.0
    assert r2.hit is True
    assert r2.record["action"] == "contain"
    assert r2.record["confidence"] == 0.95
    assert r2.record["key"] == "k1"
    assert r2.record["description"] == "desc one"
    assert r2.similarity > 0.999


def test_similar_but_below_threshold_misses(tmp_path):
    # cos(doc near a, doc a) ~ 0.95 < threshold 0.97 -> miss, but similarity is reported.
    c = make_cache(tmp_path)
    c.learn("doc a", "watch", 0.9)
    r = c.lookup("doc near a")
    assert r.hit is False
    assert 0.90 < r.similarity < 0.97


def test_confidence_floor_blocks_hit_even_at_perfect_similarity(tmp_path):
    c = make_cache(tmp_path)
    c.learn("doc a", "watch", 0.5)          # stored confidence < min_conf 0.8
    r = c.lookup("doc a again")
    assert r.similarity > 0.999             # same situation...
    assert r.hit is False                   # ...but the prior verdict wasn't trustworthy


def test_persistence_across_instances(tmp_path):
    c = make_cache(tmp_path)
    c.learn("doc a", "contain", 0.9, key="k")
    c.learn("doc far", "ignore", 0.9)
    c2 = make_cache(tmp_path)               # fresh instance, same dir
    assert len(c2) == 2
    assert c2.stats()["by_action"] == {"contain": 1, "ignore": 1}
    assert c2.lookup("doc a").hit is True


def test_legacy_field_names_migrate_on_load(tmp_path):
    # corpora written before the generic API used recommended_action / alert_key
    d = tmp_path / "corpus"
    d.mkdir(parents=True)
    np.save(d / "embeddings.npy", stub_embed(["doc a"]))
    (d / "meta.json").write_text(json.dumps([{
        "recommended_action": "ignore", "confidence": 0.9,
        "alert_key": "1002|host|none", "description": "old entry"}]))
    c = make_cache(tmp_path)
    r = c.lookup("doc a")
    assert r.hit is True
    assert r.record["action"] == "ignore"
    assert r.record["key"] == "1002|host|none"


def test_learn_accepts_raw_document_string(tmp_path):
    c = make_cache(tmp_path)
    c.learn("doc a", "contain", 0.9)         # str -> embedded internally
    assert len(c) == 1
    assert c.lookup("doc a again").hit is True


def test_match_arrays_pure_function_threshold_and_conf_sweeps(tmp_path):
    emb = stub_embed(["doc a"])
    recs = [{"action": "watch", "confidence": 0.85}]
    v = stub_embed(["doc near a"])[0]        # cosine ~0.95 to the corpus entry
    hit_lo, rec, sim = match_arrays(v, emb, recs, threshold=0.90, min_conf=0.8)
    assert hit_lo is True and rec["action"] == "watch" and 0.90 < sim < 0.97
    hit_hi, _, _ = match_arrays(v, emb, recs, threshold=0.97, min_conf=0.8)
    assert hit_hi is False                   # same vector, tighter threshold
    hit_conf, _, _ = match_arrays(v, emb, recs, threshold=0.90, min_conf=0.9)
    assert hit_conf is False                 # same vector, tighter confidence floor
    hit_empty, rec_e, sim_e = match_arrays(v, np.zeros((0, 0), dtype="float32"), [],
                                           threshold=0.5, min_conf=0.0)
    assert (hit_empty, rec_e, sim_e) == (False, None, 0.0)


def test_clear_empties_the_corpus(tmp_path):
    c = make_cache(tmp_path)
    c.learn("doc a", "contain", 0.9)
    assert len(c) == 1
    c.clear()
    assert len(c) == 0
    assert c.lookup("doc a").hit is False
