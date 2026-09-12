# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Regression: the embedding router's condition cache is bounded.

Found in the September 2026 readability review: EmbeddingRouter._cache was keyed by the tuple of
condition strings and never evicted, so a long lived process routing many distinct flows grew
without bound. The cache is now least recently used with a stated cap.
"""
import numpy as np

from prismpath.routing import router as router


def _stub_embed(texts, is_query=False):
    return np.zeros((len(texts), 4), dtype=np.float32)


def test_cache_is_bounded_and_keeps_recent_keys(monkeypatch):
    monkeypatch.setattr(router.embedder, "embed", _stub_embed)
    embedding_router = router.EmbeddingRouter()
    cap = router.CACHE_MAX
    assert 16 <= cap <= 4096
    for i in range(cap + 50):
        embedding_router._cond_embs([("t", f"cond {i}")])
    assert len(embedding_router._cache) == cap
    assert ("cond 0",) not in embedding_router._cache            # the oldest key was evicted
    assert (f"cond {cap + 49}",) in embedding_router._cache     # the newest key is present


def test_recently_used_key_survives(monkeypatch):
    monkeypatch.setattr(router.embedder, "embed", _stub_embed)
    embedding_router = router.EmbeddingRouter()
    cap = router.CACHE_MAX
    embedding_router._cond_embs([("t", "keep me")])
    for i in range(cap - 1):
        embedding_router._cond_embs([("t", f"filler {i}")])
    embedding_router._cond_embs([("t", "keep me")])             # touch it: it is the most recently used now
    for i in range(cap // 2):
        embedding_router._cond_embs([("t", f"more {i}")])
    assert ("keep me",) in embedding_router._cache
