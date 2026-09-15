# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Shadow-sampling / self-policing tests for PrefilterCache (item #3).

Same stub-embedder discipline as test_prefilter.py: no model, no torch, no network. These exercise
the cache's *continuous reuse-error* machinery — shadow-sample selection, drift-driven quarantine,
policy-hash auto-invalidation, and the monitor counters — all as pure operations on corpus state.
"""
import json
import random

import numpy as np

from prismpath.routing.prefilter import PrefilterCache

# doc a / doc a again share a direction (cosine 1.0); doc far is orthogonal.
_VECS = {
    "doc a": np.array([1.0, 0.0], dtype="float32"),
    "doc a again": np.array([1.0, 0.0], dtype="float32"),
    "doc far": np.array([0.0, 1.0], dtype="float32"),
}


def stub_embed(texts):
    return np.vstack([_VECS[text] for text in texts])


def make_cache(tmp_path, **kw):
    kw.setdefault("threshold", 0.97)
    kw.setdefault("min_conf", 0.8)
    return PrefilterCache(tmp_path / "corpus", embed_fn=stub_embed, **kw)


# --- policy-hash eligibility -------------------------------------------------------------
def test_policy_hash_matches_and_invalidates(tmp_path):
    cache = make_cache(tmp_path)
    lookup_result = cache.lookup("doc a")
    cache.learn(lookup_result.vector, "contain", 0.95, key="k", policy_hash="p1")
    assert cache.lookup("doc a again", policy_hash="p1").hit is True       # same policy -> reuse
    assert cache.lookup("doc a again", policy_hash="p2").hit is False      # policy edit -> invalidated
    assert cache.lookup("doc a again").hit is True                         # unversioned lookup ignores it


def test_unversioned_entry_is_eligible_under_any_policy(tmp_path):
    # entries learned WITHOUT a policy_hash (existing corpora) stay usable when a caller starts versioning
    cache = make_cache(tmp_path)
    cache.learn("doc a", "contain", 0.95, key="k")                        # no policy_hash
    assert cache.lookup("doc a again", policy_hash="p1").hit is True


# --- shadow-sample selection -------------------------------------------------------------
def test_shadow_flag_requires_hit_and_sample_rate(tmp_path):
    cache = make_cache(tmp_path)
    cache.learn("doc a", "contain", 0.95, key="k")
    assert cache.lookup("doc a again", sample_rate=0.0).shadow is False    # sampling off
    assert cache.lookup("doc a again", sample_rate=1.0, rng=random.Random(0)).shadow is True
    # a MISS is never shadowed even at rate 1.0 (nothing was reused to check)
    assert cache.lookup("doc far", sample_rate=1.0, rng=random.Random(0)).shadow is False


def test_shadow_sampling_is_probabilistic(tmp_path):
    cache = make_cache(tmp_path)
    cache.learn("doc a", "contain", 0.95, key="k")
    rng = random.Random(1234)
    shadow_count = sum(cache.lookup("doc a again", sample_rate=0.25, rng=rng).shadow for _ in range(2000))
    assert 400 < shadow_count < 600                                              # ~25% of 2000, wide band


# --- drift -> quarantine -----------------------------------------------------------------
def test_disagreements_quarantine_after_min_samples(tmp_path):
    cache = make_cache(tmp_path)
    cache.learn("doc a", "contain", 0.95, key="drift")
    o1 = cache.record_shadow("drift", "contain", "escalate")              # 1/1 disagree, min_samples not met
    assert o1["quarantined"] is False and o1["shadow_n"] == 1
    o2 = cache.record_shadow("drift", "contain", "escalate")              # 2/2 -> bound 0.5 met
    assert o2["quarantined"] is True and o2["shadow_n"] == 2
    assert cache.lookup("doc a again").hit is False                       # drifting entry no longer reused


def test_agreements_never_quarantine(tmp_path):
    cache = make_cache(tmp_path)
    cache.learn("doc a", "contain", 0.95, key="stable")
    for _ in range(5):
        assert cache.record_shadow("stable", "contain", "contain")["quarantined"] is False
    assert cache.lookup("doc a again").hit is True
    stats = cache.monitor_stats()
    assert stats["sampled"] == 5 and stats["agreements"] == 5 and stats["reuse_error_rate"] == 0.0


def test_mixed_agreement_below_bound_stays_live(tmp_path):
    # 1 disagree out of 4 = 0.25 < 0.5 bound, and the running rate never reaches 0.5 along the way
    # (agreements first) -> the entry is never quarantined.
    cache = make_cache(tmp_path)
    cache.learn("doc a", "contain", 0.95, key="mixed")
    for _ in range(3):
        cache.record_shadow("mixed", "contain", "contain")               # running rate stays 0.0
    cache.record_shadow("mixed", "contain", "escalate")                  # now 1/4 = 0.25 < 0.5
    assert cache.lookup("doc a again").hit is True
    assert cache.monitor_stats()["reuse_error_rate"] == 0.25


def test_quarantine_is_sticky_and_conservative(tmp_path):
    # Fail-safe: quarantine fires the FIRST moment the running disagreement rate reaches the bound over
    # min_samples, and STAYS — even if later agreements would drag the cumulative rate back down. A
    # false pull just sends one situation back to the LLM tier (cheap); a missed drift keeps reusing a
    # stale verdict (dangerous). So we err toward pulling and require a deliberate re-add.
    cache = make_cache(tmp_path)
    cache.learn("doc a", "contain", 0.95, key="sticky")
    cache.record_shadow("sticky", "contain", "escalate")                 # n=1, 1/1 but min_samples not met
    assert cache.record_shadow("sticky", "contain", "escalate")["quarantined"] is True   # n=2, 2/2 -> pull
    # a run of later agreements does NOT resurrect it
    for _ in range(10):
        cache.record_shadow("sticky", "contain", "contain")
    assert cache.lookup("doc a again").hit is False
    assert cache.monitor_stats()["quarantined_entries"] == 1


# --- monitor counters --------------------------------------------------------------------
def test_monitor_stats_and_reuse_error_rate(tmp_path):
    cache = make_cache(tmp_path)
    cache.learn("doc a", "contain", 0.95, key="k")
    cache.record_shadow("k", "contain", "contain")
    cache.record_shadow("k", "contain", "escalate")
    stats = cache.monitor_stats()
    assert stats["sampled"] == 2 and stats["agreements"] == 1 and stats["disagreements"] == 1
    assert stats["reuse_error_rate"] == 0.5


def test_duplicate_key_quarantines_all_and_counts_them(tmp_path):
    # learn() always appends, so re-learning the same situation yields two records sharing a key. A
    # shadow disagreement must quarantine BOTH, and the lifetime quarantined_total must count both (not
    # collapse them to one) so it stays consistent with quarantined_entries.
    cache = make_cache(tmp_path)
    cache.learn("doc a", "contain", 0.95, key="dup")
    cache.learn("doc a", "contain", 0.95, key="dup")                     # same key, second record
    cache.record_shadow("dup", "contain", "escalate")                    # n=1 each, below min_samples
    outcome = cache.record_shadow("dup", "contain", "escalate")                # n=2 each -> both cross the bound
    assert outcome["quarantined"] is True and outcome["shadow_n"] == 2
    stats = cache.monitor_stats()
    assert stats["quarantined_entries"] == 2 and stats["quarantined_total"] == 2
    assert cache.lookup("doc a again").hit is False                      # both pulled


def test_seeded_rng_is_respected_not_swallowed(tmp_path):
    # a seeded Random must drive selection deterministically (regression: `rng or random` would work for
    # Random(0) since it's truthy, but the guard is now explicit `is not None`).
    cache = make_cache(tmp_path)
    cache.learn("doc a", "contain", 0.95, key="k")
    import random as _r
    seq_a = [cache.lookup("doc a again", sample_rate=0.5, rng=_r.Random(7)).shadow for _ in range(5)]
    seq_b = [cache.lookup("doc a again", sample_rate=0.5, rng=_r.Random(7)).shadow for _ in range(5)]
    assert seq_a == seq_b                                            # same seed -> same decisions


def test_keyless_entry_still_bumps_monitor_but_cannot_quarantine(tmp_path):
    # a keyless comparison contributes to the corpus reuse-error rate but can't pin to an entry
    cache = make_cache(tmp_path)
    cache.learn("doc a", "contain", 0.95)                                 # key=""
    outcome = cache.record_shadow("", "contain", "escalate")
    assert outcome["quarantined"] is False and outcome["shadow_n"] == 0
    stats = cache.monitor_stats()
    assert stats["sampled"] == 1 and stats["disagreements"] == 1 and stats["quarantined_entries"] == 0


def test_monitor_persists_across_instances(tmp_path):
    cache = make_cache(tmp_path)
    cache.learn("doc a", "contain", 0.95, key="k")
    cache.record_shadow("k", "contain", "escalate")
    c2 = make_cache(tmp_path)                                         # fresh instance, same dir
    assert c2.monitor_stats()["sampled"] == 1
    assert (c2.dir / "monitor.json").exists()


# --- manual quarantine -------------------------------------------------------------------
def test_manual_quarantine_is_idempotent_and_pulls_entry(tmp_path):
    cache = make_cache(tmp_path)
    cache.learn("doc a", "contain", 0.95, key="pull")
    assert cache.lookup("doc a again").hit is True
    assert cache.quarantine("pull", reason="operator reversed") == 1
    assert cache.quarantine("pull") == 0                                  # already quarantined
    assert cache.lookup("doc a again").hit is False
    # the lifetime monitor counter is untouched by a manual pull (it tracks shadow samples)
    assert cache.monitor_stats()["quarantined_entries"] == 1


def test_quarantine_survives_reload_and_shows_reason(tmp_path):
    cache = make_cache(tmp_path)
    cache.learn("doc a", "contain", 0.95, key="pull")
    cache.quarantine("pull", reason="bad downgrade")
    meta = json.loads((cache.dir / "meta.json").read_text())
    assert meta[0]["quarantined"] is True and meta[0]["quarantine_reason"] == "bad downgrade"
    assert make_cache(tmp_path).lookup("doc a again").hit is False    # persists


# --- windowed drift (follow-on to item #3): stable-then-drifting entries pull fast --------
def test_long_stable_entry_quarantines_on_window_not_lifetime(tmp_path):
    # 20 agreements, then drift. Cumulative rate would need ~20 disagreements to reach 0.5;
    # the window (8) pulls it after 4 recent disagreements (4/8 = 0.5). Detection lag ~window.
    cache = make_cache(tmp_path)
    cache.learn("doc a", "contain", 0.95, key="aged")
    for _ in range(20):
        assert cache.record_shadow("aged", "contain", "contain")["quarantined"] is False
    outs = [cache.record_shadow("aged", "contain", "escalate") for _ in range(4)]
    assert [outcome["quarantined"] for outcome in outs] == [False, False, False, True]
    assert cache.lookup("doc a again").hit is False
    _, meta = cache.load()
    assert "window drift" in meta[0]["quarantine_reason"]


def test_window_is_bounded_in_the_record(tmp_path):
    cache = make_cache(tmp_path)
    cache.learn("doc a", "contain", 0.95, key="k")
    for _ in range(30):
        cache.record_shadow("k", "contain", "contain", window=8)
    _, meta = cache.load()
    assert len(meta[0]["shadow_recent"]) == 8            # trimmed, not unbounded


def test_sparse_disagreement_in_established_history_stays_live(tmp_path):
    # a lone disagreement inside a long stable run: at that point the window is [0,0,0,0,0,1]
    # (1/6 < 0.5) and the cumulative rate 1/6 < 0.5 — the entry stays live, and the window
    # flushes the blip out entirely as more agreements arrive.
    cache = make_cache(tmp_path)
    cache.learn("doc a", "contain", 0.95, key="k")
    for _ in range(5):
        cache.record_shadow("k", "contain", "contain")
    assert cache.record_shadow("k", "contain", "escalate")["quarantined"] is False   # the blip
    for _ in range(10):
        assert cache.record_shadow("k", "contain", "contain")["quarantined"] is False
    assert cache.lookup("doc a again").hit is True
    _, meta = cache.load()
    assert sum(meta[0]["shadow_recent"]) == 0            # blip flushed from the window
