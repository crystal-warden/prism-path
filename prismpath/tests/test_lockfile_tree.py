# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Tranche 5 of item #4: a parent lock pins its child locks (composition tree pinning — hard part 1).

Stub embedder throughout (no model), reusing the pattern from test_lockfile.py: the point here is the
TREE logic (recursive build, child pins, drift detection), not the embedding numerics.
"""
import numpy as np
import pytest

from prismpath import embedder, lockfile


def make_stub(tag=""):
    def stub(texts, is_query=False):
        out = []
        for t in texts:
            h = abs(hash(tag + t)) % (2 ** 31)
            v = np.random.RandomState(h).randn(8).astype("float32")
            out.append(v / np.linalg.norm(v))
        return np.asarray(out, dtype="float32")
    return stub


@pytest.fixture
def stub_embedder(monkeypatch):
    monkeypatch.setattr(embedder, "embed", make_stub())
    monkeypatch.setattr(embedder, "MODEL_NAME", "stub-embedder-v1")
    return embedder


PARENT = """---
name: parent
start: dispatch
---

## dispatch
Fan out one review per file.
@spawn(child=child.md, join=all_done)
-> aggregate: the reviews are all in

## aggregate
Combine.
"""

CHILD = """---
name: child
start: review
---

## review
Review one file — decide pass or fail.
-> pass_: it looks correct
-> fail_: it has a defect

## pass_
Passed.

## fail_
Failed.
"""


def _tree(tmp_path):
    (tmp_path / "parent.md").write_text(PARENT)
    (tmp_path / "child.md").write_text(CHILD)
    return tmp_path / "parent.md", tmp_path / "child.md"


def test_lock_tree_pins_child_and_saves_child_lock(tmp_path, stub_embedder):
    parent, child = _tree(tmp_path)
    lock = lockfile.lock_tree(str(parent))
    lockfile.save_lock(str(parent), lock)
    # the child's own lock was written by lock_tree...
    assert (tmp_path / "child.lock").exists()
    # ...and the parent records a pin for it (flow_hash + lock_hash)
    assert "child.md" in lock["children"]
    pin = lock["children"]["child.md"]
    assert pin["flow_hash"].startswith("sha256:") and pin["lock_hash"].startswith("sha256:")


def test_verify_tree_passes_for_a_freshly_locked_tree(tmp_path, stub_embedder):
    parent, child = _tree(tmp_path)
    lockfile.save_lock(str(parent), lockfile.lock_tree(str(parent)))
    assert lockfile.verify_tree(str(parent)) is True


def test_editing_the_child_flow_is_detected(tmp_path, stub_embedder):
    parent, child = _tree(tmp_path)
    lockfile.save_lock(str(parent), lockfile.lock_tree(str(parent)))
    # edit the child .md WITHOUT relocking -> the live child hash no longer matches the parent's pin
    child.write_text(CHILD + "\n## extra\nAn added node.\n")
    with pytest.raises(lockfile.LockError):
        lockfile.verify_tree(str(parent), policy="refuse")
    assert lockfile.verify_tree(str(parent), policy="allow") is False   # policy-controlled, like verify_lock


def test_relocking_the_child_with_a_different_embedder_is_detected(tmp_path, stub_embedder, monkeypatch):
    parent, child = _tree(tmp_path)
    lockfile.save_lock(str(parent), lockfile.lock_tree(str(parent)))
    # a different embedder build relocks the CHILD only -> its lock_hash diverges from the parent's pin
    monkeypatch.setattr(embedder, "embed", make_stub(tag="v2"))
    lockfile.save_lock(str(child), lockfile.build_lock(str(child)))
    assert lockfile.verify_tree(str(parent), policy="allow") is False


def test_missing_child_lock_is_detected(tmp_path, stub_embedder):
    parent, child = _tree(tmp_path)
    lockfile.save_lock(str(parent), lockfile.lock_tree(str(parent)))
    (tmp_path / "child.lock").unlink()                       # child lock deleted
    assert lockfile.verify_tree(str(parent), policy="allow") is False


def test_childless_flow_locks_and_verifies_like_before(tmp_path, stub_embedder):
    flow = tmp_path / "solo.md"
    flow.write_text(CHILD)                                   # no @spawn -> no children map
    lock = lockfile.lock_tree(str(flow))
    assert "children" not in lock
    lockfile.save_lock(str(flow), lock)
    assert lockfile.verify_tree(str(flow)) is True


def test_lock_tree_detects_a_cycle(tmp_path, stub_embedder):
    # parent -> child -> parent : a cyclic composition must be rejected, not infinite-loop
    (tmp_path / "a.md").write_text("""---
name: a
start: go
---

## go
@spawn(child=b.md, join=all_done)
-> done: on event all_done

## done
Done.
""")
    (tmp_path / "b.md").write_text("""---
name: b
start: go
---

## go
@spawn(child=a.md, join=all_done)
-> done: on event all_done

## done
Done.
""")
    with pytest.raises(lockfile.LockError):
        lockfile.lock_tree(str(tmp_path / "a.md"))


# --- learned-routing pins (follow-on to item #2): centroids committed in the lock ---------
FLOW_SEM = """---
name: sem
start: route
---

## route
Route the outcome.
-> good: the change is correct and complete
-> bad: the change is broken or incomplete

## good
Done.

## bad
Done.
"""


def test_centroids_are_pinned_shrunk_and_preferred(tmp_path, stub_embedder):
    import numpy as np
    flow = tmp_path / "sem.md"
    flow.write_text(FLOW_SEM)
    cond = "the change is correct and complete"
    centroid = np.zeros(8, dtype="float32"); centroid[0] = 1.0
    lock = lockfile.build_lock(str(flow), centroids={cond: centroid}, centroid_counts={cond: 12},
                               prior_weight=4.0)
    assert cond in lock["centroids"] and lock["centroids"][cond]["n"] == 12
    assert lock["centroid_prior_weight"] == 4.0
    # the pinned vector is the SHRUNK blend, unit-normalized — not the raw centroid
    pinned = lockfile._decode_vec(lock["centroids"][cond]["vec"])
    zero_shot = lockfile._decode_vec(lock["conditions"][cond])
    expect = 4.0 * zero_shot + 12 * centroid
    expect = expect / np.linalg.norm(expect)
    assert np.allclose(pinned, expect, atol=1e-6)
    assert not np.allclose(pinned, zero_shot, atol=1e-3)
    # locked_conditions prefers the centroid; opt-out returns zero-shot
    assert np.allclose(lockfile.locked_conditions(lock)[cond], pinned, atol=1e-6)
    assert np.allclose(lockfile.locked_conditions(lock, prefer_centroids=False)[cond],
                       zero_shot, atol=1e-6)
    # the other condition (no labeled data) stays zero-shot
    other = "the change is broken or incomplete"
    assert np.allclose(lockfile.locked_conditions(lock)[other],
                       lockfile._decode_vec(lock["conditions"][other]), atol=1e-6)


def test_lock_without_centroids_has_no_section(tmp_path, stub_embedder):
    flow = tmp_path / "sem.md"
    flow.write_text(FLOW_SEM)
    lock = lockfile.build_lock(str(flow))
    assert "centroids" not in lock                       # backward-compatible lock shape


def test_pinned_centroids_round_trip_and_route(tmp_path, stub_embedder):
    import numpy as np
    flow = tmp_path / "sem.md"
    flow.write_text(FLOW_SEM)
    cond = "the change is correct and complete"
    centroid = np.zeros(8, dtype="float32"); centroid[0] = 1.0
    lock = lockfile.build_lock(str(flow), centroids={cond: centroid}, centroid_counts={cond: 50})
    path = lockfile.save_lock(str(flow), lock)
    loaded = lockfile.load_lock(path)
    router = lockfile.locked_router(loaded, verify=False)
    # with n=50 the pinned vector is dominated by the centroid (~e0); an outcome embedding IS the
    # centroid direction under the stub? No — the stub hashes text; instead just assert routing runs
    # against the pinned vectors without needing the corpus or recomputation.
    d = router.route("some outcome text", [("good", cond), ("bad", "the change is broken or incomplete")])
    assert d.target in ("good", "bad") and "score" in d.info


def test_lock_records_provider_identity_and_verify_checks_it(tmp_path, stub_embedder, monkeypatch):
    flow = tmp_path / "sem.md"
    flow.write_text(FLOW_SEM)
    lock = lockfile.build_lock(str(flow))
    assert lock["embedder"]["provider"] == "sentence-transformers"
    assert lock["embedder"]["precision"] == "fp32"
    assert lockfile.verify_lock(lock, policy="allow") is True
    # same model + probe, DIFFERENT precision -> a different numeric contract -> drift
    monkeypatch.setattr(embedder, "PRECISION", "int8", raising=False)
    assert lockfile.verify_lock(lock, policy="allow") is False
    # a legacy lock without the fields is not blocked (back-compat)
    legacy = {k: (dict(v) if isinstance(v, dict) else v) for k, v in lock.items()}
    legacy["embedder"] = {k: v for k, v in lock["embedder"].items()
                          if k not in ("provider", "precision")}
    assert lockfile.verify_lock(legacy, policy="allow") is True
