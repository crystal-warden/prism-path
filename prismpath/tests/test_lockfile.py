"""Routing-lockfile tests (the reproducibility moat).

Most run with a STUB embedder (monkeypatched — no model, CI-safe): they exercise build/verify/route
logic. One real-model test (importorskip sentence_transformers) proves committed vectors give
bit-for-bit reproducible routing.
"""
import hashlib

import numpy as np
import pytest

from prismpath import embedder, lockfile
from prismpath.parser import parse
from prismpath.router import LockedEmbeddingRouter, HybridRouter, LLMRouter

FLOW = """---
name: triage
start: classify
---
## classify
Decide what kind of request this is.
-> bug: the customer is reporting something broken
-> billing: the message is about payment or refunds
-> other: anything else
## bug
-> done: when always
## billing
-> done: when always
## other
-> done: when always
## done
"""


def _unit(v):
    v = np.asarray(v, dtype="float32")
    n = np.linalg.norm(v)
    return v / n if n else v


def make_stub(vecmap=None, dim=8, tag=""):
    """Deterministic embedder: known texts map to fixed vectors; everything else hashes to one.
    `tag` perturbs the hash so two stubs model 'different embedder builds'."""
    vecmap = {k: _unit(v) for k, v in (vecmap or {}).items()}

    def stub(texts, is_query=False):
        out = []
        for t in texts:
            if t in vecmap:
                out.append(vecmap[t])
                continue
            h = hashlib.sha256((tag + ("q" if is_query else "p") + t).encode()).digest()
            out.append(_unit(np.frombuffer(h[:dim * 2], dtype="<u2").astype("float32")))
        return np.asarray(out, dtype="float32")
    return stub


@pytest.fixture
def stub_embedder(monkeypatch):
    monkeypatch.setattr(embedder, "embed", make_stub())
    monkeypatch.setattr(embedder, "MODEL_NAME", "stub-embedder-v1")
    return embedder


# --- encoding / structure ---------------------------------------------------------------

def test_vector_roundtrip_is_bit_exact():
    v = np.array([0.1, -0.2, 0.333333, 1e-7, -3.5], dtype="float32")
    back = lockfile._decode_vec(lockfile._encode_vec(v))
    assert np.array_equal(v, back)


def test_build_lock_structure(tmp_path, stub_embedder):
    flow = tmp_path / "triage.md"
    flow.write_text(FLOW)
    lock = lockfile.build_lock(str(flow))
    assert lock["version"] == lockfile.LOCK_VERSION and lock["flow"] == "triage"
    assert lock["embedder"]["name"] == "stub-embedder-v1"
    # exactly the three semantic conditions are committed (deterministic `when always` excluded)
    assert set(lock["conditions"]) == {
        "the customer is reporting something broken",
        "the message is about payment or refunds",
        "anything else"}
    assert lock["flow_hash"].startswith("sha256:") and lock["delta"] == 0.05


def test_save_load_roundtrip(tmp_path, stub_embedder):
    flow = tmp_path / "triage.md"
    flow.write_text(FLOW)
    path = lockfile.save_lock(str(flow), lockfile.build_lock(str(flow)))
    assert path == str(tmp_path / "triage.lock")
    lock = lockfile.load_lock(path)
    conds = lockfile.locked_conditions(lock)
    assert set(conds) == set(lock["conditions"]) and all(v.dtype == np.float32 for v in conds.values())


# --- verification (drift detection) -----------------------------------------------------

def test_verify_passes_when_embedder_matches(tmp_path, stub_embedder):
    flow = tmp_path / "triage.md"
    flow.write_text(FLOW)
    lock = lockfile.build_lock(str(flow))
    assert lockfile.verify_lock(lock) is True
    assert lockfile.probe_cosine(lock) == pytest.approx(1.0, abs=1e-6)


def test_locked_router_composes_locked_vectors_with_calibrated_tau(tmp_path, stub_embedder):
    from prismpath.router import LLMRouter
    flow = tmp_path / "triage.md"
    flow.write_text(FLOW)
    lock = lockfile.build_lock(str(flow), delta=0.05)     # lock commits δ=0.05
    # precedence: a calibrated τ overrides the lock's δ for escalation; the lock still governs vectors
    r = lockfile.locked_router(lock, LLMRouter(lambda p: "1"), margin=0.20)
    assert r.margin == 0.20                                # τ wins over the lock's δ
    from prismpath.router import LockedEmbeddingRouter
    assert isinstance(r.embed, LockedEmbeddingRouter)      # vectors still come from the lock
    # no override -> falls back to the lock's committed δ
    r2 = lockfile.locked_router(lock, LLMRouter(lambda p: "1"))
    assert r2.margin == 0.05


def test_verify_refuses_on_embedder_drift(tmp_path, monkeypatch):
    flow = tmp_path / "triage.md"
    flow.write_text(FLOW)
    monkeypatch.setattr(embedder, "embed", make_stub(tag="v1"))
    monkeypatch.setattr(embedder, "MODEL_NAME", "stub-embedder-v1")
    lock = lockfile.build_lock(str(flow))
    # a different embedder build: different probe numerics
    monkeypatch.setattr(embedder, "embed", make_stub(tag="v2"))
    monkeypatch.setattr(embedder, "MODEL_NAME", "stub-embedder-v2")
    with pytest.raises(lockfile.LockError):
        lockfile.verify_lock(lock)                     # default policy: refuse
    assert lockfile.verify_lock(lock, policy="allow") is False
    assert lockfile.verify_lock(lock, policy="warn") is False


# --- routing against committed vectors --------------------------------------------------

def test_locked_router_uses_committed_vectors(monkeypatch):
    conds = {"cond a": _unit([1, 0, 0]), "cond b": _unit([0, 1, 0])}
    # outcome embeds (as query) close to cond a
    monkeypatch.setattr(embedder, "embed", make_stub({"outcome-a": [0.9, 0.1, 0]}))
    r = LockedEmbeddingRouter(conds)
    d = r.route("outcome-a", [("A", "cond a"), ("B", "cond b")])
    assert d.target == "A" and d.info["locked"] is True


def test_locked_router_flags_missing_condition(monkeypatch):
    monkeypatch.setattr(embedder, "embed", make_stub())
    r = LockedEmbeddingRouter({"cond a": _unit([1, 0, 0])})
    with pytest.raises(KeyError):
        r.route("x", [("A", "cond a"), ("B", "cond NOT in lock")])


def test_hybrid_accepts_locked_embed_router(monkeypatch):
    conds = {"cond a": _unit([1, 0, 0]), "cond b": _unit([0, 1, 0])}
    monkeypatch.setattr(embedder, "embed", make_stub({"o": [0.95, 0.05, 0]}))
    h = HybridRouter(LLMRouter(lambda p: "1"), embed=LockedEmbeddingRouter(conds))
    d = h.route("o", [("A", "cond a"), ("B", "cond b")])
    assert d.target == "A" and d.info["escalated"] is False and d.info["locked"] is True


def test_locked_router_builds_hybrid_at_locked_delta(tmp_path, stub_embedder):
    flow = tmp_path / "triage.md"
    flow.write_text(FLOW)
    lock = lockfile.build_lock(str(flow))
    lock["delta"] = 0.11
    h = lockfile.locked_router(lock, llm_router=LLMRouter(lambda p: "1"))
    assert isinstance(h, HybridRouter) and h.margin == 0.11
    assert isinstance(h.embed, LockedEmbeddingRouter)


# --- the real thing: reproducible routing with the actual embedder ----------------------

def test_committed_vectors_reproduce_live_routing():
    pytest.importorskip("sentence_transformers", reason="needs the real bge embedder")
    from prismpath.router import EmbeddingRouter
    g = parse(FLOW)
    import tempfile, os
    d = tempfile.mkdtemp()
    fp = os.path.join(d, "triage.md")
    open(fp, "w").write(FLOW)
    lock = lockfile.build_lock(fp)
    assert lockfile.verify_lock(lock) is True                       # same machine reproduces
    edges = g.nodes["classify"].edges
    outcome = "the app crashes when I click save"
    live = EmbeddingRouter().route(outcome, edges)
    locked = lockfile.locked_router(lock).route(outcome, edges)
    assert live.target == locked.target
    assert live.info["score"] == pytest.approx(locked.info["score"], abs=1e-6)   # bit-for-bit
