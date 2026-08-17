# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""lockfile.py — the routing lockfile: package-lock.json for control flow.

Semantic routing is a function of the embedder's exact numerics. A model update, a different ONNX
build, even hardware float differences can shift a margin across δ — and the flow's routing changes
with no diff anywhere. For a system whose pitch is auditability, that is a hole. The lockfile closes
it: `prismpath lock <flow>` writes `<flow>.lock` committing

  * every semantic condition's embedding vector (base64 float32 — bit-exact, diffable-as-data),
  * the embedder's identity AND a fingerprint (a fixed probe sentence's embedding), and
  * δ and a hash of the flow itself.

At runtime, `LockedEmbeddingRouter` routes conditions against the committed vectors (so the
condition side is bit-for-bit reproducible), and `verify_lock` checks the local embedder still
reproduces the fingerprint — turning silent routing drift into a loud, policy-controlled signal.
That converts semantic routing from a compliance liability into a compliance *feature*: the routing
behavior is pinned, reproducible across machines and years, and any embedder change is detected.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Optional

import numpy as np

LOCK_VERSION = 1
DEFAULT_DELTA = 0.05                 # mirrors HybridRouter's default margin
LOCK_COSINE_MIN = 0.9999            # probe cosine below this ⇒ the embedder drifted
_PROBE = "prismpath routing lockfile embedder fingerprint probe sentence"


class LockError(Exception):
    pass


# --- vector + flow encoding -------------------------------------------------------------
def _encode_vec(v) -> str:
    return base64.b64encode(np.asarray(v, dtype="<f4").tobytes()).decode("ascii")


def _decode_vec(s: str) -> np.ndarray:
    return np.frombuffer(base64.b64decode(s), dtype="<f4").astype("float32")


def _flow_hash(flow_path) -> str:
    with open(flow_path, "rb") as f:
        return "sha256:" + hashlib.sha256(f.read()).hexdigest()


def lock_path(flow_path) -> str:
    """`flows/bugfix.md` -> `flows/bugfix.lock`."""
    return os.path.splitext(os.fspath(flow_path))[0] + ".lock"


# --- build / io -------------------------------------------------------------------------
def _semantic_conditions(graph) -> list:
    from prismpath import predicates
    conds = set()
    for n in graph.nodes.values():
        for _, c in n.edges:
            if not predicates.is_deterministic(c):
                conds.add(c)
    return sorted(conds)


def build_lock(flow_path, delta: Optional[float] = None, centroids: Optional[dict] = None,
               centroid_counts: Optional[dict] = None, prior_weight: float = 4.0) -> dict:
    """Embed every semantic condition + the fingerprint probe with the LOCAL embedder and return a
    lock dict. (Loads the embedder — this is a build-time command.)

    `centroids` (follow-on to roadmap item #2) pins LEARNED routing: {condition: unit mean-vector of
    historical correct outcomes} from `centroid.build_centroids`. Each pinned condition commits the
    SHRUNK vector — the same James-Stein blend CentroidRouter applies at runtime,
    unit(prior_weight·condition + n·centroid) with `n` from `centroid_counts` — so the measured
    accuracy gain (+0.14 ALL / +0.23 polarity on the benchmark) becomes bit-for-bit reproducible:
    `locked_router` routes against these exact vectors, no corpus or recomputation at runtime."""
    from prismpath import embedder
    from prismpath.parser import parse_file
    graph = parse_file(flow_path)
    conds = _semantic_conditions(graph)
    vecs = embedder.embed(conds, is_query=False) if conds else np.zeros((0, 0), dtype="float32")
    probe_vec = embedder.embed([_PROBE], is_query=False)[0]
    dim = int(vecs.shape[1]) if conds else int(probe_vec.shape[0])
    lock = {
        "version": LOCK_VERSION,
        "flow": graph.name,
        "flow_hash": _flow_hash(flow_path),
        "embedder": {
            "name": getattr(embedder, "MODEL_NAME", "unknown"),
            "device": getattr(embedder, "EMBED_DEVICE", "unknown"),
            # A lock is per-(model, provider, precision): the SAME weights under PyTorch fp32,
            # ONNX fp32, or a quantized WASM build produce slightly different vectors, and the
            # probe fingerprint will (correctly) refuse across them. Recording the provider
            # identity makes that boundary explicit instead of a mysterious drift failure.
            "provider": getattr(embedder, "PROVIDER", "sentence-transformers"),
            "precision": getattr(embedder, "PRECISION", "fp32"),
            "dim": dim,
            "probe": _PROBE,
            "probe_vec": _encode_vec(probe_vec),
        },
        "delta": DEFAULT_DELTA if delta is None else float(delta),
        "conditions": {c: _encode_vec(vecs[i]) for i, c in enumerate(conds)},
    }
    if centroids:
        pinned = {}
        counts = centroid_counts or {}
        for i, c in enumerate(conds):
            cen = centroids.get(c)
            if cen is None:
                continue
            n = int(counts.get(c, 1))
            blend = float(prior_weight) * vecs[i] + n * np.asarray(cen, dtype="float32")
            norm = np.linalg.norm(blend) or 1.0
            pinned[c] = {"vec": _encode_vec(blend / norm), "n": n}
        if pinned:
            lock["centroids"] = pinned
            lock["centroid_prior_weight"] = float(prior_weight)
    return lock


def save_lock(flow_path, lock: dict) -> str:
    path = lock_path(flow_path)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(lock, f, indent=2, sort_keys=True)
    os.replace(tmp, path)
    return path


def load_lock(path) -> dict:
    with open(path, encoding="utf-8") as f:
        lock = json.load(f)
    if lock.get("version") != LOCK_VERSION:
        raise LockError(f"unsupported lock version {lock.get('version')!r} (expected {LOCK_VERSION})")
    return lock


# --- verification -----------------------------------------------------------------------
def probe_cosine(lock: dict) -> float:
    """Cosine between the locked fingerprint probe and the LOCAL embedder's probe embedding.
    ~1.0 ⇒ same numerics; lower ⇒ the embedder drifted."""
    from prismpath import embedder
    locked = _decode_vec(lock["embedder"]["probe_vec"])
    local = embedder.embed([lock["embedder"].get("probe", _PROBE)], is_query=False)[0]
    denom = (np.linalg.norm(locked) * np.linalg.norm(local)) or 1.0
    return float(np.dot(locked, local) / denom)


def verify_lock(lock: dict, policy: Optional[str] = None) -> bool:
    """Verify the local embedder reproduces the lock's fingerprint. Returns True if it matches.
    On mismatch, PRISMPATH_LOCK_POLICY (or `policy`) decides: 'refuse' (default — raise), 'warn'
    (print + return False), 'allow' (silent + return False)."""
    from prismpath import embedder
    policy = (policy or os.environ.get("PRISMPATH_LOCK_POLICY", "refuse")).lower()
    name_ok = getattr(embedder, "MODEL_NAME", None) == lock["embedder"]["name"]
    # provider/precision are part of the lock identity when recorded (older locks lack them and
    # are not blocked): the same model under a different runtime or quantization is a DIFFERENT
    # numeric contract, even before the probe says so.
    emb = lock["embedder"]
    prov_ok = ("provider" not in emb
               or emb["provider"] == getattr(embedder, "PROVIDER", "sentence-transformers"))
    prec_ok = ("precision" not in emb
               or emb["precision"] == getattr(embedder, "PRECISION", "fp32"))
    cos = probe_cosine(lock)
    if name_ok and prov_ok and prec_ok and cos >= LOCK_COSINE_MIN:
        return True
    detail = (f"embedder drift — lock '{emb['name']}' ({emb.get('provider', '?')}/"
              f"{emb.get('precision', '?')}) vs local "
              f"'{getattr(embedder, 'MODEL_NAME', '?')}' "
              f"({getattr(embedder, 'PROVIDER', 'sentence-transformers')}/"
              f"{getattr(embedder, 'PRECISION', 'fp32')}), probe cosine {cos:.6f} "
              f"(need ≥ {LOCK_COSINE_MIN})")
    if policy == "allow":
        return False
    if policy == "warn":
        print(f"  [lock] WARNING: {detail} — routing may differ from the committed vectors")
        return False
    raise LockError(detail + " — refusing (set PRISMPATH_LOCK_POLICY=warn or =allow to override)")


# --- composition: a parent lock pins its child locks (roadmap item #4, hard part 1) ----
def _spawn_children(flow_path) -> list:
    """(resolved_child_path, child_ref_as_written) for every `@spawn(child=…)` node in a flow — the
    edges of the composition tree the lock must pin."""
    from prismpath.parser import parse_file
    graph = parse_file(flow_path)
    base = os.path.dirname(os.path.abspath(os.fspath(flow_path)))
    out = []
    for node in graph.nodes.values():
        spawn = node.annotations.get("spawn")
        if spawn and spawn.get("child"):
            child = spawn["child"]
            cpath = child if os.path.isabs(child) else os.path.normpath(os.path.join(base, child))
            out.append((cpath, child))
    return out


def _lock_hash(lock: dict) -> str:
    """Content hash of a lock (canonical JSON) — the pin a parent records for each child, so a child
    relocked or edited after the parent was pinned is detectable. The child's own `children` map is
    included, so the hash captures the whole subtree recursively."""
    return "sha256:" + hashlib.sha256(json.dumps(lock, sort_keys=True).encode()).hexdigest()


def lock_tree(flow_path, delta: Optional[float] = None, centroids: Optional[dict] = None,
              centroid_counts: Optional[dict] = None, prior_weight: float = 4.0, _seen=None) -> dict:
    """Recursively build AND SAVE a lock for every `@spawn` child (post-order), then build the parent
    lock recording each child's `{flow_hash, lock_hash}` in a `children` map — so `prismpath lock` pins the
    WHOLE composition tree in one shot. Returns the parent lock (unsaved — the caller saves it, matching
    build_lock). Childless flows return exactly what build_lock returns. Cyclic compositions raise.
    `centroids` (learned routing pins) apply to the ROOT flow only — children pin zero-shot unless
    locked separately with their own labeled data."""
    _seen = _seen or set()
    ap = os.path.abspath(os.fspath(flow_path))
    if ap in _seen:
        raise LockError(f"cyclic composition at {flow_path!r} — a flow spawns itself transitively")
    seen2 = _seen | {ap}
    children = {}
    for cpath, cref in _spawn_children(flow_path):
        if not os.path.exists(cpath):
            raise LockError(f"@spawn child {cref!r} not found at {cpath} — cannot lock the tree")
        child_lock = lock_tree(cpath, delta=delta, _seen=seen2)
        save_lock(cpath, child_lock)
        children[cref] = {"flow_hash": child_lock["flow_hash"], "lock_hash": _lock_hash(child_lock)}
    lock = build_lock(flow_path, delta=delta, centroids=centroids,
                      centroid_counts=centroid_counts, prior_weight=prior_weight)
    if children:
        lock["children"] = children
    return lock


def _tree_fail(detail: str, policy: Optional[str]) -> None:
    policy = (policy or os.environ.get("PRISMPATH_LOCK_POLICY", "refuse")).lower()
    if policy == "allow":
        return
    if policy == "warn":
        print(f"  [lock] WARNING: composition drift — {detail}")
        return
    raise LockError(f"composition lock drift — {detail} "
                    f"(set PRISMPATH_LOCK_POLICY=warn or =allow to override)")


def verify_tree(flow_path, policy: Optional[str] = None) -> bool:
    """Verify a flow's lock AND recursively every pinned child lock. Per child it checks: the child lock
    file exists; its content still hashes to the pinned `lock_hash` and its flow to the pinned
    `flow_hash` (a child edited or relocked after the parent was pinned is caught); and the child's own
    fingerprint verifies. Returns True iff the whole tree verifies. Same refuse/warn/allow policy as
    verify_lock."""
    lock = load_lock(lock_path(flow_path))
    ok = verify_lock(lock, policy)
    base = os.path.dirname(os.path.abspath(os.fspath(flow_path)))
    for cref, pin in (lock.get("children") or {}).items():
        cpath = cref if os.path.isabs(cref) else os.path.normpath(os.path.join(base, cref))
        clp = lock_path(cpath)
        if not os.path.exists(clp):
            _tree_fail(f"child lock {clp} missing (re-run `prismpath lock` on the parent)", policy)
            ok = False
            continue
        child_lock = load_lock(clp)
        # child RELOCKED since pinning (different embedder / δ / conditions)?
        if _lock_hash(child_lock) != pin.get("lock_hash"):
            _tree_fail(f"child {cref!r} lock changed since the parent was pinned", policy)
            ok = False
        # child .md EDITED since pinning? compare the LIVE file, not the (possibly stale) child lock —
        # an edit without a relock must still be caught.
        if os.path.exists(cpath) and _flow_hash(cpath) != pin.get("flow_hash"):
            _tree_fail(f"child {cref!r} flow file changed since the parent was pinned", policy)
            ok = False
        ok = verify_tree(cpath, policy) and ok        # recurse into grandchildren
    return ok


def locked_conditions(lock: dict, prefer_centroids: bool = True) -> dict:
    """{condition_text -> committed unit vector} for LockedEmbeddingRouter. When the lock pins
    centroids (learned routing) they take precedence over the zero-shot condition vectors — that IS
    the point of pinning them; pass prefer_centroids=False to route zero-shot regardless."""
    out = {text: _decode_vec(b64) for text, b64 in lock["conditions"].items()}
    if prefer_centroids:
        for text, pin in (lock.get("centroids") or {}).items():
            out[text] = _decode_vec(pin["vec"])
    return out


def locked_router(lock: dict, llm_router=None, verify: bool = True, policy: Optional[str] = None,
                  margin: Optional[float] = None):
    """Build a router that uses the lock's committed condition vectors. With `llm_router`, returns a
    HybridRouter; without, a bare LockedEmbeddingRouter.

    Precedence when a lock (δ) AND a calibration (τ) both exist — they govern DIFFERENT things and
    compose rather than conflict: the **lock governs the embedding vectors** (reproducibility), the
    **escalation threshold** is `margin` if given else the lock's δ. To run locked vectors at a
    risk-controlled τ, pass `margin=cal["tau"]` (i.e. compose, don't choose). `lock --check` verifies
    only the embedder fingerprint, never τ/δ — the threshold is a routing knob, not a lock invariant."""
    from prismpath.router import HybridRouter, LockedEmbeddingRouter
    if verify:
        verify_lock(lock, policy)
    ler = LockedEmbeddingRouter(locked_conditions(lock))
    if llm_router is None:
        return ler
    thresh = margin if margin is not None else lock.get("delta", DEFAULT_DELTA)
    return HybridRouter(llm_router, margin=thresh, embed=ler)
