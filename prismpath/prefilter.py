"""prefilter.py — decision memoization for expensive agent calls (the cache tier).

The routing spectrum resolves *transitions* cheaply; this module makes the expensive
*node* cheap. A `PrefilterCache` stores prior adjudications — (document → verdict)
pairs — as L2-normalized embeddings plus metadata. Before an expensive call (an LLM
classification, a slow judge), look the incoming document up: a near-identical prior
(cosine ≥ `threshold`) whose stored verdict carries `confidence ≥ min_conf` is a HIT
— reuse the verdict and skip the call entirely. On a miss, make the call, then
`learn()` the fresh verdict so the next near-identical input hits. The cache
compounds: measured live on SOC alert triage, ~59% of alerts auto-resolved at
threshold 0.97 (streaming, self-learning) — a ~2.4× capacity gain before the LLM
tier is touched.

Design:
  * PLUGGABLE embedder. `embed_fn(list[str]) -> [n, d] float32, unit-normalized` is
    the single swap point — the default is a small sentence-transformers model
    (BAAI/bge-small-en-v1.5) on GPU, falling back to CPU on any load failure (the
    model is tiny). Any modality encoder satisfying the contract can feed the same
    gate (e.g. a traffic encoder for network flows).
  * CORPUS = embeddings.npy + meta.json under a directory you choose. Records are
    {"action", "confidence", "key", "description"}; legacy field names
    ("recommended_action"/"alert_key") are migrated on load.
  * The gate is two thresholds, both must pass: similarity (is this the same
    situation?) and stored confidence (was the prior verdict trustworthy?).

Import-safe (no model load at import; the default embedder loads lazily on first
use). Inspect a corpus from the shell:
  python -m prismpath.prefilter info <corpus-dir>
"""
from __future__ import annotations

import json
import os
import random
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

import numpy as np

DEFAULT_THRESHOLD = float(os.environ.get("PREFILTER_THRESHOLD", "0.97"))
DEFAULT_MIN_CONF = float(os.environ.get("PREFILTER_MIN_CONF", "0.8"))
EMBED_MODEL = os.environ.get("PREFILTER_EMBED_MODEL", "BAAI/bge-small-en-v1.5")
EMBED_DEVICE = os.environ.get("PREFILTER_EMBED_DEVICE", "cuda")  # cuda|cpu; OOM -> cpu

_model = None


def _load_model():
    """Load the default sentence-transformers model once. GPU by default; on CUDA
    OOM (or any init failure) log it and fall back to CPU — the model is tiny."""
    global _model
    if _model is not None:
        return _model
    from sentence_transformers import SentenceTransformer
    try:
        _model = SentenceTransformer(EMBED_MODEL, device=EMBED_DEVICE)
    except Exception as e:  # noqa: BLE001 - broad on purpose (CUDA OOM/init)
        print(f"  [prefilter] embedder load on '{EMBED_DEVICE}' failed ({e!r}); "
              f"falling back to CPU")
        _model = SentenceTransformer(EMBED_MODEL, device="cpu")
    return _model


def default_embed_fn(texts: List[str]) -> np.ndarray:
    """The default embedder: `list[str] -> [n, d] unit-normalized float32`. THE swap
    point — pass any callable with this contract as `PrefilterCache(embed_fn=...)`
    to plug in a different modality encoder."""
    m = _load_model()
    v = m.encode(list(texts), normalize_embeddings=True, show_progress_bar=False,
                 batch_size=64)
    return np.asarray(v, dtype="float32")


def _normalize(vec: np.ndarray) -> np.ndarray:
    v = np.asarray(vec, dtype="float32").reshape(-1)
    n = np.linalg.norm(v)
    return v / n if n > 0 else v


def _migrate(record: dict) -> dict:
    """Accept legacy field names from corpora written before the generic API."""
    if "action" not in record and "recommended_action" in record:
        record["action"] = record.pop("recommended_action")
    if "key" not in record and "alert_key" in record:
        record["key"] = record.pop("alert_key")
    record.setdefault("action", "")
    record.setdefault("confidence", 0.0)
    record.setdefault("key", "")
    record.setdefault("description", "")
    return record


def match_arrays(vec: np.ndarray, emb: np.ndarray, records: list,
                 threshold: float, min_conf: float):
    """Pure-array form of the gate — for offline sweeps over thresholds/corpora
    (see measure_prefilter.py). Returns (hit, record|None, similarity)."""
    if emb.shape[0] == 0:
        return False, None, 0.0
    v = _normalize(vec)
    sims = emb @ v  # both unit-normalized -> cosine
    i = int(np.argmax(sims))
    best_sim = float(sims[i])
    best = records[i]
    hit = best_sim >= threshold and float(best.get("confidence", 0.0)) >= min_conf
    return hit, best, best_sim


@dataclass
class CacheResult:
    """Result of a lookup. `vector` is the query embedding — pass it back to
    `learn()` after adjudication so the document isn't embedded twice. `shadow` is True when this hit
    was selected for a shadow-sample: reuse the verdict AND run the real adjudicator too, then feed the
    comparison to `record_shadow()` — the cache's self-policing signal."""
    hit: bool
    record: Optional[dict]
    similarity: float
    vector: np.ndarray = field(repr=False, default=None)
    shadow: bool = False


class PrefilterCache:
    """A persistent, self-learning verdict cache keyed by embedding similarity.

    cache = PrefilterCache("~/myproj/corpus")          # lazy; no model load yet
    res = cache.lookup(document)
    if res.hit:
        act_on(res.record["action"])                    # expensive call SKIPPED
    else:
        verdict = expensive_adjudication(document)
        act_on(verdict.action)
        cache.learn(res.vector, verdict.action, verdict.confidence,
                    key=stable_key, description=short_desc)
    """

    def __init__(self, dir_path, threshold: float = None, min_conf: float = None,
                 embed_fn: Callable[[List[str]], np.ndarray] = None):
        self.dir = Path(dir_path).expanduser()
        self.threshold = DEFAULT_THRESHOLD if threshold is None else float(threshold)
        self.min_conf = DEFAULT_MIN_CONF if min_conf is None else float(min_conf)
        self.embed_fn = embed_fn or default_embed_fn

    @property
    def _emb_path(self) -> Path:
        return self.dir / "embeddings.npy"

    @property
    def _meta_path(self) -> Path:
        return self.dir / "meta.json"

    # --- store ------------------------------------------------------------------
    def load(self):
        """-> (embeddings [N,d] float32 unit-normalized, records list). Empty if none."""
        if self._emb_path.exists() and self._meta_path.exists():
            emb = np.load(self._emb_path)
            meta = [_migrate(m) for m in json.loads(self._meta_path.read_text())]
            if len(meta) == emb.shape[0] and emb.shape[0] > 0:
                return emb.astype("float32"), meta
        return np.zeros((0, 0), dtype="float32"), []

    def _save(self, emb: np.ndarray, meta: list) -> None:
        # Write both files via temp+rename so a crash mid-save leaves the OLD consistent pair, not a
        # torn one that load() would silently discard (losing a learned corpus). Meta renamed last.
        self.dir.mkdir(parents=True, exist_ok=True)
        emb_tmp = str(self._emb_path) + ".tmp.npy"
        meta_tmp = str(self._meta_path) + ".tmp"
        np.save(emb_tmp, emb.astype("float32"))
        with open(meta_tmp, "w", encoding="utf-8") as f:
            f.write(json.dumps(meta, indent=2))
        os.replace(emb_tmp, self._emb_path)
        os.replace(meta_tmp, self._meta_path)

    def clear(self) -> None:
        self._save(np.zeros((0, 0), dtype="float32"), [])

    def __len__(self) -> int:
        emb, _ = self.load()
        return int(emb.shape[0])

    # --- the gate ----------------------------------------------------------------
    def embed(self, texts: List[str]) -> np.ndarray:
        return self.embed_fn(list(texts))

    def _eligible(self, record: dict, policy_hash: Optional[str]) -> bool:
        """An entry may be reused unless it is quarantined (a shadow-sample found it drifting) or it was
        learned under a DIFFERENT policy hash than the current one — a policy/flow edit thereby
        auto-invalidates stale verdicts. Unversioned (policy_hash=None) entries are always eligible, so
        existing corpora and callers that don't version keep working unchanged."""
        if record.get("quarantined"):
            return False
        if policy_hash is not None and record.get("policy_hash") not in (None, policy_hash):
            return False
        return True

    def match(self, vec: np.ndarray, policy_hash: Optional[str] = None):
        """Cosine-match a pre-embedded vector against the ELIGIBLE corpus (non-quarantined, matching
        policy). Returns (hit, record|None, similarity). A hit requires similarity >= threshold AND the
        matched record's confidence >= min_conf."""
        emb, meta = self.load()
        if emb.shape[0] == 0:
            return False, None, 0.0
        idx = [i for i, m in enumerate(meta) if self._eligible(m, policy_hash)]
        if not idx:
            return False, None, 0.0
        return match_arrays(vec, emb[idx], [meta[i] for i in idx], self.threshold, self.min_conf)

    def lookup(self, doc: str, policy_hash: Optional[str] = None, sample_rate: float = 0.0,
               rng=None) -> CacheResult:
        """Embed `doc` and match it against the eligible corpus. With `sample_rate > 0`, a hit is
        flagged `shadow` with that probability — reuse it AND run the real adjudicator, then call
        `record_shadow()`. The returned `vector` is reusable by `learn()`."""
        vec = self.embed([doc])[0]
        hit, record, sim = self.match(vec, policy_hash=policy_hash)
        r = rng if rng is not None else random   # `rng or random` would swallow a seeded Random(0)-ish
        shadow = bool(hit and sample_rate > 0 and r.random() < sample_rate)
        return CacheResult(hit=hit, record=record, similarity=sim, vector=vec, shadow=shadow)

    # --- the learning loop --------------------------------------------------------
    def learn(self, vec_or_doc, action: str, confidence: float,
              key: str = "", description: str = "", policy_hash: Optional[str] = None) -> None:
        """Append one adjudication so future near-identical documents auto-resolve.
        Accepts either the embedding from a prior `lookup()` (preferred — no
        re-embed) or the raw document string. Guarded by a cross-process lock so concurrent
        streaming learners don't lose updates (the read-modify-write is serialized).

        `policy_hash` stamps the entry with the flow/policy it was adjudicated under. Pass the same
        value to `lookup()`/`match()` later and a policy edit auto-invalidates every verdict learned
        under the old hash — no manual cache purge."""
        if isinstance(vec_or_doc, str):
            v = self.embed([vec_or_doc])[0]
        else:
            v = vec_or_doc
        v = _normalize(v)
        with self._lock():
            emb, meta = self.load()
            emb = v.reshape(1, -1) if emb.shape[0] == 0 else np.vstack([emb, v.reshape(1, -1)])
            rec = {
                "action": action,
                "confidence": float(confidence) if confidence is not None else 0.0,
                "key": key,
                "description": description,
            }
            if policy_hash is not None:
                rec["policy_hash"] = policy_hash
            meta.append(rec)
            self._save(emb, meta)

    def _lock(self):
        """Advisory cross-process lock over the corpus (POSIX flock; a no-op where unavailable)."""
        cache = self

        class _L:
            def __enter__(self):
                self.fh = None
                try:
                    import fcntl
                    cache.dir.mkdir(parents=True, exist_ok=True)
                    self.fh = open(cache.dir / ".lock", "w")
                    fcntl.flock(self.fh, fcntl.LOCK_EX)
                except Exception:                     # noqa: BLE001 - lock is best-effort
                    if self.fh:
                        self.fh.close()
                        self.fh = None
                return self

            def __exit__(self, *a):
                if self.fh:
                    try:
                        import fcntl
                        fcntl.flock(self.fh, fcntl.LOCK_UN)
                    finally:
                        self.fh.close()
        return _L()

    # --- self-policing (shadow sampling) --------------------------------------------
    @property
    def _monitor_path(self) -> Path:
        return self.dir / "monitor.json"

    def record_shadow(self, key: str, reused_action, oracle_action,
                      quarantine_bound: float = 0.5, min_samples: int = 2,
                      window: int = 8) -> dict:
        """Feed one shadow-sample comparison back to the cache — the self-policing signal. `key` is the
        reused entry's stable key (CacheResult.record['key']); `reused_action` is the verdict that WAS
        reused, `oracle_action` the fresh adjudication run in shadow alongside it. Updates the entry's
        running (shadow_n, shadow_disagree) plus a bounded RECENT window, and QUARANTINES it when
        EITHER rate crosses `quarantine_bound` over >= `min_samples` samples:
          * cumulative — shadow_disagree/shadow_n (the lifetime signal), or
          * windowed  — disagreements within the last `window` samples, so an entry that was stable
            for months and THEN drifts is pulled after a few recent disagreements instead of needing
            its lifetime rate dragged over the bound (detection lag ~window, not ~history).
        Thereafter `_eligible()` drops it, so a drifting verdict stops being reused without deleting
        the evidence. Also advances the corpus-level continuous reuse-error counters. A keyless entry
        (key="") can't be pinned to, so only the corpus counters move."""
        agree = str(reused_action) == str(oracle_action)
        q_count = 0                                    # entries quarantined THIS call (>=1 for dup keys)
        n_after = 0
        with self._lock():
            emb, meta = self.load()
            targets = [m for m in meta if m.get("key", "") == key] if key else []
            for m in targets:
                m["shadow_n"] = int(m.get("shadow_n", 0)) + 1
                if not agree:
                    m["shadow_disagree"] = int(m.get("shadow_disagree", 0)) + 1
                recent = list(m.get("shadow_recent", []))
                recent.append(0 if agree else 1)
                m["shadow_recent"] = recent[-max(1, int(window)):]
                n_after = max(n_after, m["shadow_n"])   # dup keys can diverge; report the furthest along
                dis = int(m.get("shadow_disagree", 0))
                win = m["shadow_recent"]
                cum_drift = m["shadow_n"] >= min_samples and dis / m["shadow_n"] >= quarantine_bound
                win_drift = len(win) >= min_samples and sum(win) / len(win) >= quarantine_bound
                if not m.get("quarantined") and (cum_drift or win_drift):
                    m["quarantined"] = True
                    m["quarantine_reason"] = (f"shadow drift {dis}/{m['shadow_n']}" if cum_drift
                                              else f"shadow window drift {sum(win)}/{len(win)} recent")
                    q_count += 1
            if targets:
                self._save(emb, meta)
            # count every entry quarantined this call, so lifetime quarantined_total stays consistent
            # with quarantined_entries when the same key is stored more than once.
            self._bump_monitor(sampled=1, agree=int(agree), disagree=int(not agree),
                               quarantined_now=q_count)
        return {"key": key, "agree": agree, "quarantined": q_count > 0, "shadow_n": n_after}

    def quarantine(self, key: str, reason: str = "manual") -> int:
        """Force-quarantine every entry with `key` (e.g. an operator reversed an unsafe cached
        downgrade — pull it immediately, don't wait for the shadow bound). Idempotent; returns how many
        entries were newly quarantined."""
        n = 0
        with self._lock():
            emb, meta = self.load()
            for m in meta:
                if key and m.get("key", "") == key and not m.get("quarantined"):
                    m["quarantined"] = True
                    m["quarantine_reason"] = reason
                    n += 1
            if n:
                self._save(emb, meta)
        return n

    def _bump_monitor(self, sampled: int, agree: int, disagree: int, quarantined_now: int) -> None:
        """Advance the corpus-level shadow counters in monitor.json. MUST run inside self._lock() (the
        callers do). Kept separate from meta.json so drift is tracked even for corpora whose entries
        never carry a key or policy_hash. Atomic temp+rename."""
        path = self._monitor_path
        cur = {"sampled": 0, "agreements": 0, "disagreements": 0, "quarantined_total": 0}
        if path.exists():
            try:
                cur.update(json.loads(path.read_text()))
            except Exception:                         # noqa: BLE001 - corrupt monitor resets, not fatal
                pass
        cur["sampled"] += sampled
        cur["agreements"] += agree
        cur["disagreements"] += disagree
        cur["quarantined_total"] += quarantined_now
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = str(path) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(json.dumps(cur, indent=2))
        os.replace(tmp, path)

    def monitor_stats(self) -> dict:
        """The continuous reuse-error signal to report ALONGSIDE the hit rate: shadow-sample totals, the
        reuse-error rate (disagreements / sampled), and current vs lifetime quarantines."""
        cur = {"sampled": 0, "agreements": 0, "disagreements": 0, "quarantined_total": 0}
        if self._monitor_path.exists():
            try:
                cur.update(json.loads(self._monitor_path.read_text()))
            except Exception:                         # noqa: BLE001
                pass
        _, meta = self.load()
        q_now = sum(1 for m in meta if m.get("quarantined"))
        rate = cur["disagreements"] / cur["sampled"] if cur["sampled"] else 0.0
        return {"sampled": cur["sampled"], "agreements": cur["agreements"],
                "disagreements": cur["disagreements"], "reuse_error_rate": rate,
                "quarantined_entries": q_now, "quarantined_total": cur["quarantined_total"]}

    # --- introspection --------------------------------------------------------------
    def stats(self) -> dict:
        emb, meta = self.load()
        actions = {}
        for m in meta:
            actions[m["action"]] = actions.get(m["action"], 0) + 1
        return {"entries": int(emb.shape[0]),
                "dim": int(emb.shape[1]) if emb.shape[0] else 0,
                "by_action": actions,
                "threshold": self.threshold, "min_conf": self.min_conf,
                "dir": str(self.dir)}


# --- CLI ------------------------------------------------------------------------------
def _info(dir_path: str) -> None:
    cache = PrefilterCache(dir_path)
    print(json.dumps(cache.stats(), indent=2))
    _, meta = cache.load()
    for m in meta[:20]:
        flag = " QUARANTINED" if m.get("quarantined") else ""
        print(f"  [{m['action']:8s} c={m['confidence']:.2f}] "
              f"{m['key']:40s} {m['description'][:60]}{flag}")


def _monitor(dir_path: str) -> None:
    cache = PrefilterCache(dir_path)
    print(json.dumps(cache.monitor_stats(), indent=2))
    _, meta = cache.load()
    for m in meta:
        if m.get("quarantined"):
            print(f"  quarantined [{m['action']:8s}] {m['key']:40s} "
                  f"{m.get('quarantine_reason', '')}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "info"
    if cmd == "info" and len(sys.argv) > 2:
        _info(sys.argv[2])
    elif cmd == "monitor" and len(sys.argv) > 2:
        _monitor(sys.argv[2])
    else:
        print("usage: python -m prismpath.prefilter {info|monitor} <corpus-dir>")
