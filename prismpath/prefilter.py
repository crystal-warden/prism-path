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
        tuned = self._load_tuning()
        self.threshold, self._threshold_source = self._resolve(
            threshold, "PREFILTER_THRESHOLD", tuned.get("threshold"), 0.97)
        self.min_conf, self._min_conf_source = self._resolve(
            min_conf, "PREFILTER_MIN_CONF", tuned.get("min_conf"), 0.8)
        self.embed_fn = embed_fn or default_embed_fn

    def _load_tuning(self) -> dict:
        """The chosen operating point from a prior `tune()` run (`<corpus>/tuning.json`), if
        any. Sits BELOW explicit args and env in precedence — a derived point never overrides
        an operator's decision, it replaces the hardcoded default."""
        try:
            with open(self.dir / "tuning.json") as f:
                return (json.load(f) or {}).get("chosen") or {}
        except (OSError, ValueError):
            return {}

    @staticmethod
    def _resolve(explicit, env_name: str, tuned, fallback: float):
        """Operating-point precedence: explicit arg > env var > tuning.json > default."""
        if explicit is not None:
            return float(explicit), "explicit"
        env = os.environ.get(env_name)
        if env is not None:
            return float(env), "env"
        if tuned is not None:
            return float(tuned), "tuning.json"
        return fallback, "default"

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
                "threshold_source": self._threshold_source,
                "min_conf_source": self._min_conf_source,
                "dir": str(self.dir)}


# --- automatic tuning (risk-controlled operating point) -------------------------------
def _wilson_upper(k: int, n: int, confidence: float = 0.95) -> float:
    """High-probability UPPER bound on a binomial rate (Wilson score interval) — the mirror of
    calibrate._wilson_lower, bounding the reuse-ERROR rate from above. No scipy."""
    if n == 0:
        return 1.0                       # no evidence -> assume the worst; never certify on n=0
    import math
    z = 1.959963984540054 if confidence == 0.95 else {0.9: 1.6448536269514722,
                                                      0.99: 2.5758293035489004}.get(confidence,
                                                                                    1.959963984540054)
    phat = k / n
    denom = 1 + z * z / n
    center = phat + z * z / (2 * n)
    half = z * math.sqrt(phat * (1 - phat) / n + z * z / (4 * n * n))
    return min(1.0, (center + half) / denom)


def tune(dir_path, labels: Optional[List[dict]] = None, risk: float = 0.02,
         confidence: float = 0.95, thresholds: Optional[List[float]] = None,
         min_confs: Optional[List[float]] = None,
         embed_fn: Callable[[List[str]], np.ndarray] = None, write: bool = True) -> dict:
    """Derive the cache's operating point from evidence instead of a hand-picked constant —
    the same risk-controlled pattern as `prismpath calibrate` (τ), applied to the prefilter.

    Sweeps a (threshold × min_conf) grid via the pure `match_arrays` gate and selects the point
    that MAXIMIZES the auto-resolve rate among points whose reuse-error rate is certified
    ≤ `risk` by a Wilson upper bound at `confidence` (ties -> the higher threshold — the safer
    of two equal operating points). Evaluation stream:

      * `labels` given — replayed labeled decisions: rows of {"doc": str | "vec": [...],
        "action": <oracle>} (e.g. emitted by the SOC adapter's shadow audit);
      * `labels` None — leave-one-out over the corpus itself: each stored entry is matched
        against the corpus minus itself and its own action is the oracle. Zero extra data, but
        it measures self-consistency — prefer real labels when you have them.

    Writes `<corpus>/tuning.json` (chosen point + the full grid + provenance) unless
    `write=False`; `PrefilterCache` then picks it up automatically (precedence: explicit arg >
    env > tuning.json > default). Returns the same dict it writes. A grid with NO certified
    point returns chosen=None with a warning — the honest answer is "don't enable reuse yet",
    never a guessed threshold."""
    import time
    cache = PrefilterCache(dir_path, embed_fn=embed_fn)
    emb, meta = cache.load()
    n_corpus = int(emb.shape[0])
    thresholds = thresholds or [0.90, 0.93, 0.95, 0.97, 0.99]
    min_confs = min_confs or [0.5, 0.8, 0.9]

    # ---- build the evaluation stream: (query_vec, oracle_action, mask_index|None)
    stream = []
    if labels is not None:
        for row in labels:
            if row.get("vec") is not None:
                v = _normalize(np.asarray(row["vec"], dtype=np.float32))
            elif row.get("doc"):
                v = _normalize(cache.embed([row["doc"]])[0])
            else:
                continue
            stream.append((v, row.get("action"), None))
        source = "labels"
    else:
        for i in range(n_corpus):
            stream.append((emb[i], meta[i].get("action"), i))
        source = "leave-one-out"

    grid = []
    eligible = []
    for thr in sorted(thresholds):
        for mc in sorted(min_confs):
            hits = errors = 0
            for v, oracle, mask in stream:
                if mask is None:
                    hit, rec, _sim = match_arrays(v, emb, meta, thr, mc)
                else:                       # leave-one-out: hide the entry's own row
                    if n_corpus < 2:
                        continue
                    sel = np.arange(n_corpus) != mask
                    hit, rec, _sim = match_arrays(v, emb[sel],
                                                  [m for j, m in enumerate(meta) if j != mask],
                                                  thr, mc)
                if not hit:
                    continue
                hits += 1
                if rec.get("action") != oracle:
                    errors += 1
            n_eval = len(stream)
            auto = hits / n_eval if n_eval else 0.0
            err_rate = errors / hits if hits else 0.0
            upper = _wilson_upper(errors, hits, confidence)
            row = {"threshold": thr, "min_conf": mc, "n_eval": n_eval, "hits": hits,
                   "errors": errors, "auto_resolve": round(auto, 4),
                   "reuse_error": round(err_rate, 4), "err_upper": round(upper, 4),
                   "certified": bool(hits and upper <= risk)}
            grid.append(row)
            if row["certified"]:
                eligible.append(row)

    chosen = None
    if eligible:
        chosen = max(eligible, key=lambda r: (r["auto_resolve"], r["threshold"], r["min_conf"]))
    out = {
        "chosen": {"threshold": chosen["threshold"], "min_conf": chosen["min_conf"],
                   "auto_resolve": chosen["auto_resolve"], "reuse_error": chosen["reuse_error"],
                   "err_upper": chosen["err_upper"], "hits": chosen["hits"],
                   "errors": chosen["errors"]} if chosen else None,
        "risk": risk, "confidence": confidence, "labels": source,
        "n_eval": len(stream), "corpus_entries": n_corpus,
        "grid": grid, "generated_at": time.time(),
        "warning": None if chosen else
        f"no grid point's reuse-error upper bound clears risk={risk} — keep reuse off or "
        f"gather more labeled decisions (evidence n grows the certifiable region)",
    }
    if write:
        cache.dir.mkdir(parents=True, exist_ok=True)
        tmp = cache.dir / "tuning.json.tmp"
        with open(tmp, "w") as f:
            json.dump(out, f, indent=2)
        os.replace(tmp, cache.dir / "tuning.json")
    return out


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


def _tune_cli(argv: List[str]) -> None:
    import argparse
    ap = argparse.ArgumentParser(prog="python -m prismpath.prefilter tune")
    ap.add_argument("corpus", help="corpus dir (embeddings.npy + meta.json)")
    ap.add_argument("--labels", default=None,
                    help="JSONL of labeled decisions: {'doc'|'vec': ..., 'action': oracle}; "
                         "default = leave-one-out over the corpus")
    ap.add_argument("--risk", type=float, default=0.02,
                    help="max certified reuse-error rate (Wilson upper bound; default 0.02)")
    args = ap.parse_args(argv)
    labels = None
    if args.labels:
        labels = [json.loads(l) for l in open(args.labels) if l.strip()]
    out = tune(args.corpus, labels=labels, risk=args.risk)
    slim = {k: v for k, v in out.items() if k != "grid"}
    print(json.dumps(slim, indent=2))
    print(f"grid: {len(out['grid'])} points swept; "
          f"{sum(1 for r in out['grid'] if r['certified'])} certified at risk<={args.risk}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "info"
    if cmd == "info" and len(sys.argv) > 2:
        _info(sys.argv[2])
    elif cmd == "monitor" and len(sys.argv) > 2:
        _monitor(sys.argv[2])
    elif cmd == "tune" and len(sys.argv) > 2:
        _tune_cli(sys.argv[2:])
    else:
        print("usage: python -m prismpath.prefilter {info|monitor|tune} <corpus-dir>")
