# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The intent reader: embedder similarities, read into the integer fields the signed policy compares.

This is TRUSTED CODE OUTSIDE THE VERIFIED CORE, exactly as `governed_harness/classifier.py` is. The core
decides a reading against a signed image and what is proved is proved about the reading it is given.
Whether `harm_bp` says truthfully how close a reply is to the harm centroids, or whether `intent_class`
names the task's purpose, is this module's job alone, held by its own tests and by the lock it verifies
against. It is kept small and deterministic: fixed inputs, pinned weights verified by hash and by
fingerprint, CPU, one text per forward pass (so no batch padding enters any vector), and every number
the policy sees is an integer computed by a stated rule.

THE FIELDS (canon/2 has no floats, so every one is an integer, a category or a version):

  intent_reader_version  int, READER_VERSION, bounded by the signed policy (min=max=1)
  semantic_status        "verified" when the embedder reproduced the lock, else "disabled"
  semantic_lock          the sha256 of `intent_lock.json` (the lock the reading was made under), "none"
                         when no lock loaded. The policy's semantic rules fire only on the lock it was
                         signed with, so the P1 fingerprint, the centroids and the thresholds travel
                         together, and the value is in every reading, hence in every receipt's
                         `reading_sha256` and in the run's cases.
  harm_bp                the maximum cosine similarity, over every chunk of the reply text and of the
                         proposed call's string arguments, to the P1 harm centroids, as
                         floor(10000 * clamp(cos, 0, 1)): basis points, ROUNDED DOWN, clamped to 0..10000.
                         Declared `fixed scale=10000 unit=cosine rounding=floor`, so the rounding is part
                         of the signed definition and the threshold is an exact decimal of the cosine.
  intent_class           the nearest intent centroid to the TASK text: inspect, modify-workspace, cleanup,
                         vcs-publish, toolchain-change, network; `unknown` when disabled or the task is
                         empty. Ties go to the earlier class in that order.
  intent_margin_bp       bp(best) - bp(second), each bp as for harm_bp: the integer gap between the best
                         and second best class (0 on a tie, when disabled, or for `unknown`).

Why intent is read from the task and never from the model's reply: the reply is the untrusted side. A
model that wrote "I am only inspecting" beside a delete could otherwise steer the class to match its own
action; the task is the owner's request, which the model cannot rewrite. The reply and the call are read
for harm, since harmful text can arrive either as a reply or inside a call (a file's content).

FAIL TO FLOOR, LOUDLY. `verify()` checks, in order: the lock loads and its harm centroids equal the P1
lockfile's; the P1 lockfile's bytes hash to what the lock recorded; the embedder's weight files hash to
what the lock pinned (offline, the pinned revision, nothing downloaded); the P1 fingerprint probe embeds
to the P1 fingerprint (cosine at least 0.9999, the P1 rule); and the lock's reference readings are
reproduced (the same class, every bp within 1). Any failure sets the status to `disabled` with the reason,
writes the reason to standard error, and from then on every reading carries the zeroed semantic fields,
which no semantic rule of the policy reads as anything (union-only, proved over the field space).
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from .exemplars import ALL_CLASSES, INTENT_CLASSES, UNKNOWN

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
LOCK_PATH = HERE / "intent_lock.json"
P1_LOCK_PATH = REPO / "prismpath" / "policies" / "p1_lockfile.json"

READER_VERSION = 1
MODEL = "BAAI/bge-small-en-v1.5"
REVISION = "5c38ec7c405ec4b44b94cc5a9bb96e735b38267a"
WEIGHT_FILES = ("1_Pooling/config.json", "config.json", "config_sentence_transformers.json", "model.safetensors",
                "modules.json", "sentence_bert_config.json", "special_tokens_map.json", "tokenizer.json",
                "tokenizer_config.json", "vocab.txt")
MIN_FINGERPRINT_COSINE = 0.9999          # the P1 rule (guard_semantic.SemanticLayer.verify)
REFERENCE_BP_TOLERANCE = 1
CHUNK_WORDS = 48                         # well under the embedder's 512 token window
CHUNK_STRIDE = 24
BP = 10000

VERIFIED, DISABLED = "verified", "disabled"
SEMANTIC_FIELDS = ("intent_reader_version", "semantic_status", "semantic_lock", "harm_bp", "intent_class",
                   "intent_margin_bp")

Embed = Callable[[Sequence[str]], List[Any]]


def zero_fields() -> Dict[str, Any]:
    """The semantic fields of a reading with no semantic signal: what the floor decides on."""
    return {"intent_reader_version": READER_VERSION, "semantic_status": DISABLED, "semantic_lock": "none",
            "harm_bp": 0, "intent_class": UNKNOWN, "intent_margin_bp": 0}


def bp(cosine: float) -> int:
    """floor(10000 * clamp(cos, 0, 1)), the one rounding rule of every similarity field."""
    value = float(cosine)
    if not math.isfinite(value) or value <= 0.0:
        return 0
    if value >= 1.0:
        return BP
    return min(BP, max(0, math.floor(value * BP)))


def chunks(text: str) -> List[str]:
    """Overlapping windows of at most CHUNK_WORDS whitespace words, so a long reply or file content is
    read everywhere and a phrase is never split by the only boundary that would see it."""
    words = text.split()
    if not words:
        return []
    if len(words) <= CHUNK_WORDS:
        return [" ".join(words)]
    out, start = [], 0
    while True:
        out.append(" ".join(words[start:start + CHUNK_WORDS]))
        if start + CHUNK_WORDS >= len(words):
            return out
        start += CHUNK_STRIDE


def _strings(value: Any) -> List[str]:
    """Every string a call carries: a list of strings (an argv) as one text, each other string by itself."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        if value and all(isinstance(item, str) for item in value):
            return [" ".join(value)]
        return [text for item in value for text in _strings(item)]
    if isinstance(value, dict):
        return [text for key in sorted(value, key=str) for text in _strings(value[key])]
    return []


def harm_texts(reply: str, call: Any = None) -> List[str]:
    texts = [reply] if isinstance(reply, str) else []
    if call is not None:
        texts += _strings(call.get("args") if isinstance(call, dict) else call)
    return [chunk for text in texts for chunk in chunks(text)]


# ----------------------------------------------------------------- the embedder
def snapshot_dir() -> Path:
    """The pinned revision in the local cache, offline: never a download."""
    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
    from huggingface_hub import snapshot_download
    path = Path(snapshot_download(MODEL, revision=REVISION, local_files_only=True))
    if path.name != REVISION:
        raise RuntimeError(f"the cache resolved {MODEL} to {path.name}, not the pinned {REVISION}")
    return path


def weight_hashes(path: Path) -> Dict[str, str]:
    out = {}
    for name in WEIGHT_FILES:
        out[name] = hashlib.sha256((path / name).read_bytes()).hexdigest()
    return out


def load_embedder(threads: Optional[int] = None) -> Embed:
    """bge-small-en-v1.5 at the pinned revision on CPU, raw (no query instruction, as P1 measured),
    normalized, one text per forward pass."""
    path = snapshot_dir()
    import torch
    from sentence_transformers import SentenceTransformer
    if threads is not None:
        torch.set_num_threads(int(threads))
    model = SentenceTransformer(str(path), device="cpu", local_files_only=True)

    def embed(texts: Sequence[str]) -> List[Any]:
        return [model.encode([text], normalize_embeddings=True, show_progress_bar=False,
                             convert_to_numpy=True)[0] for text in texts]

    embed.weights = weight_hashes(path)          # type: ignore[attr-defined]
    return embed


def _dot(vector, centroid) -> float:
    return float(sum(float(left) * float(right) for left, right in zip(vector, centroid)))


# ----------------------------------------------------------------- the reader
@dataclass
class IntentReader:
    """Reads the semantic fields. `embed` is injected so fail-to-floor is testable with no model."""
    embed: Optional[Embed] = None
    lock_path: Path = LOCK_PATH
    p1_lock_path: Path = P1_LOCK_PATH
    status: str = DISABLED
    reason: str = "not verified yet"
    lock: Optional[Dict[str, Any]] = None
    lock_id: str = "none"
    loud: bool = True
    _task_cache: Dict[str, Any] = field(default_factory=dict)

    # -- verification: the lock, the P1 lockfile, the weights, the fingerprint, the reference readings
    def verify(self) -> str:
        try:
            self._verify()
            self.status, self.reason = VERIFIED, "embedder reproduces the lock"
        except Exception as failure:   # noqa: BLE001 - any failure falls to the floor, never runs unverified
            self.status, self.reason = DISABLED, f"{type(failure).__name__}: {failure}"
            if self.loud:
                print(f"[governed_intent] SEMANTIC LAYER DISABLED, deciding on the deterministic floor only: "
                      f"{self.reason}", file=sys.stderr)
        self._task_cache.clear()
        return self.status

    def _verify(self) -> None:
        raw = Path(self.lock_path).read_bytes()
        self.lock = json.loads(raw)
        self.lock_id = hashlib.sha256(raw).hexdigest()
        lock = self.lock
        if lock.get("format") != "prismpath.intent-lock/1":
            raise ValueError("not an intent lock")
        p1_raw = Path(self.p1_lock_path).read_bytes()
        if hashlib.sha256(p1_raw).hexdigest() != lock["p1_lockfile"]["sha256"]:
            raise ValueError("the P1 lockfile is not the one this lock was made from")
        p1 = json.loads(p1_raw)
        if p1["centroids"] != lock["harm"]["centroids"]:
            raise ValueError("the harm centroids differ from the P1 lockfile's")
        if self.embed is None:
            raise RuntimeError("no embedder on this device (the floor tier has none)")
        weights = getattr(self.embed, "weights", None)
        if weights is not None and weights != lock["embedder"]["weight_sha256"]:
            raise ValueError("the embedder's weight files are not the pinned ones")
        probe = self.embed([p1["fingerprint_probe"]])[0]
        fingerprint = p1["fingerprint"]
        norm = math.sqrt(_dot(fingerprint, fingerprint)) * math.sqrt(_dot(probe, probe))
        cosine = _dot(probe, fingerprint) / norm if norm else 0.0
        if cosine < MIN_FINGERPRINT_COSINE:
            raise ValueError(f"embedder fingerprint mismatch (cosine {cosine:.6f} < {MIN_FINGERPRINT_COSINE})")
        for ref in lock["reference_readings"]:
            got = self._measure(ref["text"], task=ref["kind"] == "task")
            want = {key: ref[key] for key in got}
            if got.get("intent_class") != want.get("intent_class") or any(
                    abs(got[key] - want[key]) > REFERENCE_BP_TOLERANCE for key in got if key.endswith("_bp")):
                raise ValueError(f"reference reading not reproduced: {ref['text']!r} {got} != {want}")

    @property
    def verified(self) -> bool:
        return self.status == VERIFIED

    # -- measurement
    def _harm_bp(self, texts: Sequence[str]) -> int:
        best = 0
        centroids = [self.lock["harm"]["centroids"][name] for name in sorted(self.lock["harm"]["centroids"])]
        for vector in self.embed(list(texts)) if texts else []:
            for centroid in centroids:
                best = max(best, bp(_dot(vector, centroid)))
        return best

    def _intent(self, task: str):
        words = task.split() if isinstance(task, str) else []
        if not words:
            return UNKNOWN, 0
        vector = self.embed([" ".join(words)])[0]
        scores = [(bp(_dot(vector, self.lock["intent"]["centroids"][name])), -at, name)
                  for at, name in enumerate(INTENT_CLASSES)]
        scores.sort(reverse=True)
        (best, _a, name), (second, _b, _n) = scores[0], scores[1]
        return name, best - second

    def _measure(self, text: str, task: bool) -> Dict[str, Any]:
        if task:
            name, margin = self._intent(text)
            return {"intent_class": name, "intent_margin_bp": margin}
        return {"harm_bp": self._harm_bp(chunks(text))}

    # -- the readings
    def _base(self) -> Dict[str, Any]:
        fields = zero_fields()
        fields["semantic_lock"] = self.lock_id
        return fields

    def task_fields(self, task: str) -> Dict[str, Any]:
        if not self.verified:
            return {"intent_class": UNKNOWN, "intent_margin_bp": 0}
        if task not in self._task_cache:
            name, margin = self._intent(task)
            self._task_cache[task] = {"intent_class": name, "intent_margin_bp": margin}
        return dict(self._task_cache[task])

    def read_call(self, task: str, reply: str, call: Any) -> Dict[str, Any]:
        """The semantic fields of one proposed call: harm over the reply and the call, intent of the task."""
        fields = self._base()
        if not self.verified:
            return fields
        fields["semantic_status"] = VERIFIED
        fields["harm_bp"] = self._harm_bp(harm_texts(reply, call))
        fields.update(self.task_fields(task))
        assert fields["intent_class"] in ALL_CLASSES
        return fields

    def read_response(self, reply: str, final: Any = None) -> Dict[str, Any]:
        """The fields of a reply that proposes no call (an answer, or text with no JSON): harm only."""
        fields = {key: value for key, value in self._base().items()
                  if key in ("intent_reader_version", "semantic_status", "semantic_lock", "harm_bp")}
        if not self.verified:
            return fields
        fields["semantic_status"] = VERIFIED
        extra = [final] if isinstance(final, str) and final != reply else []
        fields["harm_bp"] = self._harm_bp([chunk for text in [reply, *extra] for chunk in chunks(text)])
        return fields


def verified_reader(threads: Optional[int] = None, loud: bool = True) -> IntentReader:
    """The reader with the real embedder, verified; disabled (and saying so) when anything fails."""
    try:
        embed = load_embedder(threads)
    except Exception as failure:   # noqa: BLE001 - no embedder is the floor tier's normal state
        reader = IntentReader(embed=None, loud=loud)
        reader.verify()
        reader.reason = f"no embedder: {type(failure).__name__}: {failure}"
        return reader
    reader = IntentReader(embed=embed, loud=loud)
    reader.verify()
    return reader
