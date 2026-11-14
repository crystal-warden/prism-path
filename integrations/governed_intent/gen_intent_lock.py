# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Freeze what the intent reader consults: `intent_lock.json`.

The lock is to the intent layer what `prismpath/policies/p1_lockfile.json` is to the P1 layer, and it is
built on top of that file rather than beside it:

  * the embedder's identity: model, the pinned revision, the sha256 of every weight and tokenizer file,
    runtime, device, precision, normalization, and the encoding rule (one text per forward pass, no
    query instruction);
  * the P1 lockfile by its sha256, with its fingerprint probe and the 0.9999 rule, so the reader verifies
    the embedder by the P1 fingerprint and nothing else;
  * the harm centroids, copied unchanged from the P1 lockfile (the reader checks they still equal it);
  * the intent centroids, built from `exemplars.INTENT_EXEMPLARS` (fresh, disjoint from the cases, checked);
  * reference readings, integer fields for a few fixed texts, so a consumer proves it reproduces the
    readings and not only the fingerprint (the P1 lockfile's lesson: the fingerprint passed while a
    centroid bug was live).

The sha256 of this file's bytes is the `semantic_lock` value of every reading, and the signed policy's
semantic rules fire only on that value.

    python -m integrations.governed_intent.gen_intent_lock           # write the lock
    python -m integrations.governed_intent.gen_intent_lock --check   # exit 1 when the committed one is stale
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from pathlib import Path

from . import cases, exemplars, intent_reader as ir

REFERENCE_TEXTS = [
    ("harm", "the quick brown fox jumps over the lazy dog"),
    ("harm", "how do I kill a process in rust"),
    ("task", "Have a quick look over the readme for me."),
    ("task", "Ship the finished commits to the remote."),
    ("task", "Bump the interpreter version inside the toolchain."),
]


def _unit_mean(vectors):
    dim = len(vectors[0])
    mean = [sum(float(vector[at]) for vector in vectors) / len(vectors) for at in range(dim)]
    norm = math.sqrt(sum(component * component for component in mean))
    return [round(component / norm, 8) for component in mean]


def generate() -> str:
    exemplars.assert_disjoint(cases.all_texts())
    embed = ir.load_embedder()
    p1_raw = ir.P1_LOCK_PATH.read_bytes()
    p1 = json.loads(p1_raw)
    intent = {name: _unit_mean(embed(exemplars.INTENT_EXEMPLARS[name])) for name in exemplars.INTENT_CLASSES}
    exemplar_blob = json.dumps(exemplars.INTENT_EXEMPLARS, sort_keys=True, separators=(",", ":")).encode()
    lock = {
        "format": "prismpath.intent-lock/1",
        "embedder": {"model": ir.MODEL, "revision": ir.REVISION, "weight_sha256": embed.weights,
                     "provider": "sentence-transformers", "device": "cpu", "precision": "f32",
                     "normalize": True, "query_instruction": None, "encode": "one text per forward pass"},
        "p1_lockfile": {"path": "prismpath/policies/p1_lockfile.json",
                        "sha256": hashlib.sha256(p1_raw).hexdigest(),
                        "fingerprint_probe": p1["fingerprint_probe"],
                        "fingerprint_min_cosine": ir.MIN_FINGERPRINT_COSINE},
        "harm": {"source": "p1_lockfile centroids, unchanged", "centroids": p1["centroids"]},
        "intent": {"classes": list(exemplars.INTENT_CLASSES), "unknown": exemplars.UNKNOWN,
                   "exemplars_sha256": hashlib.sha256(exemplar_blob).hexdigest(), "centroids": intent},
        "fields": {"bp": "floor(10000 * clamp(cosine, 0, 1))", "harm_bp": "max over chunks and harm centroids",
                   "intent_margin_bp": "bp(best) - bp(second); ties go to the earlier class",
                   "chunk_words": ir.CHUNK_WORDS, "chunk_stride": ir.CHUNK_STRIDE},
    }
    reader = ir.IntentReader(embed=embed)
    reader.lock = lock
    lock["reference_readings"] = [{"kind": kind, "text": text, **reader._measure(text, task=kind == "task")}
                                  for kind, text in REFERENCE_TEXTS]
    return json.dumps(lock, indent=1, sort_keys=True) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    text = generate()
    if args.check:
        current = ir.LOCK_PATH.read_text() if ir.LOCK_PATH.exists() else None
        if current != text:
            print("GATE FAIL: intent_lock.json is stale (exemplars, P1 lockfile or embedder changed).")
            return 1
        print("GATE PASS: intent_lock.json is current.")
        return 0
    ir.LOCK_PATH.write_text(text)
    print(f"wrote {ir.LOCK_PATH} sha256 {hashlib.sha256(text.encode()).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
