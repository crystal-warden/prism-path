# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Dense retriever over a cwplatform-format turbovec docs index — grounds the coder in real docs.

Generic by design: the index is whatever the active gate-plugin points at (its RAG_INDEX) — a
plugin supplies its own target-docs index. The engine just retrieves; it knows nothing of the target.

Self-contained: BGE-base (sentence-transformers, CPU) + turbovec, reading the index written by
cwplatform's TurbovecIndexWriter — meta shape `{id: {chunk_id, text, meta:{source,path,heading_path}}}`.
This reads OUR index directly (sidesteps pipeline/doc_rag's flat-meta format).

BEST-EFFORT by design: if sentence-transformers / turbovec / the index are unavailable, `retrieve`
returns [] (warns once) so a sprint launched without the RAG deps installed simply runs RAG-off.

  EMBED_DEVICE=cpu SPRINT_RAG_INDEX=<your-index>.tvim python prismpath/retriever.py "export a typed port"
"""
import json
import os

_QUERY_INSTRUCTION = "Represent this sentence for searching relevant passages: "
_DEFAULT_INDEX = ""  # no built-in index; the caller/gate-plugin supplies one via SPRINT_RAG_INDEX (empty -> RAG off)
_MODEL_NAME = os.environ.get("EMBED_MODEL", "BAAI/bge-base-en-v1.5")


def _resolve_device():
    # 128GB unified memory: embed on GPU by default; CPU only if CUDA is genuinely unavailable.
    # (The old "keep on CPU" default was a 12GB-VRAM-era artifact.)
    embed_device = os.environ.get("EMBED_DEVICE")
    if embed_device:
        return embed_device
    try:
        import torch
        return "cuda" if torch.cuda.is_available() else "cpu"
    except Exception:
        return "cpu"

_model = None
_cache = {}        # index_path -> (turbovec index, meta dict)
_warned = False


def _embedder():
    global _model
    if _model is None:
        from sentence_transformers import SentenceTransformer  # lazy: heavy import
        _model = SentenceTransformer(_MODEL_NAME, device=_resolve_device())
    return _model


def _load(index_path):
    if index_path not in _cache:
        import turbovec
        idx = turbovec.IdMapIndex.load(index_path)
        meta = {int(k): meta_value
                for k, meta_value in json.load(open(index_path + ".meta.json")).items()}
        _cache[index_path] = (idx, meta)
    return _cache[index_path]


def retrieve(query, k=4, index_path=None):
    """Top-k doc chunks for `query` -> [{score, source, path, text}]. Never raises."""
    global _warned
    index_path = index_path or os.environ.get("SPRINT_RAG_INDEX") or _DEFAULT_INDEX
    per_doc = int(os.environ.get("SPRINT_RAG_PER_DOC", "2"))    # diversity cap: ≤N chunks per doc
    # Denoise: drop chunks the converter tagged [deprecated]/[internal] (runtime-unavailable API).
    # The corpus stays COMPLETE; filtering happens here. SPRINT_RAG_INCLUDE_ALL=1 retrieves raw.
    drop_marked = os.environ.get("SPRINT_RAG_INCLUDE_ALL", "0") != "1"
    try:
        import numpy as np
        idx, meta = _load(index_path)
        vec = _embedder().encode([_QUERY_INSTRUCTION + query], normalize_embeddings=True)
        # Over-fetch, then diversify: cap chunks per (source,path) so one doc can't monopolize top-k
        # (a lightweight MMR-style spread — keeps the canonical class AND its neighbours in view).
        scores, ids = idx.search(np.asarray(vec, dtype="float32"), k=max(k * 8, 32))
        out, seen = [], {}
        for score, chunk_id in zip(np.asarray(scores)[0], np.asarray(ids)[0]):
            meta_record = meta.get(int(chunk_id))
            if not meta_record:
                continue
            text = meta_record.get("text", "")
            if drop_marked and ("[deprecated]" in text.lower() or "[internal]" in text.lower()):
                continue
            mm = meta_record.get("meta", {}) or {}
            key = (mm.get("source", ""), mm.get("path", ""))
            if seen.get(key, 0) >= per_doc:
                continue
            seen[key] = seen.get(key, 0) + 1
            out.append({"score": float(score), "source": mm.get("source", ""),
                        "path": mm.get("path", ""), "text": text})
            if len(out) >= k:
                break
        return out
    except Exception as exc:
        if not _warned:
            print(f"[retriever] RAG disabled ({type(exc).__name__}: {str(exc)[:140]})", flush=True)
            _warned = True
        return []


if __name__ == "__main__":
    import sys
    query_text = sys.argv[1] if len(sys.argv) > 1 else "export a typed port"
    hits = retrieve(query_text, int(os.environ.get("K", "4")))
    print(f"query: {query_text}\n{len(hits)} hits:")
    for hit in hits:
        print(f"  [{hit['score']:.3f}] {hit['source']}/{hit['path']}")
        print("     " + hit["text"][:160].replace("\n", " ") + "…")
