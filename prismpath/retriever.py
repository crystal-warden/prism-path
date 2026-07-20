"""Dense retriever over a cwplatform-format turbovec docs index — grounds the coder in real docs.

Generic by design: the index is whatever the active gate-plugin points at (its RAG_INDEX) — e.g. the
Roblox plugin supplies a Luau-docs index. The engine just retrieves; it knows nothing of the target.

Self-contained: BGE-base (sentence-transformers, CPU) + turbovec, reading the index written by
cwplatform's TurbovecIndexWriter — meta shape `{id: {chunk_id, text, meta:{source,path,heading_path}}}`.
This reads OUR index directly (sidesteps pipeline/doc_rag's flat-meta format).

BEST-EFFORT by design: if sentence-transformers / turbovec / the index are unavailable, `retrieve`
returns [] (warns once) so a sprint launched without the RAG deps installed simply runs RAG-off.

  EMBED_DEVICE=cpu SPRINT_RAG_INDEX=prismpath/rag/luau.tvim python prismpath/retriever.py "export a Luau type"
"""
import json
import os

_QUERY_INSTRUCTION = "Represent this sentence for searching relevant passages: "
_DEFAULT_INDEX = ""  # no built-in index; the caller/gate-plugin supplies one via SPRINT_RAG_INDEX (empty -> RAG off)
_MODEL_NAME = os.environ.get("EMBED_MODEL", "BAAI/bge-base-en-v1.5")


def _resolve_device():
    # 128GB unified memory: embed on GPU by default; CPU only if CUDA is genuinely unavailable.
    # (The old "keep on CPU" default was a 12GB-VRAM-era artifact.)
    d = os.environ.get("EMBED_DEVICE")
    if d:
        return d
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
        meta = {int(k): v for k, v in json.load(open(index_path + ".meta.json")).items()}
        _cache[index_path] = (idx, meta)
    return _cache[index_path]


def retrieve(query, k=4, index_path=None):
    """Top-k Luau doc chunks for `query` -> [{score, source, path, text}]. Never raises."""
    global _warned
    index_path = index_path or os.environ.get("SPRINT_RAG_INDEX") or _DEFAULT_INDEX
    per_doc = int(os.environ.get("SPRINT_RAG_PER_DOC", "2"))    # diversity cap: ≤N chunks per doc
    # Denoise: drop chunks the converter tagged [deprecated]/[internal] (game-unusable API).
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
        for s, i in zip(np.asarray(scores)[0], np.asarray(ids)[0]):
            m = meta.get(int(i))
            if not m:
                continue
            text = m.get("text", "")
            if drop_marked and ("[deprecated]" in text.lower() or "[internal]" in text.lower()):
                continue
            mm = m.get("meta", {}) or {}
            key = (mm.get("source", ""), mm.get("path", ""))
            if seen.get(key, 0) >= per_doc:
                continue
            seen[key] = seen.get(key, 0) + 1
            out.append({"score": float(s), "source": mm.get("source", ""),
                        "path": mm.get("path", ""), "text": text})
            if len(out) >= k:
                break
        return out
    except Exception as e:
        if not _warned:
            print(f"[retriever] RAG disabled ({type(e).__name__}: {str(e)[:140]})", flush=True)
            _warned = True
        return []


if __name__ == "__main__":
    import sys
    q = sys.argv[1] if len(sys.argv) > 1 else "export a Luau type for a port"
    hits = retrieve(q, int(os.environ.get("K", "4")))
    print(f"query: {q}\n{len(hits)} hits:")
    for h in hits:
        print(f"  [{h['score']:.3f}] {h['source']}/{h['path']}")
        print("     " + h["text"][:160].replace("\n", " ") + "…")
