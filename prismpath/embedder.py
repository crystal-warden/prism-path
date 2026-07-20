"""Thin bge embedder for prismpath routing — mirrors pipeline/doc_rag.py conventions.

CPU by default (bge-base is tiny; keeps the GPU free for other jobs). The agent's outcome
is treated as the 'query', the edge conditions as 'passages' (bge puts the instruction on
the query side only).
"""
from __future__ import annotations

import os
import numpy as np

MODEL_NAME = os.environ.get("EMBED_MODEL", "BAAI/bge-base-en-v1.5")
EMBED_DEVICE = os.environ.get("EMBED_DEVICE", "cpu")
# The lock identity is per-(model, provider, precision): the same weights under a different
# runtime (ONNX, WASM) or quantization are a different numeric contract. Recorded in every
# lockfile and compared by verify_lock.
PROVIDER = os.environ.get("EMBED_PROVIDER", "sentence-transformers")
PRECISION = os.environ.get("EMBED_PRECISION", "fp32")
QUERY_INSTRUCTION = "Represent this sentence for searching relevant passages: "

_model = None


def _embedder():
    global _model
    if _model is None:
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as e:
            raise ImportError(
                "the embedder needs sentence-transformers, an optional extra. Install it with "
                "`pip install 'prismpath[embeddings]'` (or `pipx inject prismpath sentence-transformers`). "
                "The non-embedding commands (annotate, kappa, validate, contract, graph, import, test) "
                "work without it.") from e
        _model = SentenceTransformer(MODEL_NAME, device=EMBED_DEVICE)
    return _model


def embed(texts, is_query=False):
    if is_query:
        texts = [QUERY_INSTRUCTION + t for t in texts]
    v = _embedder().encode(texts, normalize_embeddings=True, show_progress_bar=False)
    return np.asarray(v, dtype="float32")


def cosine(a, b):
    """a: [d] or [n,d], b: [m,d] (all unit-normalized) -> similarity matrix/vector."""
    a = np.atleast_2d(a)
    return (a @ b.T)
