#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Semantic retrieval with EmbeddingGemma (CPU — GPU/gemma untouched). Reads the r2 catalog + the blind
company docs, embeds control-queries vs docs, writes efficacy/semantic_map.json = {control: [top-k docs]}.
Runs under the ST env; decoupled from the adjudication step (which runs under the prismpath venv)."""
import os, json, sys
os.environ["CUDA_VISIBLE_DEVICES"] = ""   # force CPU: do not compete with gemma on the GPU
import numpy as np
from sentence_transformers import SentenceTransformer

HERE = os.path.dirname(os.path.abspath(__file__))
CAT = json.load(open(os.path.join(HERE, "catalog", "nist_800171_r2.json")))["controls"]
COMPANY = os.path.join(HERE, "efficacy", "company")
TOPK = 3


def breadth_controls():
    by_fam = {}
    for cid, control in CAT.items():
        by_fam.setdefault(control["family"], []).append(cid)
    key = lambda cid: [int(part) for part in cid.split(".")]
    return [sorted(family_controls, key=key)[0] for _, family_controls in sorted(by_fam.items())]


def load_docs():
    out = []
    for filename in sorted(os.listdir(COMPANY)):
        path = os.path.join(COMPANY, filename)
        if os.path.isfile(path) and not filename.startswith("_"):
            text = open(path, errors="ignore").read()
            if text.strip():
                out.append((filename, text[:6000]))
    return out


def emb(model, texts, kind):
    fn = getattr(model, "encode_query" if kind == "query" else "encode_document", None)
    try:
        return np.asarray(fn(texts, normalize_embeddings=True)) if fn else \
               np.asarray(model.encode(texts, normalize_embeddings=True))
    except Exception:
        return np.asarray(model.encode(texts, normalize_embeddings=True))


def main():
    model = SentenceTransformer("google/embeddinggemma-300m", device="cpu")
    docs = load_docs()
    dnames = [doc_name for doc_name, _ in docs]
    dvec = emb(model, [text for _, text in docs], "document")
    controls = breadth_controls()
    queries = []
    for cid in controls:
        control = CAT[cid]
        query = "%s. %s. Objectives: %s. Evidence: %s." % (
            control["title"], control.get("family_name", ""),
            " ".join(objective["text"] for objective in control["objectives"]),
            " ".join(control.get("evidence_types", [])))
        queries.append(query)
    qvec = emb(model, queries, "query")
    sims = qvec @ dvec.T                                        # cosine (both normalized)
    smap, detail = {}, {}
    for control_index, cid in enumerate(controls):
        order = np.argsort(-sims[control_index])[:TOPK]
        smap[cid] = [dnames[doc_index] for doc_index in order]
        detail[cid] = [{"doc": dnames[doc_index], "sim": round(float(sims[control_index][doc_index]), 3)} for doc_index in order]
    json.dump(smap, open(os.path.join(HERE, "efficacy", "semantic_map.json"), "w"), indent=1)
    json.dump(detail, open(os.path.join(HERE, "efficacy", "semantic_map_detail.json"), "w"), indent=1)
    for cid in controls:
        print(cid.ljust(7), CAT[cid]["family"].ljust(3), "<-", ", ".join("%s(%.2f)" % (hit["doc"], hit["sim"]) for hit in detail[cid]))


if __name__ == "__main__":
    main()
