#!/usr/bin/env python3
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
    for cid, c in CAT.items():
        by_fam.setdefault(c["family"], []).append(cid)
    key = lambda cid: [int(x) for x in cid.split(".")]
    return [sorted(v, key=key)[0] for _, v in sorted(by_fam.items())]


def load_docs():
    out = []
    for f in sorted(os.listdir(COMPANY)):
        p = os.path.join(COMPANY, f)
        if os.path.isfile(p) and not f.startswith("_"):
            t = open(p, errors="ignore").read()
            if t.strip():
                out.append((f, t[:6000]))
    return out


def emb(m, texts, kind):
    fn = getattr(m, "encode_query" if kind == "query" else "encode_document", None)
    try:
        return np.asarray(fn(texts, normalize_embeddings=True)) if fn else \
               np.asarray(m.encode(texts, normalize_embeddings=True))
    except Exception:
        return np.asarray(m.encode(texts, normalize_embeddings=True))


def main():
    m = SentenceTransformer("google/embeddinggemma-300m", device="cpu")
    docs = load_docs()
    dnames = [n for n, _ in docs]
    dvec = emb(m, [t for _, t in docs], "document")
    controls = breadth_controls()
    queries = []
    for cid in controls:
        c = CAT[cid]
        q = "%s. %s. Objectives: %s. Evidence: %s." % (
            c["title"], c.get("family_name", ""),
            " ".join(o["text"] for o in c["objectives"]),
            " ".join(c.get("evidence_types", [])))
        queries.append(q)
    qvec = emb(m, queries, "query")
    sims = qvec @ dvec.T                                        # cosine (both normalized)
    smap, detail = {}, {}
    for i, cid in enumerate(controls):
        order = np.argsort(-sims[i])[:TOPK]
        smap[cid] = [dnames[j] for j in order]
        detail[cid] = [{"doc": dnames[j], "sim": round(float(sims[i][j]), 3)} for j in order]
    json.dump(smap, open(os.path.join(HERE, "efficacy", "semantic_map.json"), "w"), indent=1)
    json.dump(detail, open(os.path.join(HERE, "efficacy", "semantic_map_detail.json"), "w"), indent=1)
    for cid in controls:
        print(cid.ljust(7), CAT[cid]["family"].ljust(3), "<-", ", ".join("%s(%.2f)" % (d["doc"], d["sim"]) for d in detail[cid]))


if __name__ == "__main__":
    main()
