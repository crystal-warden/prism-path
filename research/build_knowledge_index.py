#!/usr/bin/env python3
"""#58 — build the retrieval knowledge index from published detection frameworks.

First source: LOLBAS (living-off-the-land binaries) — the highest-value corpus for our measured
weakness (admin-mimicry / LOLBin under-calls). Each entry becomes a compact 'knowledge card' the
triage decision nodes can PULL discriminators from. Emits an embedded index + a content HASH for
Flow-Ledger attestation (a verdict can be bound to the exact knowledge snapshot that informed it).

Next sources (staged): MITRE ATT&CK technique detection guidance, Sigma rules, CAR, D3FEND.
"""
import json, os, hashlib
import numpy as np
from sentence_transformers import SentenceTransformer

RAW = "/home/cwadmin/cwprojects/knowledge-lib/raw/lolbas.json"
OUT = "/home/cwadmin/cwprojects/knowledge-lib/index"
os.makedirs(OUT, exist_ok=True)

lol = json.load(open(RAW))
cards = []
for e in lol:
    name = e.get("Name", "").strip()
    desc = e.get("Description", "").strip()
    cats, uses, mitres, dets = [], [], set(), []
    for c in e.get("Commands", []) or []:
        if c.get("Category"): cats.append(c["Category"])
        if c.get("Usecase"): uses.append(c["Usecase"].strip())
        if c.get("MitreID"): mitres.add(c["MitreID"])
    for d in e.get("Detection", []) or []:
        for k, v in (d.items() if isinstance(d, dict) else []):
            if v: dets.append(f"{k}:{v}")
    cats = sorted(set(cats)); uses = list(dict.fromkeys(uses))[:4]; mitres = sorted(mitres)
    # the card text = what the model reads as decision criteria
    text = (f"{name} — {desc}. LOLBin abuse categories: {', '.join(cats) or 'n/a'}. "
            f"Malicious use: {'; '.join(uses) or 'n/a'}. MITRE: {', '.join(mitres) or 'n/a'}. "
            f"This is a LEGITIMATE Windows binary that attackers abuse to masquerade as normal "
            f"activity — its mere presence is not malicious, but the abuse patterns above are high-fidelity.")
    cards.append({"source": "LOLBAS", "binary": name, "mitre": mitres, "categories": cats,
                  "detection": dets[:3], "text": text})

gm = SentenceTransformer("google/embeddinggemma-300m", device="cuda")


def emb(texts):
    for kw in ({"prompt_name": "Retrieval"}, {}):
        try:
            return np.asarray(gm.encode(texts, normalize_embeddings=True, batch_size=64,
                                        show_progress_bar=False, **kw), np.float32)
        except Exception:
            continue
    raise RuntimeError("encode failed")


E = emb([c["text"] for c in cards])
np.save(os.path.join(OUT, "emb.npy"), E)
with open(os.path.join(OUT, "cards.jsonl"), "w") as f:
    for c in cards:
        f.write(json.dumps(c) + "\n")

# content hash over the sorted card texts = the attestable knowledge-base fingerprint
kb_hash = hashlib.sha256("\n".join(sorted(c["text"] for c in cards)).encode()).hexdigest()
meta = {"source": "LOLBAS", "n_cards": len(cards), "dim": int(E.shape[1]),
        "embedder": "google/embeddinggemma-300m", "kb_sha256": kb_hash}
json.dump(meta, open(os.path.join(OUT, "index_meta.json"), "w"), indent=1)
print(json.dumps(meta, indent=1))
# sanity: retrieve for the wuauclt alert
q = emb(["Execution evasion imageload wuauclt.exe loaded a dll"])[0]
sims = E @ q
top = np.argsort(-sims)[:3]
print("\ntop-3 retrieved for the wuauclt masquerade alert:")
for i in top:
    print(f"  {sims[i]:.3f}  {cards[i]['binary']}  {cards[i]['text'][:80]}")
