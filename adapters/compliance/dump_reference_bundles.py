#!/usr/bin/env python3
"""Dump the EXACT (control, objectives, methods, retrieved-evidence) bundles gemma adjudicated, so agy
can independently assess the identical inputs — an apples-to-apples reference for the differential test."""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import compliance_adapter as ca
import ingest_company as ic

ca.use_standard("nist_800171_r2")
docs = ic.load_docs()
import collections, math
df = collections.Counter()
for d in docs:
    for t in d["tf"]:
        df[t] += 1
idf = {t: math.log(1 + len(docs) / (1 + c)) for t, c in df.items()}

outdir = os.path.join(HERE, "efficacy", "reference", "bundles")
os.makedirs(outdir, exist_ok=True)
manifest = []
for cid in ic.breadth_controls():
    c = ca.get_control(cid)
    hits = ic.retrieve(c, docs, idf)
    bundle = {
        "control_id": cid, "title": c["title"], "family": c["family_name"],
        "method_profile": ca._method_profile(c), "methods": c.get("methods", []),
        "control_statement": c["control"],
        "objectives": [{"id": o["id"], "text": o["text"]} for o in c["objectives"]],
        "boundary": "Meridian Aerospace CUI environment",
        "evidence": [{"source": h["name"], "text": h["text"][:ic.MAX_EXCERPT]} for h in hits],
    }
    json.dump(bundle, open(os.path.join(outdir, f"{cid}.json"), "w"), indent=1)
    manifest.append({"control": cid, "family": c["family_name"], "n_evidence": len(hits)})
json.dump(manifest, open(os.path.join(HERE, "efficacy", "reference", "_manifest.json"), "w"), indent=1)
print("wrote %d reference bundles to %s" % (len(manifest), outdir))
