#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Dump the EXACT (control, objectives, methods, retrieved-evidence) bundles gemma adjudicated, so agy
can independently assess the identical inputs — an apples-to-apples reference for the differential test."""
import os, json
HERE = os.path.dirname(os.path.abspath(__file__))
from adapters.compliance import compliance_adapter as ca
from adapters.compliance import ingest_company as ic

ca.use_standard("nist_800171_r2")
docs = ic.load_docs()
import collections, math
df = collections.Counter()
for document in docs:
    for term in document["tf"]:
        df[term] += 1
idf = {term: math.log(1 + len(docs) / (1 + document_frequency)) for term, document_frequency in df.items()}

outdir = os.path.join(HERE, "efficacy", "reference", "bundles")
os.makedirs(outdir, exist_ok=True)
manifest = []
for cid in ic.breadth_controls():
    control = ca.get_control(cid)
    hits = ic.retrieve(control, docs, idf)
    bundle = {
        "control_id": cid, "title": control["title"], "family": control["family_name"],
        "method_profile": ca._method_profile(control), "methods": control.get("methods", []),
        "control_statement": control["control"],
        "objectives": [{"id": objective["id"], "text": objective["text"]} for objective in control["objectives"]],
        "boundary": "Meridian Aerospace CUI environment",
        "evidence": [{"source": hit["name"], "text": hit["text"][:ic.MAX_EXCERPT]} for hit in hits],
    }
    json.dump(bundle, open(os.path.join(outdir, f"{cid}.json"), "w"), indent=1)
    manifest.append({"control": cid, "family": control["family_name"], "n_evidence": len(hits)})
json.dump(manifest, open(os.path.join(HERE, "efficacy", "reference", "_manifest.json"), "w"), indent=1)
print("wrote %d reference bundles to %s" % (len(manifest), outdir))
