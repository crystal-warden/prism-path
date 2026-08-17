#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Compile the frozen predicate corpus for fabric certification: same subset filter as the
C-target's run_vectors.cert_predicates, bundling in-subset (image, ctx, expect) for the board
to eval on silicon. Exclusions itemized with reasons — the exclusion report is part of the cert."""
import json, sys
from collections import Counter
from pathlib import Path
HW = Path("prismpath-hw"); sys.path.insert(0, str(HW)); sys.path.insert(0, ".")
import ppt_compile as pc
CONF = Path("prismpath/portable/conformance")

cases = json.loads((CONF / "predicates.json").read_text())["cases"]
excluded = Counter()
images = {}            # cond -> {ppt_hex, json}
vectors = []           # {cid, ctx, expect}
for case in cases:
    cond, ctx, expect = case["cond"], case["ctx"], case["expect"]
    try:
        img = pc.compile_predicate(cond)
        blob = img.serialize()
        if blob != pc.compile_predicate(cond).serialize():
            raise RuntimeError(f"non-deterministic compile: {cond!r}")
        pc.encode_regs(img, ctx, node_idx=0)      # subset check on the ctx (raises SubsetError)
    except pc.SubsetError as e:
        excluded[e.reason] += 1
        continue
    if cond not in images:
        # node 0 edge 0 target is the "match" node (== 1 by compile_predicate construction)
        dbg = img.debug()
        images[cond] = {"ppt_hex": blob.hex(), "json": dbg}
    vectors.append({"cid": cond, "ctx": ctx, "expect": bool(expect)})

out = {"vectors": vectors, "images": images, "excluded": dict(excluded), "total_cases": len(cases)}
Path(sys.argv[1]).write_text(json.dumps(out))
print(f"in-subset vectors: {len(vectors)}  unique images: {len(images)}  excluded: {sum(excluded.values())}")
print("exclusion reasons:", dict(excluded.most_common()))
