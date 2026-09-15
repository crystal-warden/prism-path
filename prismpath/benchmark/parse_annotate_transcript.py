# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""parse_annotate_transcript.py — recover annotations from a saved `prismpath annotate` TERMINAL transcript.

If an annotator pastes/saves the interactive session's scrollback (the prompts + their `pick>` lines)
instead of the clean `--out` JSONL, the labels are still fully recoverable: `prismpath annotate` presents
cases in `blind_cases()` order, so the k-th `pick>` maps to the k-th benchmark case. This script aligns
them RIGOROUSLY — it verifies each transcript block's `[flow/node]` header matches the corresponding
benchmark case before trusting the pick — and emits the clean benchmark-shaped annotation file. The
outcome/stratum are taken from the BENCHMARK (authoritative + un-wrapped), so the alignment key matches
`prismpath kappa` exactly.

    python prismpath/benchmark/parse_annotate_transcript.py <transcript> --out prismpath/benchmark/gate_zero/annot_human.jsonl
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

from prismpath.evals.annotate import blind_cases, _resolve

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.join(HERE, "routing_bench.jsonl")

HEAD = re.compile(r"^\[([^/\]]+)/([^\]]+)\]\s*\((\w+)\)\s*$")
PICK = re.compile(r"^pick>\s*(.+?)\s*$")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("transcript")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    cases = list(blind_cases(BENCH))
    gold = [json.loads(line) for line in open(BENCH, encoding="utf-8") if line.strip()]

    # Walk the transcript; pair each block header with the pick that closes it, in order.
    pairs = []            # (flow, node, raw_pick)
    cur = None
    for line in open(args.transcript, encoding="utf-8"):
        header = HEAD.match(line.rstrip("\n"))
        if header:
            cur = (header.group(1), header.group(2))
            continue
        pick = PICK.match(line.rstrip("\n"))
        if pick:
            if cur is None:
                print(f"  ✗ a `pick>` with no preceding [flow/node] header near: {line.strip()!r}")
                return 1
            pairs.append((cur[0], cur[1], pick.group(1)))
            cur = None

    if len(pairs) != len(cases):
        print(f"  ✗ transcript has {len(pairs)} answered cases; benchmark has {len(cases)}. "
              f"Alignment needs a 1:1, in-order match (were any cases skipped?).")
        return 1

    out_recs, mism = [], []
    for case_index, ((flow, node, raw), case) in enumerate(zip(pairs, cases)):
        if (flow, node) != (case["flow"], case["node"]):
            mism.append(f"case {case_index}: transcript [{flow}/{node}] vs benchmark [{case['flow']}/{case['node']}]")
            continue
        target = _resolve(raw, case["targets"])
        if target is None:
            mism.append(f"case {case_index} [{flow}/{node}]: pick {raw!r} is not a valid edge "
                        f"(targets: {case['targets']})")
            continue
        out_recs.append({"flow": case["flow"], "node": case["node"], "outcome": case["outcome"],
                         "label": target, "stratum": gold[case_index].get("stratum")})

    if mism:
        print(f"VERIFICATION FAILED — {len(mism)} misalignment(s):")
        for message in mism[:25]:
            print(f"  ✗ {message}")
        return 1

    with open(args.out, "w", encoding="utf-8") as handle:
        for record in out_recs:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(f"✓ verified {len(out_recs)} cases (headers aligned, picks in-range); wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
