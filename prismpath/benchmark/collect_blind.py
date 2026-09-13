# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""collect_blind.py — VERIFY a second annotator's blind answers and convert them to an annotation file.

Reads the blind sheet (make_blind.py) and an answers file — one JSON object per line, each carrying an
`i` (the case index) and a `choice` (the edge NUMBER, 1..N, as shown in the sheet). Verifies every case
is answered exactly once with an in-range choice (no silent drops, no invented cases — the second
annotator's output is not trusted blindly), then writes a benchmark-shaped annotation file
`{flow, node, outcome, label, stratum}` that `prismpath kappa` compares against the first annotator.

    python prismpath/benchmark/collect_blind.py <answers.jsonl> --out prismpath/benchmark/gate_zero/annot_agy.jsonl
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from prismpath.evals.annotate import blind_cases

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.join(HERE, "routing_bench.jsonl")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("answers", help="the second annotator's answers JSONL ({i, choice} per line)")
    ap.add_argument("--out", required=True, help="write the benchmark-shaped annotation file here")
    ap.add_argument("--drop-invalid", action="store_true",
                    help="instead of failing, EXCLUDE cases the annotator answered out-of-range or not "
                         "at all, and report them; κ is then computed over the validly-labeled subset "
                         "(align() drops unmatched). Use when a model produced a few bad picks.")
    ap.add_argument("--split-compound", action="append", default=[], metavar="FLOW/NODE[:POS]",
                    help="declare that on this node the annotator read a COMPOUND ('A or B') edge as two "
                         "separately-numbered reasons, so every pick shifted up by one past that edge. "
                         "POS is the 1-indexed edge to treat as split (default: the first disjunctive "
                         "edge). Remaps ALL of that node's picks (valid range becomes 1..N+1) and REPORTS "
                         "every remap — explicit + auditable, never applied without you naming the node. "
                         "See gate_zero/findings.md for why billing needed it.")
    args = ap.parse_args()

    # parse the node specs: {(flow, node): compound_edge_pos_or_None}
    split_nodes = {}
    for spec in args.split_compound:
        key, _, pos = spec.partition(":")
        flow, _, node = key.partition("/")
        if not flow or not node:
            print(f"  ✗ --split-compound {spec!r}: expected FLOW/NODE[:POS]"); return 1
        split_nodes[(flow, node)] = int(pos) if pos else None

    cases = list(blind_cases(BENCH))                       # authoritative order + valid targets
    gold = [json.loads(line) for line in open(BENCH, encoding="utf-8") if line.strip()]

    answers = {}
    for ln, line in enumerate(open(args.answers, encoding="utf-8"), 1):
        line = line.strip()
        if not line:
            continue
        try:
            answer = json.loads(line)
        except ValueError as error:
            print(f"  ✗ line {ln}: not JSON ({error})"); return 1
        if "i" not in answer or "choice" not in answer:
            print(f"  ✗ line {ln}: needs both 'i' and 'choice' — got {sorted(answer)}"); return 1
        answers[int(answer["i"])] = int(answer["choice"])

    def split_pos(case):
        """The 1-indexed compound-edge position to expand for this node, or None if the node isn't
        declared --split-compound. Uses the declared POS, else the first disjunctive ('… or …') edge."""
        declared = split_nodes.get((case["flow"], case["node"]), "absent")
        if declared == "absent":
            return None
        if declared is not None:
            return declared
        for edge_position, (_t, condition) in enumerate(case["edges"], 1):
            if " or " in condition.lower():
                return edge_position
        return None

    def resolve_pick(case_index):
        """Map answers[i] -> a target. On a --split-compound node the compound edge occupies TWO adjacent
        slots (its two disjuncts) so every pick past it shifts up by one; valid range is 1..N+1.
        Returns (target, note) or (None, reason)."""
        case = cases[case_index]
        edge_count = len(case["edges"])
        choice = answers.get(case_index)
        if choice is None:
            return None, "unanswered"
        split_position = split_pos(case)
        if split_position is None:
            if 1 <= choice <= edge_count:
                return case["targets"][choice - 1], None
            return None, f"case {case_index}: choice {choice} out of range 1..{edge_count}"
        # compound edge at position p spans slots p and p+1; later edges shift back one:
        #   v <= p    -> targets[v-1]   (before, or the compound edge's 1st disjunct)
        #   v == p+1  -> targets[p-1]   (the compound edge's 2nd disjunct)
        #   v  > p+1  -> targets[v-2]   (a later edge)
        if not (1 <= choice <= edge_count + 1):
            return None, f"case {case_index}: choice {choice} out of range 1..{edge_count+1} (split node)"
        idx = choice - 1 if choice <= split_position else (split_position - 1 if choice == split_position + 1 else choice - 2)
        tgt = case["targets"][idx]
        note = None
        if choice >= split_position + 1:  # only the shifted picks are a genuine reinterpretation worth reporting
            cond = case["edges"][split_position - 1][1]
            note = (f"case {case_index} [{case['flow']}/{case['node']}]: pick {choice} under compound-split of edge "
                    f"{split_position} (\"{cond[:44]}\") -> {tgt}")
        return tgt, note

    remaps, problems, labels = [], [], {}
    for case_index in range(len(cases)):
        tgt, note = resolve_pick(case_index)
        if tgt is None:
            problems.append(note)
        else:
            labels[case_index] = tgt
            if note:
                remaps.append(note)
    extra = [case_index for case_index in answers if case_index >= len(cases)]
    if extra:
        problems.append(f"answers for nonexistent cases: {extra[:10]}")

    if remaps:
        print(f"↺ compound-split remap applied to {len(remaps)} pick(s) (auditable):")
        for r in remaps[:30]:
            print(f"    {r}")
    if problems and not args.drop_invalid:
        print(f"VERIFICATION FAILED — {len(problems)} problem(s) "
              f"(use --split-compound for disjunctive-edge picks, or --drop-invalid to exclude + proceed):")
        for problem in problems[:25]:
            print(f"  ✗ {problem}")
        return 1

    with open(args.out, "w", encoding="utf-8") as handle:
        for case_index in sorted(labels):
            handle.write(json.dumps({"flow": cases[case_index]["flow"], "node": cases[case_index]["node"],
                                "outcome": cases[case_index]["outcome"], "label": labels[case_index],
                                "stratum": gold[case_index].get("stratum")}, ensure_ascii=False) + "\n")
    dropped = len(cases) - len(labels)
    if dropped:
        print(f"⚠ excluded {dropped} out-of-range/unanswered case(s): "
              f"{[case_index for case_index in range(len(cases)) if case_index not in labels][:20]}")
    print(f"✓ wrote {len(labels)} labeled cases -> {args.out}"
          f"{' (κ over this subset)' if dropped else ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
