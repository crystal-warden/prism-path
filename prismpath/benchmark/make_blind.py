# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""make_blind.py — emit a BLIND annotation sheet from the routing benchmark, for a second annotator.

The gate-zero design (annotate.py) steps a human through each case with the AI label hidden. When a
second *human* isn't available, an independent model can serve as the second annotator — a
human-vs-independent-model agreement figure, which is stronger than the AI-vs-AI upper bound already
disclosed (one side is now human ground truth), though NOT a substitute for inter-human reliability.

This script writes the same blind view `annotate.present()` shows a human — the node instruction, the
outcome, and the NUMBERED out-edges — with the gold label stripped, one self-contained JSON object per
case. Give ONLY this file to the second annotator (keep `routing_bench.jsonl` out of its reach so the
answer key can't leak). Its answers (`{"i": <index>, "choice": <edge number>}` per line) convert back
to a benchmark-shaped annotation file via `collect_blind.py`, which `prismpath kappa` then compares.

    python prismpath/benchmark/make_blind.py            # -> prismpath/benchmark/gate_zero/blind_cases.jsonl
"""
from __future__ import annotations

import json
import os

from prismpath.annotate import blind_cases

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.join(HERE, "routing_bench.jsonl")
OUT_DIR = os.path.join(HERE, "gate_zero")
OUT = os.path.join(OUT_DIR, "blind_cases.jsonl")


def main() -> None:
    os.makedirs(OUT_DIR, exist_ok=True)
    n = 0
    with open(OUT, "w", encoding="utf-8") as f:
        for i, case in enumerate(blind_cases(BENCH)):
            # exactly the human's information: flow/node context, instruction, outcome, numbered edges.
            # NO label, NO stratum hint about the answer.
            rec = {
                "i": i,
                "flow": case["flow"],
                "node": case["node"],
                "instruction": case["instruction"],
                "outcome": case["outcome"],
                "choices": [{"n": j + 1, "target": t, "condition": c}
                            for j, (t, c) in enumerate(case["edges"])],
            }
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            n += 1
    print(f"wrote {OUT}  ({n} blind cases)")


if __name__ == "__main__":
    main()
