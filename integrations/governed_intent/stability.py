# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Re-embedding stability: do the same inputs give the same integer fields, run after run and across
CPU thread counts? Each measurement is its own process (a fresh model and a fresh torch state).

    python -m integrations.governed_intent.stability measure --threads 4 --out FILE.json
    python -m integrations.governed_intent.stability compare FILE.json FILE.json ...

`measure` reads every case of every set (the inputs the reader embeds: each task, each reply and each
proposed call) and records the integer fields and the sha256 of every raw float32 embedding, so a
difference shows both at the bit level and where it reaches the policy. `compare` reports, against the
first file, every differing field with its size and how many embeddings were not bit identical.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from . import cases as case_sets
from . import intent_reader as ir


def measure(threads: int, out: Path) -> None:
    import numpy as np
    import torch
    reader = ir.verified_reader(threads)
    if not reader.verified:
        raise SystemExit(f"not verified: {reader.reason}")
    inner, vectors = reader.embed, {}

    def embed(texts):
        got = inner(texts)
        for text, vector in zip(texts, got):
            vectors[text] = hashlib.sha256(np.asarray(vector, dtype="<f4").tobytes()).hexdigest()
        return got
    embed.weights = inner.weights
    reader.embed = embed
    fields = {}
    for case in case_sets.build():
        if case.calls:
            for at, call in enumerate(case.calls):
                fields[f"{case.id}#{at}"] = reader.read_call(case.task, json.dumps(call), call)
        else:
            fields[case.id] = reader.read_response(case.reply, json.loads(case.reply).get("final"))
    out.write_text(json.dumps({"threads": threads, "torch_threads": torch.get_num_threads(),
                               "fields": fields, "vectors": vectors}, indent=0))


def compare(paths) -> dict:
    runs = [json.loads(Path(path).read_text()) for path in paths]
    first = runs[0]
    report = {"runs": [{"file": str(path), "threads": run["threads"], "torch_threads": run["torch_threads"]}
                       for path, run in zip(paths, runs)], "readings": len(first["fields"]),
              "embeddings": len(first["vectors"]), "differences": []}
    for path, run in zip(paths[1:], runs[1:]):
        field_diffs = []
        for key, want in first["fields"].items():
            got = run["fields"][key]
            for name in want:
                if got[name] != want[name]:
                    size = got[name] - want[name] if isinstance(want[name], int) else None
                    field_diffs.append({"reading": key, "field": name, "first": want[name], "this": got[name],
                                        "delta": size})
        vector_diffs = sum(run["vectors"].get(text) != digest for text, digest in first["vectors"].items())
        report["differences"].append({"file": str(path), "threads": run["threads"], "field_differences": len(field_diffs),
                                      "max_abs_bp_delta": max((abs(d["delta"]) for d in field_diffs if d["delta"] is not None), default=0),
                                      "class_changes": sum(d["field"] == "intent_class" for d in field_diffs),
                                      "embeddings_not_bit_identical": vector_diffs, "examples": field_diffs[:10]})
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    one = sub.add_parser("measure")
    one.add_argument("--threads", type=int, required=True)
    one.add_argument("--out", required=True)
    many = sub.add_parser("compare")
    many.add_argument("files", nargs="+")
    args = parser.parse_args(argv)
    if args.cmd == "measure":
        measure(args.threads, Path(args.out))
        return 0
    print(json.dumps(compare(args.files), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
