#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""run_vectors.py — certify the C target against the frozen conformance corpus.

For every vector inside the declared v0 subset (TABLE_FORMAT.md), compile the condition/flow
to a PPT image, run the C interpreter, and diff against the recorded expectation. Vectors
outside the subset are excluded WITH a reason and counted — the exclusion report is part of
the certificate, because a subset you don't state is a claim you can't defend.

Also gates determinism: every image is compiled twice and must be byte-identical (the
"reproducible compile" leg of the demo's proof stack).

Exit 0 iff every in-subset vector passes.
"""
from __future__ import annotations

import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
BUILD = HERE / "build"
INTERP = BUILD / "interp"                               # --interp <path> certifies another binary (interp_hdr)
if "--interp" in sys.argv:
    INTERP = Path(sys.argv[sys.argv.index("--interp") + 1]).resolve()

import ppt_compile as pc                                   # noqa: E402
from prismpath.kernel.parser import parse                         # noqa: E402

CONF = Path(pc._REPO) / "portable" / "conformance"    # pc._REPO is the package dir (matches tb/)


def _subset_scalar_ok(value) -> str | None:
    """None if a ctx/script value is in the v0 domain, else the exclusion reason."""
    if value is None or isinstance(value, (bool, str)):
        return None
    if isinstance(value, int):
        return None if pc.I32_MIN <= value <= pc.I32_MAX else "int-out-of-i32"
    if isinstance(value, float):
        return "float-value"
    return "non-scalar-value"


def run_interp(mode: str, image: Path, payload: Path) -> str:
    out = subprocess.run([str(INTERP), mode, str(image), str(payload)],
                         capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"interp failed: {out.stderr.strip()}")
    return out.stdout.strip()


# ---------------------------------------------------------------- predicate vectors

def cert_predicates() -> tuple:
    doc = json.loads((CONF / "predicates.json").read_text())
    cases = doc["cases"]
    excluded: Counter = Counter()
    passed = failed = 0
    failures = []
    img_cache: dict = {}

    for case_index, case in enumerate(cases):
        cond, ctx, expect = case["cond"], case["ctx"], case["expect"]
        try:
            if cond not in img_cache:
                img = pc.compile_predicate(cond)
                blob = img.serialize()
                if blob != pc.compile_predicate(cond).serialize():
                    raise RuntimeError(f"non-deterministic compile: {cond!r}")
                path = BUILD / "pred.ppt"
                path.write_bytes(blob)
                img_cache[cond] = (img, blob)
            img, blob = img_cache[cond]
            (BUILD / "pred.ppt").write_bytes(blob)
            # only fields the condition reads are subset-relevant
            regs = pc.encode_regs(img, ctx, node_idx=0)
        except pc.SubsetError as error:
            excluded[error.reason] += 1
            continue
        (BUILD / "pred_regs.bin").write_bytes(regs)
        out = run_interp("eval", BUILD / "pred.ppt", BUILD / "pred_regs.bin")
        got = out.startswith("match")
        if expect == "ERROR":       # unreachable: ERROR conds never classify as Level M
            raise RuntimeError(f"ERROR case survived the subset filter: {cond!r}")
        if got == expect:
            passed += 1
        else:
            failed += 1
            failures.append((case_index, cond, ctx, expect, got))
    return passed, failed, excluded, failures


# ---------------------------------------------------------------- engine vectors

def flow_subset_reason(case: dict) -> str | None:
    if "start" in case or "state" in case:
        return "resume-fixture"
    exp = case["expect"]
    if exp["stopped"] not in ("terminal", "stuck", "max_steps"):
        return f"outcome-{exp['stopped']}"
    if exp["pending_node"] is not None or exp["spawn"] is not None:
        return "pending-outcome"
    return None


def cert_flows() -> tuple:
    doc = json.loads((CONF / "flows.json").read_text())
    cases = doc["cases"]
    excluded: Counter = Counter()
    passed = failed = 0
    failures = []

    for case in cases:
        reason = flow_subset_reason(case)
        if reason:
            excluded[reason] += 1
            continue
        graph = parse(case["flow"])
        try:
            img = pc.compile_flow(graph, case.get("maxSteps", 25))
            blob = img.serialize()
            if blob != pc.compile_flow(graph, case.get("maxSteps", 25)).serialize():
                raise RuntimeError(f"non-deterministic compile: {case['name']}")
            script = pc.encode_script(img, case["script"])
        except pc.SubsetError as error:
            excluded[error.reason] += 1
            continue
        (BUILD / "flow.ppt").write_bytes(blob)
        (BUILD / "flow_script.bin").write_bytes(script)
        out = run_interp("run", BUILD / "flow.ppt", BUILD / "flow_script.bin")
        names = [name for name, _ in img.nodes]
        path, stopped = [], None
        for line in out.splitlines():
            kind, _, val = line.partition(" ")
            if kind == "N":
                path.append(names[int(val)])
            elif kind == "S":
                stopped = val
        exp = case["expect"]
        if path == exp["path"] and stopped == exp["stopped"]:
            passed += 1
        else:
            failed += 1
            failures.append((case["name"], exp["path"], exp["stopped"], path, stopped))
    return passed, failed, excluded, failures


def main() -> int:
    BUILD.mkdir(exist_ok=True)
    if not INTERP.exists():
        print(f"{INTERP} missing — run `make` first", file=sys.stderr)
        return 2

    pred_passed, pred_failed, pred_excluded, pred_failures = cert_predicates()
    flow_passed, flow_failed, flow_excluded, flow_failures = cert_flows()

    print("── predicate vectors ─────────────────────────────")
    print(f"  total {pred_passed + pred_failed + sum(pred_excluded.values())}   in-subset {pred_passed + pred_failed}   "
          f"pass {pred_passed}   FAIL {pred_failed}   excluded {sum(pred_excluded.values())}")
    for reason, count in sorted(pred_excluded.items(), key=lambda entry: -entry[1]):
        print(f"    excluded {count:4d}  {reason}")
    for case_index, cond, ctx, want, got in pred_failures[:20]:
        print(f"    ✗ case {case_index}: {cond!r}  ctx={ctx}  want={want} got={got}")

    print("── engine vectors ────────────────────────────────")
    print(f"  total {flow_passed + flow_failed + sum(flow_excluded.values())}   in-subset {flow_passed + flow_failed}   "
          f"pass {flow_passed}   FAIL {flow_failed}   excluded {sum(flow_excluded.values())}")
    for reason, count in sorted(flow_excluded.items(), key=lambda entry: -entry[1]):
        print(f"    excluded {count:4d}  {reason}")
    for name, want_path, want_stopped, got_path, got_stopped in flow_failures:
        print(f"    ✗ {name}: want path={want_path} stopped={want_stopped}\n"
              f"               got path={got_path} stopped={got_stopped}")

    ok = (pred_failed == 0 and flow_failed == 0)
    print(f"\n{'✅ ' + INTERP.name + ' CONFORMANT on the declared subset' if ok else '✗ ' + INTERP.name + ' NOT CONFORMANT'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
