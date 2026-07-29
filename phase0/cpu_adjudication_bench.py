#!/usr/bin/env python3
"""Phase 0 — can the air-gapped CPU regime run P2 (LLM compliance adjudication)?

Runs PrismPath's NIST 800-171 compliance adjudicator against an OpenAI-compatible endpoint
(point it at a CPU llama.cpp llama-server) over the three labeled sample requests and reports,
per control: wall-clock latency, schema-validity, and whether the model reached the correct
verdict. This is the empirical answer to llmfit's tier question: P2-on-CPU, or P1-only?

Usage:
  PRISMPATH_LLM_ENDPOINT=http://127.0.0.1:8099/v1/chat/completions \
  PRISMPATH_LLM_MODEL=qwen2.5-3b \
  python phase0/cpu_adjudication_bench.py

The endpoint/model env vars are read by compliance_adapter at import, so they must be set first.
Portable: this same script is the representative test to re-run on the N150 (real x86 floor).
"""
import os, sys, json, time, statistics

REPO = "/home/cwadmin/cwprojects/prismpath"
CADIR = os.path.join(REPO, "adapters", "compliance")
sys.path.insert(0, REPO)
sys.path.insert(0, CADIR)

ENDPOINT = os.environ.get("PRISMPATH_LLM_ENDPOINT", "(default GPU factory)")
MODELNM = os.environ.get("PRISMPATH_LLM_MODEL", "gemma4")

import compliance_adapter as ca  # noqa: E402 — must import AFTER env is set

# sample request file -> expected ground-truth verdict (from the filename convention)
EXPECT = {
    "req_3.1.11_met.json": "met",
    "req_3.1.12_partial.json": "partially-met",
    "req_3.1.5_notmet.json": "not-met",
}
REQUIRED_KEYS = {"status", "unmet_objective_ids", "gap_summary"}


def run():
    print(f"# Phase 0 — P2-on-CPU compliance adjudication")
    print(f"# endpoint : {ENDPOINT}")
    print(f"# model    : {MODELNM}")
    print(f"# standard : {ca.active_standard()}\n")
    rows, lats = [], []
    for fname, expected in EXPECT.items():
        req = json.load(open(os.path.join(CADIR, "requests", fname)))
        control = ca.get_control(req["control_id"])
        t0 = time.perf_counter()
        try:
            det = ca.adjudicate(control, req)
        except Exception as e:
            det, err = None, repr(e)[:120]
        dt = time.perf_counter() - t0
        lats.append(dt)
        if det is None:
            rows.append((req["control_id"], expected, "ERROR", False, False, dt,
                         locals().get("err", "returned None")))
            continue
        valid = REQUIRED_KEYS.issubset(det.keys()) and det.get("status") in (
            "met", "partially-met", "not-met")
        got = det.get("status", "?")
        correct = (got == expected)
        rows.append((req["control_id"], expected, got, valid, correct, dt,
                     (det.get("gap_summary") or "")[:70]))

    # table
    print(f"{'control':9} {'expected':14} {'got':14} {'valid':6} {'correct':8} {'sec':>7}  gap_summary")
    print("-" * 100)
    for cid, exp, got, valid, correct, dt, note in rows:
        print(f"{cid:9} {exp:14} {got:14} {'✓' if valid else '✗':6} "
              f"{'✓' if correct else '✗':8} {dt:7.2f}  {note}")
    n = len(rows)
    n_valid = sum(1 for r in rows if r[3])
    n_correct = sum(1 for r in rows if r[4])
    print("-" * 100)
    print(f"\nschema-valid : {n_valid}/{n}")
    print(f"correct verdict : {n_correct}/{n}")
    print(f"latency (s)  : min {min(lats):.2f}  median {statistics.median(lats):.2f}  "
          f"max {max(lats):.2f}  mean {statistics.mean(lats):.2f}")
    print("\n# UX bar: a compliance assessor waits per-control; <~15s feels interactive, "
          ">~60s is batch-only.")


if __name__ == "__main__":
    run()
