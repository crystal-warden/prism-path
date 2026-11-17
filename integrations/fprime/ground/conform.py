#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The cross framework conformance check: the F Prime guard's receipts against the cFS app's.

The claim is that the same proposals give the same decisions and the same receipts, byte for byte, in the two
frameworks, because both run the same C (integrations/cfs/prismpath_app/fsw/src). Two things stand for "the cFS
app's receipts" here, and neither shares code with the C:

  * `integrations.cfs.ground.reference`, the Python reference writer, which `integrations/cfs/tests/test_cfs_run.py`
    holds the cFS app's C to, line by line;
  * optionally a run directory taken from a real cFS run (`--cfs-run`), whose first receipts are the S1 sequence.

The one member of a receipt that may differ is `decider`, which names the framework (`cfs:prismpath_app` or
`fprime:prismpath_guard`). Everything else, the case, the image hash, the reading hash and the decision, has to be
identical, so the comparison replaces the decider by the cFS name and then compares bytes.

    python -m integrations.fprime.ground.conform RUN [--cfs-run CFSRUN]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from integrations.cfs.ground import reference  # noqa: E402
from prismpath.agent.policy import Policy  # noqa: E402
from prismpath.ledgers import core_evidence  # noqa: E402

FPRIME_DECIDER = "fprime:prismpath_guard"


def as_cfs(line: bytes) -> bytes:
    """The line with its decider spelled as the cFS app's. Nothing else changes."""
    old = f'"decider":"{FPRIME_DECIDER}"'.encode()
    assert line.count(old) == 1, line
    return line.replace(old, f'"decider":"{reference.DECIDER}"'.encode())


def payload_of_args(args: bytes) -> bytes:
    """The cFS payload (little endian, at the layout's offsets) for the big endian argument bytes of a proposed
    command, as the guard reads it: every field the arguments hold completely, none past the first that is cut."""
    out, used = bytearray(10), 0
    end = 0
    for _name, kind, off, width in reference.layout():
        if kind == "MONITOR":                    # the app's field: no command argument carries it
            continue
        if used + width > len(args):
            break
        out[off:off + width] = args[used:used + width][::-1]
        used += width
        end = off + width
    return bytes(out[:end])


def compare(run: Path, policy: Policy, version: int, payloads: List[bytes], cfs_run: Path = None) -> List[str]:
    """Differences between the run's receipts and the reference's for these payloads (empty when none)."""
    lines = core_evidence._lines(Path(run) / "receipts.jsonl")
    problems = []
    if len(lines) != len(payloads):
        problems.append(f"{len(lines)} receipts for {len(payloads)} proposals")
    for idx, (line, payload) in enumerate(zip(lines, payloads)):
        want = reference.receipt_line(policy, idx, f"v{version}", idx, payload)
        if as_cfs(line) != want:
            problems.append(f"receipt {idx} differs from the reference:\n  fprime: {line.decode()}\n  cfs:    {want.decode()}")
    if cfs_run is not None:
        theirs = core_evidence._lines(Path(cfs_run) / "receipts.jsonl")
        for idx, (line, other) in enumerate(zip(lines, theirs)):
            if as_cfs(line) != other:
                problems.append(f"receipt {idx} differs from the cFS run's:\n  fprime: {line.decode()}\n  cfs:    {other.decode()}")
    return problems


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("run", type=Path, help="the guard's run directory")
    parser.add_argument("--cfs-run", type=Path, default=None, help="a run directory from a real cFS run of the S1 sequence")
    args = parser.parse_args(argv)
    from integrations.cfs.prismpath_app.policy import gen_image
    from integrations.cfs.tests import run_scenario
    policy = Policy.load(gen_image.CORE)
    payloads = [run_scenario.payload_of(case) for _n, case in run_scenario.SEQUENCE]
    problems = compare(args.run, policy, gen_image.VERSION, payloads, args.cfs_run)
    print("\n".join(problems) if problems else f"{len(payloads)} receipts identical to the cFS app's, decider aside")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
