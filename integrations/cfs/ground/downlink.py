#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Verify a run downlinked from the PrismPath cFS app, on the ground.

    python -m integrations.cfs.ground.downlink FROM RUN --keys KEYS

FROM is the app's run directory as it came down (`/cf/pprun` onboard), and RUN is where the ground keeps it. It is
already a signed core run in the layout `prismpath evidence verify` reads: the app wrote every receipt, the cases
file, the image attestations, the manifest and the root statement, and signed the statement itself with the
instance key. Nothing is reconstructed. `fetch` copies it, giving one file its core run name back: OSAL limits a
file name to 19 characters, so onboard the root statement is `roots.jsonl`, and here it is `receipts.roots.jsonl`,
the same bytes. (`cases.stream`, the cases file while it grows, is not part of the run and stays behind.) Then two
checks:

  1. the repository's verifier, `prismpath.ledgers.core_evidence.verify`, with both keys pinned to the ground's
     own copies (`KEYS/authority.pub`, `KEYS/instance.pub`) and every receipt replayed through the reference
     kernel (`--sample all`): the same check `prismpath evidence verify RUN --sample all --pin-authority ...
     --pin-instance ...` makes;
  2. the root history, `roots.log.jsonl`: every root statement the app sealed, in order, each signed with the
     pinned instance key over its own domain and body, each a `prismpath.core-run-root/2` statement whose root is
     the RFC 6962 root of the first `leaves` receipts of the run, the counts never going back, and the last one
     the run's root statement. A statement sealed before a processor reset is then a root of a prefix of the
     receipts after it, which is what "the receipts continue across the reset" means.

Each earlier statement's `policy` member binds the manifest as it stood when it was sealed, which a later seal
replaced, so for those only the signature, the root and the count are checked; the last is checked in full by 1.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from prismpath.kernel import canon2  # noqa: E402
from prismpath.ledgers import core_evidence, root_statement  # noqa: E402


class Bad(Exception):
    """A downlinked run the ground refuses."""


ONBOARD_NAMES = {"roots.jsonl": "receipts.roots.jsonl"}
LEFT_BEHIND = ("cases.stream",)


def fetch(source: Path, run: Path) -> Path:
    """Copy a downlinked run directory to `run`, each file under its core run name."""
    source, run = Path(source), Path(run)
    run.mkdir(parents=True, exist_ok=False)
    for path in sorted(source.iterdir()):
        if path.is_file() and path.name not in LEFT_BEHIND:
            (run / ONBOARD_NAMES.get(path.name, path.name)).write_bytes(path.read_bytes())
    return run


def root_history(run: Path, instance_pub: bytes) -> List[Dict]:
    """Every sealed root statement, checked as the module says, or Bad."""
    _Priv, _Pub, _ser, InvalidSignature = root_statement._ed25519()
    key = core_evidence._public_key(instance_pub, "instance")
    leaves = [core_evidence.sha256_hex(line) for line in core_evidence._lines(run / "receipts.jsonl")]
    lines = core_evidence._lines(run / "roots.log.jsonl")
    if not lines:
        raise Bad("the run has no sealed root statement")
    out, last = [], -1
    for number, line in enumerate(lines):
        statement = canon2.loads(line)
        if canon2.dumps(statement) != line or set(statement) != set(core_evidence.ROOT_MEMBERS) \
                or statement["format"] != core_evidence.ROOT_FORMAT:
            raise Bad(f"root statement {number} is not a canonical {core_evidence.ROOT_FORMAT} statement")
        if statement["public_key"] != instance_pub.hex() or statement["key_id"] != core_evidence.sha256_hex(instance_pub):
            raise Bad(f"root statement {number} is not signed with the pinned instance key")
        try:
            key.verify(bytes.fromhex(statement["sig"]), core_evidence.root_signed_bytes(statement))
        except (InvalidSignature, ValueError):
            raise Bad(f"root statement {number}: the signature does not verify") from None
        count = statement["leaves"]
        if count < last or count > len(leaves):
            raise Bad(f"root statement {number} counts {count} receipts after one that counted {last}, of {len(leaves)}")
        if statement["root"] != root_statement.merkle_root(leaves[:count]):
            raise Bad(f"root statement {number}: its root is not the root of the run's first {count} receipts")
        last = count
        out.append({"leaves": count, "root": statement["root"], "time_us": statement["time_us"]})
    if lines[-1] + b"\n" != (run / "receipts.roots.jsonl").read_bytes():
        raise Bad("the last sealed statement is not the run's root statement")
    return out


def verify(run: Path, keys: Path) -> Dict:
    """Both checks, or Bad (the verifier's own refusal is passed on as Bad with its message)."""
    run, keys = Path(run), Path(keys)
    try:
        summary = core_evidence.verify(run, sample=None, pin_authority=keys / "authority.pub",
                                       pin_instance=keys / "instance.pub")
    except core_evidence.Bad as bad:
        raise Bad(f"prismpath evidence verify refuses the run: {bad}") from None
    summary["roots"] = root_history(run, (keys / "instance.pub").read_bytes())
    return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("source", type=Path, help="the run directory as downlinked")
    parser.add_argument("run", type=Path, help="where the ground keeps the run (must not exist)")
    parser.add_argument("--keys", type=Path, required=True, help="the ground's keys (authority.pub, instance.pub)")
    args = parser.parse_args(argv)
    try:
        summary = verify(fetch(args.source, args.run), args.keys)
    except Bad as bad:
        print(f"REFUSED {args.run}: {bad}")
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
