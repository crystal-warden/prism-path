# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A differential run as evidence (docs/design/spec-verified-core.md, section 11).

A run is one implementation's decisions on a set of cases, written so that a reader who trusts neither
the implementation nor the person who ran it can check what was decided:

  * every policy image's canon/2 bytes are signed with the authority key (`images.jsonl`, an image
    attestation per case, Ed25519 over `IMAGE_DOMAIN` and the image bytes);
  * every decision has a receipt (`receipts.jsonl`, one canon/2 line each) binding the image's hash, the
    reading's hash and the decision with its registered cause; a receipt is not signed by itself;
  * the receipts are the leaves of a Merkle tree, and one root statement signed with the instance key
    (`receipts.roots.jsonl`, `prismpath.core-run-root/1`, log `core-run`) states their root and count,
    and binds the run's manifest (`run.json`) through its `policy` member. It is a canon/2 document with
    its time an integer count of microseconds (`time_us`), signed over its own domain prefix, so the
    run's evidence is canon/2 end to end, as the root statements of audit logs and epoch chains
    (`prismpath.ledgers.root_statement`, `prismpath-root-statement/2`) are.

The verifier re-checks the root statement, every receipt and every image attestation, and replays a
sample of the decisions through the Lean oracle; a case outside the core (section 1) is excluded with
its reason, which the verifier recomputes from the image, so every receipted decision must be the
oracle's. The Rust twin is
`prismpath-hotswap-rs/examples/core_evidence.rs`; each verifies a run the other produced.

The run format, the producer and every check but the replay are the package's own
(`prismpath.ledgers.core_evidence`, which `prismpath evidence verify` runs with a replay through the
Python reference kernel); this tool adds the differential's case generator, the scope check, and the
replay through the Lean oracle (`--oracle` names the binary), so there is one verifier, not two.

    python formal/diff/core_evidence.py cases --cases 2000 --seed 7 --out cases.jsonl
    python formal/diff/core_evidence.py produce --from cases.jsonl --out RUN --keys KEYS
    python formal/diff/core_evidence.py verify RUN --sample 500

Keys are test keys: `produce` generates an authority key and an instance key in `--keys` when none are
there (the repository's own `swap keygen` and `ledger keygen` code), and the run holds only their public
halves. The verifier pins the public keys it is given, or reads them from the run and says the run is
signed but unpinned.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import core_diff  # noqa: E402
from prismpath.kernel import core_policy  # noqa: E402
# The run format, the producer and the checks, from the package: one implementation for both verifiers
from prismpath.ledgers.core_evidence import (  # noqa: E402,F401
    FILES, IMAGE_DOMAIN, IMAGE_FORMAT, LOG_CORE_RUN, RECEIPT_FORMAT, ROOT_DOMAIN, ROOT_FORMAT, ROOT_MEMBERS,
    RUN_FORMAT, Bad, _decision, _hex_of, _lines, _norm, _why, ensure_keys, make_root_statement, outside_core,
    produce, python_decisions, read_cases, replay_through_reference, root_signed_bytes, sha256_hex,
    verify_root_statement)
from prismpath.ledgers import core_evidence as _package  # noqa: E402

ORACLE_NAME = "the oracle"   # what `replay_through_oracle` holds a receipt to, in the verifier's messages


# ----------------------------------------------------------------- the cases
def write_cases(cases, out: Path) -> None:
    """The run's inputs, one canon/2 line per case: the image and the readings as hex of their bytes, and
    the flow the image renders to (the text the reference and the ports read), or null."""
    from prismpath.kernel import canon2
    core_diff.prepare(cases)
    with open(out, "wb") as handle:
        for case in cases:
            handle.write(canon2.dumps({"case": case["id"], "image": case["image"].hex(), "flow": case["flow"],
                                       "readings": [raw.hex() for raw in case["readings"]]}) + b"\n")


# ----------------------------------------------------------------- the core's scope
def oracle_policies(cases, oracle=None) -> list:
    """The oracle's check of every case's image, as (cause, code, field, reason) or None when accepted."""
    binary = Path(oracle) if oracle else core_diff.ORACLE
    data = bytearray()
    for number, case in enumerate(cases):
        data += f"case s{number} 0\n{len(case['image'])}\n".encode() + case["image"] + b"\n"
    lines = subprocess.run([str(binary), "--batch"], input=bytes(data), capture_output=True, check=True).stdout
    rows = {row["id"]: row["policy"] for row in map(json.loads, lines.decode().splitlines())}
    out = []
    for number in range(len(cases)):
        row = rows[f"s{number}"]
        out.append(None if row["policy"] == "accepted" else (row["cause"], row["code"], row.get("field"), row.get("reason")))
    return out


def scope_check(cases, oracle=None, rust_lines=None) -> dict:
    """The ported checks of a policy image against the oracle's on every image: the Python port
    (`core_policy.load_policy`) and, given the Rust port's lines (`core_evidence policy`, one canon/2 line
    per case), the Rust port; whether each image is accepted, and the cause, code, field and reason of every
    refusal. The exclusion of `engine-counter` cases is sound only while they agree."""
    from prismpath.kernel import canon2
    want = oracle_policies(cases, oracle)
    ports = {"python": [core_policy.load_policy(case["image"]) for case in cases]}
    if rust_lines is not None:
        rows = [canon2.loads(line) for line in rust_lines]
        if len(rows) != len(cases) or any(row.get("case") != case["id"] for row, case in zip(rows, cases)):
            raise Bad("the Rust port's lines are not one per case in order")
        ports["rust"] = [None if row["policy"] == "accepted" else (row["cause"], row["code"], row.get("field"),
                                                                    row.get("reason")) for row in rows]
    counts = {"images": len(cases), "accepted": sum(item is None for item in want),
              "counter": sum(item is not None and item[0] == "policy:engine-counter" for item in want),
              "first": None}
    for name, got in ports.items():
        agree = [a == b for a, b in zip(got, want)]
        counts[name] = {"agree": sum(agree), "disagree": len(agree) - sum(agree)}
        if not all(agree):
            at = agree.index(False)
            counts["first"] = counts["first"] or {"port": name, "case": cases[at]["id"], "got": got[at], "oracle": want[at]}
    return counts


# ----------------------------------------------------------------- verifying a run
def verify(run: Path, *, sample=200, seed=0, pin_authority=None, pin_instance=None, oracle=None) -> dict:
    """Every check of a run, the package's (`prismpath.ledgers.core_evidence.verify`), with the sampled
    receipts replayed through the Lean oracle, or Bad naming the first that fails. Returns a summary."""
    return _package.verify(Path(run), sample=sample, seed=seed, pin_authority=pin_authority,
                           pin_instance=pin_instance, replay=lambda chosen: replay_through_oracle(chosen, oracle))


def replay_through_oracle(chosen, oracle=None) -> dict:
    """Each chosen receipt's image and reading through the oracle, one case each, and the decisions
    compared: every receipted case is inside the core, so every decision must be the oracle's."""
    binary = Path(oracle) if oracle else core_diff.ORACLE
    data = bytearray()
    for number, (case, index, _receipt) in enumerate(chosen):
        reading = case["readings"][index]
        data += f"case r{number} 1\n".encode() + f"{len(case['image'])}\n".encode() + case["image"] + b"\n"
        data += f"{len(reading)}\n".encode() + reading + b"\n"
    lines = subprocess.run([str(binary), "--batch"], input=bytes(data), capture_output=True, check=True).stdout
    rows = {row["id"]: row for row in map(json.loads, lines.decode().splitlines())}
    counts = {"replayed": len(chosen), "agree": 0, "disagree": 0, "first": None, "against": ORACLE_NAME}
    for number, (case, _index, receipt) in enumerate(chosen):
        oracle_verdict = rows[f"r{number}"]["readings"][0]
        if _norm(oracle_verdict) == _norm(receipt):
            counts["agree"] += 1
        else:
            counts["disagree"] += 1
            counts["first"] = counts["first"] or {"case": case["id"], "receipt": receipt, "oracle": oracle_verdict}
    return counts


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    gen = sub.add_parser("cases", help="generate the harness's cases and write them as a run's inputs")
    gen.add_argument("--cases", type=int, default=2000)
    gen.add_argument("--seed", type=int, default=7)
    gen.add_argument("--out", required=True)
    make = sub.add_parser("produce", help="decide the cases with the Python reference and write a run")
    make.add_argument("--from", dest="source", required=True)
    make.add_argument("--out", required=True)
    make.add_argument("--keys", required=True, help="the test keys' directory (generated when empty)")
    scope = sub.add_parser("scope-check", help="hold the ported policy check to the oracle's on every image")
    scope.add_argument("--from", dest="source", required=True)
    scope.add_argument("--rust", help="the Rust port's lines (`core_evidence policy --from CASES`), held to the oracle too")
    scope.add_argument("--oracle")
    check = sub.add_parser("verify", help="re-check a run and replay a sample through the oracle")
    check.add_argument("run")
    check.add_argument("--sample", default="200", help="how many decisions to replay, or 'all'")
    check.add_argument("--seed", type=int, default=0)
    check.add_argument("--pin-authority")
    check.add_argument("--pin-instance")
    check.add_argument("--oracle")
    args = parser.parse_args(argv)
    if args.command == "cases":
        write_cases(core_diff.generate(args.cases, args.seed), Path(args.out))
        print(f"core_evidence: wrote {args.cases} cases to {args.out}")
        return 0
    if args.command == "scope-check":
        cases = read_cases(Path(args.source))
        counts = scope_check(cases, args.oracle, _lines(Path(args.rust)) if args.rust else None)
        ports = ", ".join(f"{name} port {counts[name]['agree']} agree, {counts[name]['disagree']} disagree"
                          for name in ("python", "rust") if name in counts)
        failed = counts["first"] is not None
        print(f"core_evidence: scope check {args.source}: {counts['images']} images ({counts['accepted']} accepted, "
              f"{counts['counter']} refused for an engine counter): {ports}" + (f"; first {counts['first']}" if failed else ""))
        return 1 if failed else 0
    if args.command == "produce":
        manifest = produce(Path(args.source), Path(args.out), Path(args.keys))
        print(f"core_evidence: produced {args.out}: decider {manifest['decider']}, {manifest['cases']} cases, "
              f"{manifest['receipts']} receipts, {len(manifest['excluded'])} excluded")
        return 0
    try:
        summary = verify(Path(args.run), sample=None if args.sample == "all" else int(args.sample), seed=args.seed,
                         pin_authority=args.pin_authority, pin_instance=args.pin_instance, oracle=args.oracle)
    except Bad as bad:
        print(f"core_evidence: REFUSED {args.run}: {bad}")
        return 1
    print(f"core_evidence: verified {args.run}: decider {summary['decider']}, {summary['receipts']} receipts, "
          f"{summary['images']} image attestations, root statement {summary['root_statement']}, "
          f"{summary['replayed']} replayed: {summary['agree']} agree, "
          f"{summary['disagree']} disagree")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
