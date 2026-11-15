# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""PrismPath deciding whether PrismPath's own artifacts are eligible for release.

The acceptance script gathers the facts: which gates ran, which passed, whether the skip budget held,
whether provenance and compatibility verified. This runner reads that report, turns it into one
outcome, and lets the flow in tools/release_policy.md decide: eligible, refused, or missing evidence.
Every edge of the flow is deterministic, so the same policy compiles to a table image, and the image
hash in the receipt is the policy's identity.

The receipt binds the decision to what it judged: the source revision, the sha256 of each artifact,
the sha256 of the policy flow and of its compiled image, the sha256 of each report the facts came
from, the facts themselves and the path the flow took. It is appended to a Merkle committed audit
log beside the report, so a receipt cannot be altered after the fact without the root changing.

The shell script's exit status stays authoritative during adoption. This decision is advisory and is
recorded beside it; a defect in the engine cannot certify the engine.

    python -m tools.release_eligibility --out <acceptance output dir> --revision <commit> [--leg full]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path

from prismpath.kernel import ppt_compile
from prismpath.kernel.engine import run
from prismpath.kernel.parser import parse_file
from prismpath.ledgers.audit_log import AuditLog

POLICY = Path(__file__).resolve().parent / "release_policy.md"
REQUIRED_GATES = {
    "compatibility": "compatibility_ok",
    "provenance check": "provenance_ok",
    "inventory and boundary: repository": "boundary_ok",
    "package boundary (wheel and sdist)": "boundary_ok",
    "python full: skip budget": "skip_budget_ok",
    "reproducible wheel and sdist": "reproducible_ok",
    "end to end: Python chain from the wheel, Rust chain from the candidates, seams compared": "end_to_end_ok",
}
ROW = re.compile(r"^\| (.+?) \| (pass|FAIL|BLOCKED|skip) \| (.*) \|$")


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_report(report: Path) -> tuple[str, dict[str, str]]:
    """The leg the report names and every gate row's status."""
    leg = ""
    statuses: dict[str, str] = {}
    for line in report.read_text(encoding="utf-8").splitlines():
        found = re.search(r"commit [0-9a-f]+, leg (\w+),", line)
        if found:
            leg = found.group(1)
        row = ROW.match(line)
        if row and row.group(1) not in ("Gate",):
            statuses[row.group(1)] = row.group(2)
    return leg, statuses


def facts_from(report: Path) -> dict:
    """One outcome for the flow. A required gate with no row leaves its fact absent and marks the
    evidence incomplete, so the flow refuses to decide rather than treating absence as success."""
    leg, statuses = read_report(report)
    facts = {
        "leg": leg,
        "gates_failed": sum(1 for status in statuses.values() if status in ("FAIL", "BLOCKED")),
        "gates_missing": sum(1 for gate in statuses if gate.startswith("missing gate: ")),
    }
    complete = bool(leg) and bool(statuses)
    for gate, fact in REQUIRED_GATES.items():
        if gate in statuses:
            facts[fact] = facts.get(fact, True) and statuses[gate] == "pass"
        else:
            complete = False
    facts["evidence_complete"] = complete
    for fact in set(REQUIRED_GATES.values()):
        facts.setdefault(fact, False)
    return facts


def decide(facts: dict) -> tuple[str, list[str]]:
    """Run the policy flow once over the facts; the terminal node is the decision."""
    graph = parse_file(str(POLICY))
    result = run(graph, lambda node, instruction, state: dict(facts, text="facts read"), max_steps=5)
    if result.stopped != "terminal":
        raise RuntimeError(f"the release policy did not reach a terminal node: {result.stopped}")
    return result.path[-1], list(result.path)


def policy_identity() -> dict:
    image = ppt_compile.compile_flow(parse_file(str(POLICY))).serialize()
    return {"flow": str(POLICY.name), "flow_sha256": sha256_of(POLICY),
            "image_sha256": hashlib.sha256(image).hexdigest(), "image_bytes": len(image)}


def artifacts_in(out: Path) -> dict[str, str]:
    found = {}
    for pattern in ("dist/*.whl", "dist/*.tar.gz", "cargo-target/package/*.crate"):
        for artifact in sorted(out.glob(pattern)):
            found[artifact.name] = sha256_of(artifact)
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", required=True, help="the acceptance output directory holding report.md")
    parser.add_argument("--revision", required=True, help="the source commit the artifacts were built from")
    args = parser.parse_args(argv)
    out = Path(args.out).resolve()
    report = out / "report.md"
    if not report.exists():
        print(f"release eligibility: no report at {report}", file=sys.stderr)
        return 2
    facts = facts_from(report)
    decision, path = decide(facts)
    reports = {name: sha256_of(out / name) for name in ("report.md", "skips.log") if (out / name).exists()}
    receipt = {"decision": decision, "path": path, "facts": facts, "source_revision": args.revision,
               "artifacts": artifacts_in(out), "policy": policy_identity(), "reports": reports,
               "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "authority": "advisory; the acceptance exit status decides"}
    (out / "release_receipt.json").write_text(json.dumps(receipt, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    log = AuditLog(str(out / "release_receipts.log"))
    event = log.append("release_policy", "release_eligibility", receipt)
    print(f"release eligibility: {decision} (path {' -> '.join(path)}); policy image {receipt['policy']['image_sha256'][:12]}; "
          f"receipt leaf {event['idx']} root {log.current_root()[:12]}")
    return 0 if decision == "eligible" else 1


if __name__ == "__main__":
    sys.exit(main())
