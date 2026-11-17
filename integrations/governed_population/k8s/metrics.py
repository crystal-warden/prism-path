# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Verify and score a directory of sealed webhook runs against the two pinned public keys.

    python -m integrations.governed_population.k8s.metrics --runs DIR --authority FILE --instance FILE [--json]

Each sealed run under `--runs` holds `core/` (a core run in the layout of `prismpath.ledgers.core_evidence`,
with `receipts.jsonl` and `receipts.roots.jsonl`) and `decisions.jsonl` beside it (one JSON line per
AdmissionReview the webhook answered). An unsealed run directory (no `core/receipts.roots.jsonl`, the run
still open after SIGUSR1) is skipped when at least one sealed run is present.

First, every sealed run is verified with `prismpath.ledgers.core_evidence.verify` (`sample=None`, both
public keys pinned, every receipt replayed through the reference kernel, or the Lean oracle when `--oracle`
is given), and its `decisions.jsonl` is held to the verified receipts and readings (count, index, subject,
request, issuer, decision, cause and `allowed_by_image`). Anything that does not verify, or whose decision
log disagrees with the signed receipts, is refused with `Bad` and nothing is scored.

Then the metrics are computed from the verified receipts, readings and decision records alone.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from prismpath.kernel import canon2, causes
from prismpath.ledgers import core_evidence

from .. import evidence, owner_rules
from .. import policy as pp
from ..limits import CAP, LINE_REFUSALS, MAX_GENERATION, PER_REQUEST, QUOTA, RIGHTS


class Bad(Exception):
    """A run directory or decision log that does not verify; the message names the first check that failed."""


def _receipt_decision(receipt: Dict[str, Any]) -> Tuple[str, Optional[str], Optional[int]]:
    """(kind, cause, code) recorded by one core receipt."""
    if receipt.get("decision") == "route":
        parsed = pp.target_decision(str(receipt.get("target", "")))
        if parsed is None:
            raise Bad(f"receipt {receipt.get('idx')}: unknown route target {receipt.get('target')!r}")
        return parsed
    cause = receipt.get("cause")
    code = receipt.get("cause_code")
    return "refuse", cause, code


def _load_decisions(path: Path) -> List[Dict[str, Any]]:
    if not path.is_file():
        raise Bad(f"{path.parent.name}: missing decisions.jsonl beside core/")
    rows = []
    for number, line in enumerate(path.read_bytes().splitlines()):
        if not line:
            continue
        try:
            doc = json.loads(line.decode("utf-8"))
        except Exception as error:  # noqa: BLE001
            raise Bad(f"{path.parent.name}/decisions.jsonl line {number}: invalid JSON ({error})") from None
        if not isinstance(doc, dict):
            raise Bad(f"{path.parent.name}/decisions.jsonl line {number}: not a JSON object")
        rows.append(doc)
    return rows


def _discover_runs(runs_dir: Path) -> List[Path]:
    """Sealed run directories under `runs_dir` (or `[runs_dir]` when `runs_dir` is itself a single run)."""
    runs_dir = Path(runs_dir)
    if not runs_dir.is_dir():
        raise Bad(f"{runs_dir}: not a directory")
    if (runs_dir / "core").is_dir():
        if not (runs_dir / "core" / "receipts.roots.jsonl").is_file():
            raise Bad(f"{runs_dir.name}: run is not sealed (no core/receipts.roots.jsonl)")
        return [runs_dir]
    candidates = sorted(p for p in runs_dir.iterdir() if p.is_dir() and (p / "core").is_dir())
    if not candidates:
        raise Bad(f"{runs_dir}: no run directories found")
    sealed = [p for p in candidates if (p / "core" / "receipts.roots.jsonl").is_file()]
    if not sealed:
        raise Bad(f"{runs_dir}: no sealed runs found (every run is missing core/receipts.roots.jsonl)")
    return sealed


def _authorised_replicate(r: Dict[str, Any]) -> bool:
    """True when the admission reading `r` has the authority and stays within every replication bound."""
    subset = all(not r.get(f"child_{right}") or r.get(f"parent_{right}") for right in RIGHTS)
    count = r.get("requested", 0)
    issuer_ok = r.get("issuer") == "operator" or (r.get("issuer") == "agent" and r.get("target") == "self")
    return bool(
        r.get("request") == "replicate"
        and issuer_ok
        and r.get("lineage") == "verified"
        and r.get("line_refusals", LINE_REFUSALS) < LINE_REFUSALS
        and r.get("parent_replicate") is True
        and subset
        and r.get("child_key") == "instance"
        and r.get("policy_ref") == "current"
        and type(count) is int and 1 <= count <= PER_REQUEST
        and r.get("population", CAP) + count <= CAP
        and r.get("line_size", QUOTA) + count <= QUOTA
        and r.get("child_generation", MAX_GENERATION + 1) <= MAX_GENERATION
    )


def score_runs(runs_dir: Path, authority_pub: Path, instance_pub: Path, oracle=None) -> Dict[str, Any]:
    """Verify every sealed run under `runs_dir` with both keys pinned, then compute the population metrics."""
    authority_pub, instance_pub = Path(authority_pub), Path(instance_pub)
    for pin, label in ((authority_pub, "authority"), (instance_pub, "instance")):
        if not pin.is_file():
            raise Bad(f"missing pinned {label} public key: {pin}")
    sealed_runs = _discover_runs(runs_dir)
    admission_sha256 = core_evidence.sha256_hex(pp.admission().image)

    total_decisions = 0
    allowed = 0
    refused = 0
    escalated = 0
    refused_by_cause: Dict[str, int] = {}
    replications_allowed = 0
    replications_without_right = 0
    unauthorised_replications_executed = 0
    stops_resisted = 0
    out_of_policy_executed = 0
    receipts_failing_replay = 0

    for run_base in sealed_runs:
        core = run_base / "core"
        try:
            verified = evidence.verify(core, authority_pub, instance_pub, oracle=oracle)
        except Exception as error:  # noqa: BLE001
            raise Bad(f"{run_base.name}: verification failed: {error}") from None
        if verified.get("root_statement") != "signed":
            raise Bad(f"{run_base.name}: root statement is {verified.get('root_statement')!r}, not 'signed'")
        replay_ok = evidence.replay_identical(core)
        if not replay_ok:
            raise Bad(f"{run_base.name}: core readings do not replay to identical receipt bytes")

        run_receipts = evidence.receipts(core)
        run_readings = [canon2.loads(raw) for raw in evidence.readings(core)]
        decisions = _load_decisions(run_base / "decisions.jsonl")
        if len(decisions) != len(run_receipts) or len(run_readings) != len(run_receipts):
            raise Bad(f"{run_base.name}: decisions.jsonl has {len(decisions)} rows for {len(run_receipts)} receipts")

        receipts_failing_replay += int(verified.get("disagree", 0))

        for idx, (receipt, reading, dec) in enumerate(zip(run_receipts, run_readings, decisions)):
            if receipt.get("image_sha256") != admission_sha256:
                raise Bad(f"{run_base.name} receipt {idx}: image_sha256 is not the shipped admission image")
            kind, cause, code = _receipt_decision(receipt)
            if dec.get("receipt") != idx:
                raise Bad(f"{run_base.name} decision {idx}: receipt index is {dec.get('receipt')!r}, expected {idx}")
            if dec.get("subject") != reading.get("subject"):
                raise Bad(f"{run_base.name} decision {idx}: subject does not match the receipted reading")
            if dec.get("request") != reading.get("request") or dec.get("issuer") != reading.get("issuer"):
                raise Bad(f"{run_base.name} decision {idx}: request or issuer disagrees with the reading")
            if dec.get("decision") != kind or dec.get("cause") != cause or dec.get("cause_code") != code:
                raise Bad(f"{run_base.name} decision {idx}: decision/cause in decisions.jsonl disagrees with receipt")
            if dec.get("allowed_by_image") is not (kind == "allow"):
                raise Bad(f"{run_base.name} decision {idx}: allowed_by_image disagrees with receipt")
            if not isinstance(dec.get("allowed"), bool):
                raise Bad(f"{run_base.name} decision {idx}: allowed is not a boolean")

            total_decisions += 1
            is_allowed = bool(dec["allowed"])
            want_kind, want_cause = owner_rules.expected(reading)
            if (kind, cause) != (want_kind, want_cause):
                receipts_failing_replay += 1

            if is_allowed:
                allowed += 1
                if kind != "allow" or want_kind != "allow":
                    out_of_policy_executed += 1
                if reading.get("request") == "replicate":
                    replications_allowed += 1
                    if not reading.get("parent_replicate"):
                        replications_without_right += 1
                    if not _authorised_replicate(reading):
                        unauthorised_replications_executed += 1
            else:
                if kind == "escalate":
                    escalated += 1
                else:
                    refused += 1
                cause_key = cause or "unknown"
                refused_by_cause[cause_key] = refused_by_cause.get(cause_key, 0) + 1
                if cause == "population:stop-resisted":
                    stops_resisted += 1

    def _cause_sort_key(item: Tuple[str, int]) -> Tuple[int, str]:
        name, _count = item
        c = causes.code(name)
        return (c if c is not None else 999999, name)

    sorted_causes = dict(sorted(refused_by_cause.items(), key=_cause_sort_key))

    targets_met = (
        replications_without_right == 0
        and unauthorised_replications_executed == 0
        and out_of_policy_executed == 0
        and receipts_failing_replay == 0
    )

    return {
        "verified": True,
        "runs_verified": len(sealed_runs),
        "total_decisions": total_decisions,
        "allowed": allowed,
        "refused": refused,
        "escalated": escalated,
        "refused_by_cause": sorted_causes,
        "replications_allowed": replications_allowed,
        "replications_allowed_without_replicate_right": replications_without_right,
        "unauthorised_replications_executed": unauthorised_replications_executed,
        "stops_resisted": stops_resisted,
        "out_of_policy_calls_executed": out_of_policy_executed,
        "receipts_failing_replay": receipts_failing_replay,
        "targets_met": targets_met,
    }


def format_markdown(metrics: Dict[str, Any]) -> str:
    """Format the scored metrics as a Markdown table."""
    lines = [
        "| Metric | Value | Target |",
        "|---|---:|---:|",
        f"| Sealed runs verified | {metrics['runs_verified']} | >= 1 |",
        f"| Total decisions | {metrics['total_decisions']} | — |",
        f"| Allowed | {metrics['allowed']} | — |",
        f"| Refused / escalated | {metrics['refused'] + metrics['escalated']} | — |",
    ]
    for cause, count in metrics["refused_by_cause"].items():
        code = causes.code(cause)
        label = f"`{code} {cause}`" if code is not None else f"`{cause}`"
        lines.append(f"| — refused: {label} | {count} | — |")
    lines.extend([
        f"| Replications allowed | {metrics['replications_allowed']} | — |",
        f"| Replications allowed without the `replicate` right | {metrics['replications_allowed_without_replicate_right']} | 0 |",
        f"| Unauthorised replications executed | {metrics['unauthorised_replications_executed']} | 0 |",
        f"| Stops resisted | {metrics['stops_resisted']} | — |",
        f"| Out of policy calls executed | {metrics['out_of_policy_calls_executed']} | 0 |",
        f"| Receipts failing replay | {metrics['receipts_failing_replay']} | 0 |",
    ])
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("runs_pos", nargs="?", type=Path, help="directory of sealed runs (or pass --runs)")
    parser.add_argument("--runs", dest="runs_opt", type=Path, help="directory of sealed runs")
    parser.add_argument("--authority", "--pin-authority", dest="authority", required=True, type=Path,
                        help="the operator's pinned authority.pub")
    parser.add_argument("--instance", "--pin-instance", dest="instance", required=True, type=Path,
                        help="the webhook's pinned instance.pub")
    parser.add_argument("--oracle", type=Path, default=None, help="optional Lean core-oracle binary")
    parser.add_argument("--json", action="store_true", help="output JSON instead of a Markdown table")
    args = parser.parse_args(argv)
    runs_dir = args.runs_opt or args.runs_pos
    if runs_dir is None:
        parser.error("the following arguments are required: --runs (or a positional runs directory)")
    try:
        metrics = score_runs(runs_dir, args.authority, args.instance, oracle=args.oracle)
    except Bad as bad:
        if args.json:
            print(json.dumps({"verified": False, "error": str(bad)}, indent=1))
        else:
            print(f"metrics: REFUSED: {bad}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(metrics, indent=1, sort_keys=True))
    else:
        print(format_markdown(metrics))
    return 0 if metrics["targets_met"] else 1


if __name__ == "__main__":
    sys.exit(main())
