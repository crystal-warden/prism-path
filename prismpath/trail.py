# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""trail: the operator's read side of the receipts. Summarise an append only audit log (the JSONL
`prismpath.audit_log` writes: decisions, swaps, attestations) over a window, in cause code terms, and
say whether the log's Merkle root still verifies. What decisions have been shifting, and why, is the
input to "should the policy change today"; the assessor uses the same verb after the fact.

    prismpath trail run.audit.jsonl                 # everything, by action, outcome, and cause
    prismpath trail run.audit.jsonl --last 200      # the most recent 200 events
    prismpath trail run.audit.jsonl --since 2026-09-09T00:00:00Z --json
    prismpath trail run.audit.jsonl --pub instance.pub              # and the signed roots, under a pinned key
    prismpath trail run.audit.jsonl --pub instance.pub --receipt 3  # one receipt, checked on its own
    prismpath trail run.audit.jsonl --receipt 3 --bundle-out bundle.json    # and handed on as a bundle
    prismpath trail --verify-bundle bundle.json --pub instance.pub  # the reader's side: no log needed

Beside the Merkle check, trail reads the root statements beside the log (`run.audit.roots.jsonl`) and
says whether the log is signed, unsigned (written without an instance key, as every log before 0.1.2
was) or invalid, naming each finding: a log shorter than a signed leaf count, a receipt rewritten under
a signed root, a statement signed by a key that is not the pinned one, a broken statement chain. With
`--pub` the reader pins the deployment's instance key, and a log with no statements is then invalid
rather than unsigned. Checking a signature needs the signing extra; an unsigned log needs nothing.

`--verify-bundle` is the check a reader runs on a receipt bundle they were handed (`--receipt IDX
--bundle-out FILE`, or the `--json` report of one): receipt, leaf, inclusion path, signed root,
signature and key, offline, from the bundle and the pinned public key alone. The result is `signed`
(a pinned key made the signature), `signed-unpinned` (no key was pinned, so the statement's own key
was trusted) or `invalid`, and the exit status follows `trail`: 0 for the first two, 1 for invalid.
With `--anchor-dir` it also checks that the statement's hash was timestamped by `ledger anchor`; that
step runs `ots verify`, which needs Bitcoin block data (a node or a block explorer), so it is the one
step that is not offline. A bundle holds one statement, not the chain around it, and says nothing about
the log's other receipts; `trail LOG --pub KEY` checks those.
"""
from __future__ import annotations

import collections
import datetime as _dt
import json
import os
import sys
from typing import Any, Dict, List, Optional

from prismpath.ledgers import audit_log
from prismpath.ledgers import root_statement
from prismpath.kernel import causes

def _parse_since(text: Optional[str]) -> Optional[float]:
    if not text:
        return None
    normalized = text.replace("Z", "+00:00")
    parsed_time = _dt.datetime.fromisoformat(normalized)
    if parsed_time.tzinfo is None:
        parsed_time = parsed_time.replace(tzinfo=_dt.timezone.utc)
    return parsed_time.timestamp()


def summarise(events: List[dict]) -> Dict[str, Any]:
    by_action: collections.Counter = collections.Counter(ev.get("action", "?") for ev in events)
    decisions = [ev for ev in events if ev.get("action") == "decision"]
    outcomes: collections.Counter = collections.Counter(str((ev.get("data") or {}).get("outcome")) for ev in decisions)
    by_cause: collections.Counter = collections.Counter()
    for ev in decisions:
        code = (ev.get("data") or {}).get("cause")
        if code is None:
            label = "unrecorded"
        elif int(code) == 0:
            label = "0 clean"                      # 0 is the clean decision, outside the registry's refusal bands
        else:
            label = f"{code} {causes.name(int(code)) or 'unregistered'}"
        by_cause[label] += 1
    rules: collections.Counter = collections.Counter(str((ev.get("data") or {}).get("rule")) for ev in decisions)
    swaps = [ev for ev in events if ev.get("action") in ("swap", "swap_rejected", "rollback", "attestation")]
    swap_lines = []
    for ev in swaps:
        data = ev.get("data") or {}
        when = _dt.datetime.fromtimestamp(float(ev.get("ts", 0)), _dt.timezone.utc).isoformat(timespec="seconds")
        if ev["action"] == "swap":
            swap_lines.append(f"{when} swap accepted -> version {data.get('version')} {str(data.get('to_hash'))[:12]}"
                              + (f" overlay of {data['overlay_of']}" if data.get("overlay_of") else ""))
        elif ev["action"] == "swap_rejected":
            swap_lines.append(f"{when} swap refused: {','.join(data.get('reasons', []))}")
        elif ev["action"] == "rollback":
            swap_lines.append(f"{when} rollback -> {str(data.get('to_hash'))[:12]}")
        else:
            swap_lines.append(f"{when} attestation: version {data.get('version')}"
                              + (f" overlay of {data['overlay_of']}" if data.get("overlay_of") else ""))
    first = min((float(ev.get("ts", 0)) for ev in events), default=None)
    last = max((float(ev.get("ts", 0)) for ev in events), default=None)
    return {"events": len(events), "decisions": len(decisions),
            "window": {"first": first, "last": last},
            "by_action": dict(by_action), "outcomes": dict(outcomes), "causes": dict(by_cause),
            "rules": dict(rules), "swaps": swap_lines}


def run(path: str, since: Optional[str] = None, last: Optional[int] = None,
        pinned: Optional[List[bytes]] = None, statements_path: Optional[str] = None,
        receipt: Optional[int] = None) -> Dict[str, Any]:
    log = audit_log.AuditLog(path, statements_path=statements_path)
    events = list(log.events)
    t0 = _parse_since(since)
    if t0 is not None:
        events = [ev for ev in events if float(ev.get("ts", 0)) >= t0]
    if last:
        events = events[-last:]
    out = summarise(events)
    out["log"] = {"path": path, "total_events": len(log.events), "merkle_root": log.current_root(),
                  "verifies": log.verify_log()}
    out["signing"] = log.verify_statements(pinned)
    out["signing"]["statements_path"] = log.statements_path
    if receipt is not None:
        try:
            bundle = log.receipt_bundle(receipt)
        except LookupError as uncovered:
            out["receipt"] = {"ok": False, "index": receipt, "uncovered": str(uncovered)}
        else:
            out["receipt"] = {**root_statement.verify_receipt_bundle(bundle, pinned), "bundle": bundle}
    return out


def load_bundle(path: str) -> dict:
    """A receipt bundle from a file: the bare bundle `--bundle-out` writes, or the `--json` report of
    `trail --receipt` that carries one."""
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, dict) and isinstance(data.get("receipt"), dict) and isinstance(data["receipt"].get("bundle"), dict):
        return data["receipt"]["bundle"]
    return data


def check_bundle(bundle: dict, pinned: Optional[List[bytes]] = None, anchor_dir: Optional[str] = None,
                 label: str = "v1") -> Dict[str, Any]:
    """`verify_receipt_bundle`, plus the anchor when `anchor_dir` is given: the statement's hash must be
    one of the hashes `ledger anchor` stamped there, and its OpenTimestamps proof must verify. The
    anchor needs the `ots` program and Bitcoin block data; nothing else here touches the network."""
    result = root_statement.verify_receipt_bundle(bundle, pinned)
    result["bundle"] = bundle
    if anchor_dir:
        from prismpath.ledgers import ledger_ots
        anchor = ledger_ots.verify_unit(result["statement_sha256"], anchor_dir, label) \
            if result["statement_sha256"] else {"merkle_ok": False, "reason": "no statement to look up"}
        anchor["ok"] = bool(anchor.get("merkle_ok") and anchor.get("ots_ok"))
        result["anchor"] = anchor
        if not anchor["ok"]:
            result["ok"], result["status"] = False, root_statement.INVALID
    return result


def _bundle_text(result: Dict[str, Any]) -> str:
    if "problem" in result:
        return f"bundle: INVALID: not a receipt bundle: {result['problem']}"
    lines = [f"bundle: receipt {result['index']} in statement {result['statement']} "
             f"(statement sha256 {result['statement_sha256'][:16]}), status {result['status']}"]
    check = {**result, "bundle": result["bundle"]}
    lines.append(_receipt_line(check))
    if result["status"] == root_statement.SIGNED_UNPINNED:
        lines.append("  no key was pinned, so the key the statement carries was trusted: pass --pub with the "
                     "deployment's instance public key to check it is theirs")
    steps = result["checks"]
    for name in ("index", "covered"):
        if steps.get(name) is False:
            lines.append(f"  check failed: {name}")
    if "anchor" in result:
        anchor = result["anchor"]
        if anchor["ok"]:
            lines.append("anchor: the statement hash is in the anchored batch and its OpenTimestamps proof verifies")
        elif anchor.get("merkle_ok") is False:
            lines.append(f"anchor: FAILS: {anchor.get('reason') or 'the statement hash is not in this anchor batch'} "
                         f"(anchor the statements with `ledger anchor --statements`)")
        else:
            lines.append(f"anchor: FAILS: the OpenTimestamps proof does not verify: {anchor.get('ots_verify', '')}")
    return "\n".join(lines)


def _finding_text(finding: dict) -> str:
    name = finding["finding"]
    where = f" at statement {finding['statement']}" if "statement" in finding else ""
    if name == "log_truncated":
        return f"log truncated{where}: it signed {finding['signed_leaves']} leaves, the log holds {finding['log_leaves']}"
    if name == "root_mismatch":
        first, last_index = finding["leaf_range"]
        return f"root does not match{where}: a receipt with idx {first} to {last_index} changed after it was signed"
    if name == "unpinned_key":
        return f"signed by key {finding['key']}{where}, which is not a pinned key"
    if name == "authority_key":
        return f"signed{where} by {finding['key']}, a policy authority key, not an instance key"
    if name == "bad_signature":
        return f"signature does not verify{where}"
    if name == "chain_broken":
        return f"statement chain broken{where} (a statement was removed, reordered or edited)"
    if name == "no_statements":
        return "a key is pinned and the log has no root statements"
    if name == "interrupted_statement":
        return f"the last statement line ({finding['line']}) was cut short by a crash; ignored"
    if name == "bad_format" and "log_lines" in finding:
        return f"unreadable log lines {finding['log_lines']}"
    return name.replace("_", " ") + where


def _signing_line(signing: Dict[str, Any]) -> str:
    status = signing["status"]
    if status == root_statement.UNSIGNED:
        return "signing: unsigned (no root statements beside this log; it was written without an instance key)"
    if status == root_statement.INVALID:
        fatal = [finding for finding in signing["findings"] if finding["finding"] in root_statement.FATAL_FINDINGS]
        return "signing: INVALID: " + "; ".join(_finding_text(finding) for finding in fatal)
    keys = ", ".join(signing["keys"])
    pin = "pinned" if signing["pinned"] else "not pinned: pass --pub to check it is the deployment's key"
    tail = (f", {signing['unsigned_tail']} later receipts not yet covered" if signing["unsigned_tail"] else "")
    count = signing["statements"]
    return (f"signing: signed by instance key {keys} ({pin}); {count} statement{'s cover' if count != 1 else ' covers'} "
            f"{signing['signed_leaves']} of {signing['log_leaves']} events{tail}")


def render(rep: Dict[str, Any]) -> str:
    lines = [f"trail: {rep['log']['path']}  events {rep['events']} of {rep['log']['total_events']}  "
             f"root {rep['log']['merkle_root'][:16] or '(empty)'}  verifies {rep['log']['verifies']}"]
    if "signing" in rep:
        lines.append(_signing_line(rep["signing"]))
        for finding in rep["signing"]["findings"]:
            if finding["finding"] not in root_statement.FATAL_FINDINGS:
                lines.append("  note: " + _finding_text(finding))
    if "receipt" in rep:
        lines.append(_receipt_line(rep["receipt"]))
    if rep["window"]["first"] is not None:
        first_iso = _dt.datetime.fromtimestamp(rep["window"]["first"],
                                               _dt.timezone.utc).isoformat(timespec="seconds")
        last_iso = _dt.datetime.fromtimestamp(rep["window"]["last"],
                                              _dt.timezone.utc).isoformat(timespec="seconds")
        lines.append(f"window: {first_iso} to {last_iso}")
    lines.append("by action: " + ", ".join(f"{tally_name} {tally_count}"
                                           for tally_name, tally_count in sorted(rep["by_action"].items())))
    if rep["decisions"]:
        lines.append(f"decisions {rep['decisions']}:")
        lines.append("  outcomes: " + ", ".join(
            f"{tally_name} {tally_count}"
            for tally_name, tally_count in sorted(rep["outcomes"].items(), key=lambda kv: -kv[1])))
        lines.append("  causes:   " + ", ".join(
            f"{tally_name} x{tally_count}"
            for tally_name, tally_count in sorted(rep["causes"].items(), key=lambda kv: -kv[1])))
        lines.append("  rules:    " + ", ".join(
            f"{tally_name} {tally_count}"
            for tally_name, tally_count in sorted(rep["rules"].items(), key=lambda kv: -kv[1])))
    for sl in rep["swaps"]:
        lines.append("  " + sl)
    return "\n".join(lines)


def _receipt_line(check: Dict[str, Any]) -> str:
    if "uncovered" in check:
        return f"receipt {check['index']}: not covered: {check['uncovered']}"
    steps = check["checks"]
    chain = (f"leaf {'ok' if steps['leaf'] else 'CHANGED'} -> inclusion {'ok' if steps['inclusion'] else 'FAILS'}"
             f" -> statement {check['statement']} -> signature {'ok' if steps['signature'] else 'FAILS'}"
             f" -> key {check['key']} "
             + ("pinned" if steps["pinned"] else ("NOT the pinned key" if steps["pinned"] is False else "not pinned")))
    line = f"receipt {check['index']}: {'verifies' if check['ok'] else 'DOES NOT VERIFY'}: {chain}"
    policy = (check.get("bundle", {}).get("statement") or {}).get("policy")
    if isinstance(policy, dict) and "authorization" in policy:
        authorization = policy["authorization"]
        flow = f"flow {policy.get('flow')} {str(policy.get('flow_sha256'))[:16]}"
        if isinstance(authorization, dict):
            line += (f"\n  the signed root names {flow}, authorized by authority key {authorization['key_id'][:16]} "
                     f"at version {authorization['version']} (flow manifest {authorization['manifest_sha256'][:16]}); "
                     f"`prismpath authorize verify` checks that manifest against the authority key")
        else:
            line += f"\n  the signed root names {flow}, run {authorization} (no verified flow manifest)"
    return line


def trail_cmd(args) -> int:
    pinned = [root_statement.load_public(path) for path in (args.pub or [])]
    if args.verify_bundle:
        return _verify_bundle_cmd(args, pinned)
    if not args.audit_log:
        from prismpath.cli import CliError
        raise CliError("name an audit log to read, or --verify-bundle FILE to check a receipt bundle")
    if args.anchor_dir:
        from prismpath.cli import CliError
        raise CliError("--anchor-dir checks a bundle's statement: use it with --verify-bundle")
    if not os.path.exists(args.audit_log):        # a mistyped path must not read as an empty, verified log
        import errno
        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), args.audit_log)
    if args.bundle_out and args.receipt is None:
        from prismpath.cli import CliError
        raise CliError("--bundle-out writes the bundle of one receipt: pass --receipt IDX")
    rep = run(args.audit_log, since=args.since, last=args.last, pinned=pinned or None,
              statements_path=args.statements, receipt=args.receipt)
    print(json.dumps(rep, indent=1) if args.json else render(rep))
    ok = rep["log"]["verifies"] and rep["signing"]["status"] != root_statement.INVALID
    if "receipt" in rep:
        ok = ok and rep["receipt"]["ok"]
    if args.bundle_out:
        bundle = rep["receipt"].get("bundle")
        if bundle is None:
            from prismpath.cli import CliError
            raise CliError(f"no bundle to write: {rep['receipt'].get('uncovered')}")
        with open(args.bundle_out, "w", encoding="utf-8") as handle:
            json.dump(bundle, handle, indent=1)
            handle.write("\n")
        if not args.json:
            print(f"bundle written to {args.bundle_out}; check it with `prismpath trail --verify-bundle "
                  f"{args.bundle_out} --pub INSTANCE_PUB`")
    return 0 if ok else 1


def _verify_bundle_cmd(args, pinned: List[bytes]) -> int:
    from prismpath.cli import CliError, require_program
    if args.audit_log:
        raise CliError("--verify-bundle checks a bundle on its own: drop the audit log (or drop --verify-bundle to read the log)")
    for flag in ("since", "last", "statements", "receipt", "bundle_out"):
        if getattr(args, flag) is not None:
            raise CliError(f"--{flag.replace('_', '-')} reads a log, and --verify-bundle does not take one")
    if args.anchor_dir:
        require_program("ots", "the OpenTimestamps client: pip install opentimestamps-client", "--anchor-dir")
    result = check_bundle(load_bundle(args.verify_bundle), pinned or None, args.anchor_dir, args.label)
    if args.json:
        print(json.dumps(result, indent=1))
    else:
        print(_bundle_text(result))
    return 0 if result["ok"] else 1


def add_parser(subparsers) -> None:
    parser = subparsers.add_parser("trail", help="Summarise an audit log over a window: decisions by outcome, rule, and cause code, "
                                            "swaps and attestations, whether the Merkle root verifies, and whether "
                                            "its signed roots do; or check a receipt bundle offline (--verify-bundle)")
    parser.add_argument("audit_log", nargs="?", default=None,
                        help="an append only JSONL written by prismpath.audit_log (decisions, swaps, attestations); "
                             "not given with --verify-bundle")
    parser.add_argument("--since", default=None, help="ISO 8601 lower bound on event time (UTC if no zone)")
    parser.add_argument("--last", type=int, default=None, help="only the most recent N events")
    parser.add_argument("--json", action="store_true", help="machine readable output")
    parser.add_argument("--pub", nargs="+", default=None, metavar="INSTANCE_PUB",
                        help="pin the deployment's instance public key(s): every root statement must be signed by "
                             "one, and a log with no statements is invalid rather than unsigned")
    parser.add_argument("--statements", default=None, metavar="PATH",
                        help="the root statements file (default: beside the log, run.audit.jsonl -> run.audit.roots.jsonl)")
    parser.add_argument("--receipt", type=int, default=None, metavar="IDX",
                        help="check one receipt offline: leaf -> inclusion path -> signed root -> signature -> key; "
                             "--json prints the self contained bundle")
    parser.add_argument("--bundle-out", dest="bundle_out", default=None, metavar="FILE",
                        help="with --receipt: write that receipt's bundle to FILE, for a reader to check with "
                             "--verify-bundle")
    parser.add_argument("--verify-bundle", dest="verify_bundle", default=None, metavar="FILE",
                        help="check a receipt bundle from FILE (a --bundle-out file, or the --json report of "
                             "--receipt) without the log: receipt -> leaf -> inclusion path -> signed root -> signature "
                             "-> key, result signed | signed-unpinned | invalid (exit 0, 0, 1). Offline, except the "
                             "anchor step: --anchor-dir runs `ots verify`, which needs Bitcoin block data (a node or "
                             "an explorer)")
    parser.add_argument("--anchor-dir", dest="anchor_dir", default=None, metavar="DIR",
                        help="with --verify-bundle: also check the statement's hash is in the batch `ledger anchor "
                             "--statements --out DIR` stamped, and that its OpenTimestamps proof verifies")
    parser.add_argument("--label", default="v1", help="the anchor label (default v1), with --anchor-dir")
    parser.set_defaults(func=trail_cmd)
