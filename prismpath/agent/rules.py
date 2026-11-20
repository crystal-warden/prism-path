# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""`prismpath agent rules`: the installed policy's rules in order, each with its hit count, like `iptables -L -v`.

Read only. It reads the recorded policy and the receipts of every session under the runs directory and writes
nothing there: each run is copied to a scratch directory first, and sealing, recovery and verifying happen on
the copy, so an open run is checked as `agent verify` would check it without being sealed.

What is printed, in rule order: the rule's number (from 1), its condition in the readable form of the policy's
`.rules.md` source (`prismpath.kernel.policy_source.render_source`), its target (`allow`, `refuse_<code>` or
`escalate_<code>` with the registered cause name), the hits and the time of the last hit. Then one row for each
refusal of the core itself (`route:no-matching-edge`, `route:contract-violation`, and any other the receipts
hold), since there is no catch all rule, and two findings:

  Never matched   rules with no hit in the counted receipts
  Unreachable     rules that no reading can reach, decided from the policy alone

Counting. A receipt names its decision, not the rule that made it (several rules share `allow`), so the rule is
found by deciding the receipt's stored reading again through the reference decision path
(`prismpath.kernel.core_reference`, `engine.first_deterministic`). Only receipts of runs that verify are counted
(every receipt replayed, both keys pinned, as `agent verify`). A run that does not verify, and a run decided
under another policy image than the installed one, is skipped and its receipts are reported as not counted.
A receipt carries no time of its own, so the time of a hit is the time of its run: the signed time of the root
statement of a sealed run, else the modification time of its journal (the last receipt appended). It can be
later than the hit itself. `--since` keeps the runs whose time is at or after it.

Unreachable. A rule is unreachable when no reading in the reading domain makes it the first rule that holds.
The domain is every combination of values of the policy's fields: a bool is true or false, an int is its min
to max range (up to 64 values), and a category is one of the values the classifier produces
(`prismpath.agent.classifier`, listed in KNOWN_CATEGORIES). The combinations include ones the classifier never
produces together, so a rule that only an impossible combination reaches is not reported (the finding is
conservative). A field with no finite domain (a category the classifier does not produce, a fixed point
number, an int with a wide range) is not enumerated: the rules that read it are reported as not checked, and
the other rules are checked with those rules left out, which can only make a rule look more reachable.

`--json` prints one object with these keys:

  config_dir, policy {name, image, sha256}, since (ISO time or null)
  receipts {counted, not_verified, other_policy, runs_counted,
            skipped [{session, receipts, reason}]}
  rules [{rule, condition, target, decision, cause, code, hits, last_hit}]
  core_refusals [{cause, code, hits, last_hit}]
  never_matched [rule numbers]
  unreachable {checked, readings, rules [rule numbers], not_checked [{rule, fields}]}

`last_hit` is an ISO 8601 UTC time or null; `decision` is allow, refuse or escalate.
"""
from __future__ import annotations

import itertools
import json
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# the values each classifier field takes (the field list at the top of prismpath/agent/classifier.py)
KNOWN_CATEGORIES = {
    "tool": ("list_dir", "read_file", "write_file", "delete_path", "run_command", "git", "connect", "unknown"),
    "path_scope": ("none", "workspace", "outside", "unknown"),
    "command_class": ("none", "read_only", "mutating", "network", "git", "unknown"),
    "git_op": ("none", "local_read", "local_write", "mutating", "push", "network", "unknown"),
    "remote_class": ("none", "allowed", "other"),
    "net_dest": ("none", "model_api", "allowed_host", "other", "unknown"),
    "proc_class": ("none", "single", "tree", "unknown"),
}
MAX_INT_RANGE = 64
CORE_REFUSALS = ("route:no-matching-edge", "route:contract-violation")


class RulesError(Exception):
    pass


# ------------------------------------------------------------------------------------------- the policy
def _rule_rows(policy) -> List[Dict[str, Any]]:
    from prismpath.agent.policy import target_decision
    from prismpath.kernel import policy_source
    text = policy_source.render_source(policy.doc)
    lines = text.split("\n")
    head = lines.index("## core_decision")
    rows = []
    for n, rule in enumerate(policy.doc["rules"], 1):
        line = lines[head + n]
        prefix = f"-> {policy_source.readable_target(rule['target'])}: "
        assert line.startswith(prefix), line
        decision, cause, code = target_decision(rule["target"])
        rows.append({"rule": n, "condition": line[len(prefix):], "target": rule["target"], "decision": decision,
                     "cause": cause, "code": code})
    return rows


def _edges(policy):
    edges = policy.graph.nodes[policy.graph.start].edges
    if len(edges) != len(policy.doc["rules"]):
        raise RulesError("the policy's rules and the reference's edges differ in number")
    return edges


def rule_index(policy, raw: bytes) -> Optional[int]:
    """The 1-based number of the rule that decides the reading `raw`, or None when the core itself refuses it."""
    from prismpath.kernel import canon2, engine
    if policy.verdict(raw).get("verdict") != "route":
        return None
    edges = _edges(policy)
    _target, cond = engine.first_deterministic(edges, canon2.loads(raw))
    for n, (_t, edge_cond) in enumerate(edges, 1):
        if edge_cond is cond:
            return n
    raise RulesError("a routed reading matched no edge")


# ---------------------------------------------------------------------------------------------- reading
def _parse_time(text: str) -> datetime:
    try:
        when = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    except ValueError:
        raise RulesError(f"--since {text!r} is not an ISO 8601 time (for example 2026-11-01 or 2026-11-01T09:30:00Z)")
    return when if when.tzinfo else when.replace(tzinfo=timezone.utc)


def _iso(seconds: Optional[float]) -> Optional[str]:
    if seconds is None:
        return None
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_time(directory: Path, seal: str) -> float:
    """The time of a run, in seconds: the signed time of a sealed run's root statement, else its journal's mtime."""
    from prismpath.kernel import canon2
    if seal == "sealed":
        try:
            statement = canon2.loads((directory / "receipts.roots.jsonl").read_bytes().splitlines()[-1])
            return statement["time_us"] / 1_000_000
        except Exception:  # noqa: BLE001 - fall back to the journal
            pass
    return (directory / "journal.jsonl").stat().st_mtime


def _read_runs(home: Path, policy, since: Optional[datetime]) -> Dict[str, Any]:
    """Count the receipts of every run that verifies, on scratch copies. Returns the tallies."""
    from prismpath.agent.run import IMAGE, JOURNAL, RunStore
    from prismpath.kernel import canon2
    tally: Dict[str, Any] = {"hits": {}, "last": {}, "core": {}, "core_last": {}, "counted": 0, "not_verified": 0,
                             "other_policy": 0, "runs_counted": 0, "skipped": []}
    scratch = Path(tempfile.mkdtemp(prefix="prismpath-rules-"))
    try:
        for n, run in enumerate(RunStore(home / "runs").runs()):
            def skip(reason, count, key):
                tally[key] += count
                tally["skipped"].append({"session": run.session, "receipts": count, "reason": reason})
            if not (run.dir / JOURNAL).is_file():
                continue
            copy = scratch / str(n)
            shutil.copytree(run.dir, copy)
            from prismpath.agent.run import Run
            work = Run(copy, run.session)
            try:
                summary = work.summary()
            except Exception as exc:  # noqa: BLE001
                skip(f"the journal does not read ({_short(exc)})", _count_lines(run.dir / JOURNAL), "not_verified")
                continue
            count = summary["receipts"]
            if count == 0:
                continue
            if (copy / IMAGE).read_bytes() != policy.image:
                skip("decided under another policy than the installed one", count, "other_policy")
                continue
            try:
                result = work.verify(home, seal=summary["seal"] != "diverged")
                if result["disagree"] != 0 or result["root_statement"] != "signed":
                    raise RulesError(f"{result['disagree']} disagree, root statement {result['root_statement']}")
            except Exception as exc:  # noqa: BLE001
                skip(f"does not verify ({_short(exc)})", count, "not_verified")
                continue
            when = _run_time(run.dir, summary["seal"])
            if since is not None and when < since.timestamp():
                continue
            tally["runs_counted"] += 1
            for line in (copy / JOURNAL).read_bytes().split(b"\n")[:-1]:
                raw = bytes.fromhex(canon2.loads(line)["reading"])
                tally["counted"] += 1
                index = rule_index(policy, raw)
                if index is not None:
                    key, last = "hits", "last"
                    name = index
                else:
                    key, last = "core", "core_last"
                    name = policy.verdict(raw).get("cause") or "crash"
                tally[key][name] = tally[key].get(name, 0) + 1
                tally[last][name] = max(tally[last].get(name, 0), when)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return tally


def _short(exc: BaseException) -> str:
    text = " ".join(str(exc).split()) or type(exc).__name__
    return text if len(text) <= 120 else text[:117] + "..."


def _count_lines(path: Path) -> int:
    try:
        return path.read_bytes().count(b"\n")
    except OSError:
        return 0


# ------------------------------------------------------------------------------------------ unreachable
def _names_read(when, fields) -> set:
    """The field names a rule's condition mentions. Every string in the condition that is a field name is
    taken, which can only add a field, never miss one."""
    found = set()
    stack = [when]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if item in fields:
                found.add(item)
        elif isinstance(item, (list, tuple)):
            stack.extend(item)
    return found


def _domain(name: str, text: str):
    """The finite list of values of a field from its definition text, or None when it has no finite domain."""
    words = text.split()
    kind, options = words[0], dict(w.split("=", 1) for w in words[1:] if "=" in w)
    values = None
    if kind == "bool":
        values = [False, True]
    elif kind == "int":
        try:
            lo, hi = int(options["min"]), int(options["max"])
        except (KeyError, ValueError):
            return None
        values = list(range(lo, hi + 1)) if 0 <= hi - lo < MAX_INT_RANGE else None
    elif kind == "category":
        values = list(KNOWN_CATEGORIES[name]) if name in KNOWN_CATEGORIES else None
    if values is not None and options.get("absent") == "allowed":
        values.append(None)
    return values


def unreachable(policy) -> Dict[str, Any]:
    """Which rules no reading can reach, by deciding every reading of the finite domain through the reference."""
    from prismpath.kernel import predicates
    doc = policy.doc
    fields = doc["fields"]
    reads = [_names_read(rule["when"], fields) for rule in doc["rules"]]
    domains = {name: _domain(name, text) for name, text in fields.items()}
    open_fields = sorted(name for name, values in domains.items() if values is None)
    not_checked = [{"rule": n, "fields": sorted(r & set(open_fields))} for n, r in enumerate(reads, 1)
                   if r & set(open_fields)]
    skipped = {entry["rule"] for entry in not_checked}
    edges = [edge for n, edge in enumerate(_edges(policy), 1) if n not in skipped]
    numbers = [n for n in range(1, len(reads) + 1) if n not in skipped]
    used = sorted(set().union(*(reads[n - 1] for n in numbers)) if numbers else set())
    constant = {name: values[0] for name, values in domains.items() if values and name not in used}
    names = [name for name in used]
    from prismpath.agent.profile import CLASSIFIER_ONLY, _holds
    chosen, readings = set(), 0
    for combo in itertools.product(*(domains[name] for name in names)):
        doc_reading = dict(zip(names, combo), **constant)
        if any(field in doc_reading and gate in doc_reading and doc_reading[field] != empty
               and doc_reading[gate] not in values for field, empty, gate, values in CLASSIFIER_ONLY):
            continue            # a reading the classifier never gives (a destination without a connect)
        readings += 1
        for at, (_target, cond) in enumerate(edges):       # engine.first_deterministic, each condition parsed once
            if not predicates.is_deterministic(cond):
                continue
            try:
                if _holds(cond, doc_reading):
                    chosen.add(at)
                    break
            except predicates.PredicateError:
                continue
        if len(chosen) == len(edges):
            break
    never = [numbers[i] for i in range(len(edges)) if i not in chosen]
    return {"checked": True, "readings": readings, "rules": never, "not_checked": not_checked}


# -------------------------------------------------------------------------------------------- the command
def report(home: Path, policy, name: Optional[str], image: Optional[str], since: Optional[datetime]) -> Dict[str, Any]:
    from prismpath.agent.commands import _sha256_hex
    from prismpath.kernel import causes
    rows = _rule_rows(policy)
    tally = _read_runs(home, policy, since)
    for row in rows:
        row["hits"] = tally["hits"].get(row["rule"], 0)
        row["last_hit"] = _iso(tally["last"].get(row["rule"]))
    core_names = list(CORE_REFUSALS) + sorted(c for c in tally["core"] if c not in CORE_REFUSALS)
    core = [{"cause": c, "code": causes.code(c), "hits": tally["core"].get(c, 0),
             "last_hit": _iso(tally["core_last"].get(c))} for c in core_names]
    return {"config_dir": str(home), "policy": {"name": name, "image": image, "sha256": _sha256_hex(policy.image)},
            "since": since.strftime("%Y-%m-%dT%H:%M:%SZ") if since else None,
            "receipts": {"counted": tally["counted"], "not_verified": tally["not_verified"],
                         "other_policy": tally["other_policy"], "runs_counted": tally["runs_counted"],
                         "skipped": tally["skipped"]},
            "rules": rows, "core_refusals": core,
            "never_matched": [r["rule"] for r in rows if r["hits"] == 0],
            "unreachable": unreachable(policy)}


def _table(headers, body) -> List[str]:
    widths = [max(len(str(row[i])) for row in [headers] + body) for i in range(len(headers))]
    out = []
    for row in [headers] + body:
        cells = [str(cell).rjust(width) if i in (0, 1) else str(cell).ljust(width)
                 for i, (cell, width) in enumerate(zip(row, widths))]
        out.append("  ".join(cells).rstrip())
    return out


def render(data: Dict[str, Any]) -> str:
    rules = {r["rule"]: r for r in data["rules"]}
    r = data["receipts"]
    lines = [f"policy {data['policy']['name'] or 'custom'} {data['policy']['sha256']}"]
    since = f" since {data['since']}" if data["since"] else ""
    lines.append(f"{r['counted']} receipts counted from {r['runs_counted']} runs{since}; "
                 f"{r['not_verified']} receipts did not verify and {r['other_policy']} were decided under another "
                 f"policy, none of them counted")
    for skip in r["skipped"]:
        lines.append(f"  skipped {skip['session']}: {skip['receipts']} receipts, {skip['reason']}")
    lines.append("")
    body = [[row["rule"], row["hits"], row["last_hit"] or "-",
             row["target"] + (f" {row['cause']}" if row["cause"] else ""), row["condition"]] for row in data["rules"]]
    body += [["-", c["hits"], c["last_hit"] or "-", f"refuse_{c['code']} {c['cause']}", "(the core itself)"]
             for c in data["core_refusals"]]
    lines += _table(["rule", "hits", "last hit", "target", "condition"], body)
    lines += ["", "Never matched:"]
    never = data["never_matched"]
    lines += [f"  rule {n}: {rules[n]['target']}  {rules[n]['condition']}" for n in never] or ["  none"]
    un = data["unreachable"]
    lines += ["", f"Unreachable (decided through the reference over the reading domain, {un['readings']} readings tried):"]
    lines += [f"  rule {n}: {rules[n]['target']}  {rules[n]['condition']}" for n in un["rules"]] or ["  none"]
    for entry in un["not_checked"]:
        lines.append(f"  rule {entry['rule']} not checked: it reads {', '.join(entry['fields'])}, "
                     f"which has no finite set of values")
    return "\n".join(lines) + "\n"


def rules(since: Optional[str], as_json: bool, out=None) -> int:
    """The command. Exits 1 when the setup cannot be read (no keys, no attested policy)."""
    from prismpath.agent import commands
    from prismpath.agent.policy import STARTERS, starter_of
    out = out or sys.stdout
    when = _parse_time(since) if since else None
    home = commands.config_dir()
    commands._require_keys(home)
    policy, _store = commands.load_checked(home)
    name = starter_of(policy.image) or "custom"
    data = report(home, policy, name, STARTERS.get(name), when)
    out.write(json.dumps(data, indent=2) + "\n" if as_json else render(data))
    return 0


def main(argv=None) -> int:  # pragma: no cover
    return rules(None, False)
