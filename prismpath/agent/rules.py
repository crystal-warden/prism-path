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

Outcomes. What became of each receipt is read from the run's `outcomes.jsonl` (prismpath/agent/run.py), after
`verify` has checked its chain and binding. Per rule the report adds `allowed_ran` and `allowed_no_outcome` for a
rule that allows, `asked_approved` (the person said yes and the call ran), `asked_failed` (it was started and failed or was
interrupted, so it was not a call that ran) and `asked_no_outcome` (declined, or approved and never ran, which cannot
be told apart) for a rule that escalates, and `refused` for a rule that
refuses and for the core's own refusals. A call still waiting for its outcome counts as having none. These counts
are records, never decisions: nothing here changes a rule, a policy or a verdict.

Unreachable. A rule is unreachable when no reading in the reading domain makes it the first rule that holds.
The domain is every combination of values of the policy's fields: a bool is true or false, an int is its min
to max range (up to 64 values), and a category is one of the values the classifier produces
(`prismpath.agent.classifier`, listed in the agent's reading domain, `prismpath.agent.profile.AGENT_DOMAIN`). The combinations include ones the classifier never
produces together, so a rule that only an impossible combination reaches is not reported (the finding is
conservative). A field with no finite domain (a category the classifier does not produce, a fixed point
number, an int with a wide range) is not enumerated: the rules that read it are reported as not checked, and
the other rules are checked with those rules left out, which can only make a rule look more reachable.

`--json` prints one object with these keys:

  config_dir, policy {name, image, sha256}, since (ISO time or null)
  receipts {counted, not_verified, other_policy, runs_counted,
            skipped [{session, receipts, reason}]}
  rules [{rule, condition, target, decision, cause, code, hits, last_hit,
          allowed_ran, allowed_no_outcome, asked_approved, asked_failed, asked_no_outcome, refused}]
  core_refusals [{cause, code, hits, last_hit, refused}]
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
                             "other_policy": 0, "runs_counted": 0, "skipped": [], "outcome": {}, "approved": {}}
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
            done = work.outcome_map()
            for line in (copy / JOURNAL).read_bytes().split(b"\n")[:-1]:
                journal_line = canon2.loads(line)
                raw = bytes.fromhex(journal_line["reading"])
                tally["counted"] += 1
                index = rule_index(policy, raw)
                had = journal_line["i"] in done
                result = done.get(journal_line["i"])
                if index is not None:
                    row = tally["outcome"].setdefault(index, {})
                    kind = _KIND[policy.decide(raw).kind]
                    key = "asked_failed" if kind == "asked" and result == "failed" else _OUTCOME_KEY[(kind, had)]
                    row[key] = row.get(key, 0) + 1
                    if kind == "asked" and result == "ran":
                        examples = tally["approved"].setdefault(index, {})
                        shown = reading_classes(canon2.loads(raw))
                        examples[shown] = examples.get(shown, 0) + 1
                else:
                    row = tally["outcome"].setdefault("core", {})
                    row["refused"] = row.get("refused", 0) + 1
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


_KIND = {"allow": "allowed", "escalate": "asked", "refuse": "refused"}
_OUTCOME_KEY = {("allowed", True): "allowed_ran", ("allowed", False): "allowed_no_outcome",
                ("asked", True): "asked_approved", ("asked", False): "asked_no_outcome",
                ("refused", True): "refused", ("refused", False): "refused"}
OUTCOME_KEYS = ("allowed_ran", "allowed_no_outcome", "asked_approved", "asked_failed", "asked_no_outcome", "refused")
MAX_EXAMPLES = 3


def reading_classes(reading: Dict[str, Any]) -> str:
    """The reading as classes only: each field the classifier set and its class (`tool=run_command command_class=mutating`),
    never a path, a command or a host. A reading holds only classes, so this is the reading with the empty ones left out."""
    skip = ("none", False, 0, None)
    return " ".join(f"{k}={'yes' if v is True else v}" for k, v in sorted(reading.items())
                    if k != "classifier_version" and v not in skip) or "(no class set)"


def _short(exc: BaseException) -> str:
    text = " ".join(str(exc).split()) or type(exc).__name__
    return text if len(text) <= 120 else text[:117] + "..."


def _count_lines(path: Path) -> int:
    try:
        return path.read_bytes().count(b"\n")
    except OSError:
        return 0


# ------------------------------------------------------------------------------------------ unreachable
def _domain(name: str, text: str):
    """The finite list of values of a field from its definition text, or None when it has no finite domain (the
    kernel's walk, `prismpath.kernel.domain`, over the agent's domain)."""
    from prismpath.agent.profile import AGENT_DOMAIN
    from prismpath.kernel import domain
    try:
        return domain.field_values(name, text, AGENT_DOMAIN)
    except domain.DomainError:
        return None


def unreachable(policy) -> Dict[str, Any]:
    """Which rules no reading can reach, by deciding every reading of the finite domain through the reference."""
    from prismpath.kernel import predicates
    from prismpath.agent.profile import AGENT_DOMAIN
    from prismpath.kernel.domain import names_read
    doc = policy.doc
    fields = doc["fields"]
    reads = [names_read(rule["when"], fields) for rule in doc["rules"]]
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
    chosen, readings = set(), 0
    for combo in itertools.product(*(domains[name] for name in names)):
        doc_reading = dict(zip(names, combo), **constant)
        if any(field in doc_reading and gate in doc_reading and doc_reading[field] != empty
               and doc_reading[gate] not in values for field, empty, gate, values in AGENT_DOMAIN.unproduced):
            continue            # a reading the classifier never gives (a destination without a connect)
        readings += 1
        for at, (_target, cond) in enumerate(edges):       # engine.first_deterministic, each condition parsed once
            if not predicates.is_deterministic(cond):
                continue
            try:
                if predicates.holds(cond, doc_reading):
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
        counted = tally["outcome"].get(row["rule"], {})
        row.update({key: counted.get(key, 0) for key in OUTCOME_KEYS})
    core_names = list(CORE_REFUSALS) + sorted(c for c in tally["core"] if c not in CORE_REFUSALS)
    core = [{"cause": c, "code": causes.code(c), "hits": tally["core"].get(c, 0),
             "last_hit": _iso(tally["core_last"].get(c)), "refused": tally["core"].get(c, 0)} for c in core_names]
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
    def what_became(row):
        if row["decision"] == "allow":
            return f"{row['allowed_ran']} ran, {row['allowed_no_outcome']} none"
        if row["decision"] == "escalate":
            return f"{row['asked_approved']} approved and ran, {row['asked_failed']} failed, {row['asked_no_outcome']} none"
        return f"{row['refused']} refused"
    body = [[row["rule"], row["hits"], what_became(row), row["last_hit"] or "-",
             row["target"] + (f" {row['cause']}" if row["cause"] else ""), row["condition"]] for row in data["rules"]]
    body += [["-", c["hits"], f"{c['refused']} refused", c["last_hit"] or "-", f"refuse_{c['code']} {c['cause']}",
              "(the core itself)"] for c in data["core_refusals"]]
    lines += _table(["rule", "hits", "outcome", "last hit", "target", "condition"], body)
    lines += ["", "outcome: for an allow rule, calls that ran (a PostToolUse or the sandbox runner reported it) and calls "
                  "with no outcome; for an escalate rule, calls the person approved that ran, calls that failed or were interrupted, "
                  "and calls with no outcome (declined, or approved and not run); a call still waiting counts as none. Records only; they decide nothing."]
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


def approvals(home: Path, policy, minimum: int, since: Optional[datetime]) -> Dict[str, Any]:
    """The escalate rules whose asks were approved and ran (a failed or interrupted call is not counted) at least `minimum` times, each with its counts and
    up to MAX_EXAMPLES readings as classes only, most often approved first. They are candidates for the owner to
    sign into the envelope as an allow rule; this lists them and changes nothing. An approval is an observation of
    what the person said yes to: it can change what the system knows and never what it is permitted to do."""
    rows = {row["rule"]: row for row in _rule_rows(policy)}
    tally = _read_runs(home, policy, since)
    out = []
    for number, row in rows.items():
        if row["decision"] != "escalate":
            continue
        counted = tally["outcome"].get(number, {})
        approved = counted.get("asked_approved", 0)
        if approved < minimum:
            continue
        examples = sorted(tally["approved"].get(number, {}).items(), key=lambda kv: (-kv[1], kv[0]))[:MAX_EXAMPLES]
        out.append({"rule": number, "condition": row["condition"], "target": row["target"], "cause": row["cause"],
                    "approved": approved, "asked_failed": counted.get("asked_failed", 0),
                    "asked_no_outcome": counted.get("asked_no_outcome", 0),
                    "asked": approved + counted.get("asked_failed", 0) + counted.get("asked_no_outcome", 0),
                    "examples": [{"reading": text, "approved": count} for text, count in examples]})
    out.sort(key=lambda r: (-r["approved"], r["rule"]))
    return {"note": APPROVALS_NOTE, "minimum": minimum, "since": since.strftime("%Y-%m-%dT%H:%M:%SZ") if since else None,
            "receipts": {"counted": tally["counted"], "runs_counted": tally["runs_counted"],
                         "not_verified": tally["not_verified"], "other_policy": tally["other_policy"]},
            "candidates": out}


APPROVALS_NOTE = "candidates for the owner to sign; nothing is changed"


def render_approvals(data: Dict[str, Any]) -> str:
    lines = [data["note"].capitalize() + ".",
             f"Escalate rules whose asks were approved and ran at least {data['minimum']} times, from "
             f"{data['receipts']['counted']} receipts of {data['receipts']['runs_counted']} runs that verify."]
    if not data["candidates"]:
        lines.append("none")
    for c in data["candidates"]:
        lines.append(f"rule {c['rule']}: {c['target']} {c['cause']}  {c['condition']}")
        lines.append(f"  approved and ran {c['approved']} of {c['asked']} asked ({c['asked_failed']} failed or interrupted, "
                     f"{c['asked_no_outcome']} with no outcome: declined, or approved and not run)")
        lines += [f"  e.g. {e['reading']}  ({e['approved']}x)" for e in c["examples"]]
    lines.append("To adopt one, write an allow rule for that class of call in the policy source and record it with "
                 "`prismpath agent init --policy FILE.rules.md`, which attests it with the authority key "
                 "(docs/guides/writing-agent-rules.md). This command never does.")
    return "\n".join(lines) + "\n"


def approvals_command(since: Optional[str], minimum: int, as_json: bool, out=None) -> int:
    from prismpath.agent import commands
    from prismpath.agent.policy import STARTERS, starter_of
    out = out or sys.stdout
    if minimum < 1:
        raise RulesError("--min must be at least 1")
    when = _parse_time(since) if since else None
    home = commands.config_dir()
    commands._require_keys(home)
    policy, _store = commands.load_checked(home)
    data = approvals(home, policy, minimum, when)
    out.write(json.dumps(data, indent=2) + "\n" if as_json else render_approvals(data))
    return 0


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
