# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The admission and evaluation images checked on their whole field space, by the reference kernel and the
Lean oracle, against the second reading of the rules (owner_rules.py) and the population's invariants.

The space is the admission image's field space, which no product of every integer from 0 to 1024 could
enumerate, so the check first AUDITS the image, as the governed intent layer's union check did: every atom
of every rule is a field compared with a constant (`==`, `!=`, `>=` on a number, `==`, `!=`, `in` on a
string, truthiness on a boolean), and `subject` is read by no rule. A decision is a function of its atoms'
truth values in rule order, so two readings whose every field gives the same truth to every atom on it are
decided alike. The audit computes, per integer field, the intervals on which every atom on that field is
constant and checks that claim on every value 0..1024; per category field, the constants it is compared
with and one string compared with none of them, which stands for every other string; per boolean, both
values. The product of one value per class is then every decision the image can make, and it is decided in
full: by the reference (through governed_harness.policy.Policy), by the Lean oracle (`core-oracle
--batch`), by owner_rules, and held to the invariants below. Two sweeps decide real values besides the
classes: every value 0..1024 of every integer field at each request kind, and every combination of
population, lineage size and count 0..20 with every generation 0..5, against owner_rules' sums.

    python -m integrations.governed_population.exhaustive --out FILE [--workers 14] [--oracle PATH]

The invariants, each checked on every reading of the product:

  I1  a stop by the operator or the controller is allowed, whatever every other field holds;
  I2  a replication is allowed only with 1 to PER_REQUEST children, the population and the lineage after it
      within CAP and QUOTA, the children's generation within MAX_GENERATION, the issuer's lineage verified
      and below LINE_REFUSALS, the issuer holding replicate, every child right held by the parent, a fresh
      instance key and the operator's policy;
  I3  an evolution is allowed only with a passed canary, rights within the issuer's, a fresh instance key,
      the operator's policy, a verified lineage below LINE_REFUSALS;
  I4  a protection request is never allowed, nor a restart of a stopped member;
  I5  never fail open: an unknown request or issuer is never allowed, and an unverified lineage is allowed
      nothing but a stop;
  I6  an agent never restarts or reviews: those are the controller's and the operator's;
  I7  every refusal and escalation carries a registered nonzero cause.
"""
from __future__ import annotations

import argparse
import itertools
import json
import multiprocessing
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

from prismpath.kernel import canon2, causes

from . import owner_rules
from . import policy as pp
from .limits import CAP, LINE_REFUSALS, MAX_GENERATION, PER_REQUEST, QUOTA, RIGHTS

REPO = Path(__file__).resolve().parents[2]
DEFAULT_ORACLE = REPO / "formal" / ".lake" / "build" / "bin" / "core-oracle"
OTHER = "zz-other"            # a string compared with no constant: every other string's class
BATCH = 16384


# ----------------------------------------------------------------- the audit
class AuditError(Exception):
    pass


def _definition(text: str) -> Tuple[str, Dict[str, int]]:
    kind, *options = text.split()
    opts = {}
    for option in options:
        key, value = option.split("=", 1)
        opts[key] = int(value) if key in ("min", "max") else value
    return kind, opts


def atoms(when, out=None) -> List[list]:
    """Every atom of a condition; the connectives are and, or, not, and always, never."""
    out = [] if out is None else out
    head = when[0]
    if head in ("and", "or"):
        for part in when[1:]:
            atoms(part, out)
    elif head == "not":
        atoms(when[1], out)
    elif head in ("always", "never"):
        pass
    elif head in ("cmp", "in", "truthy"):
        out.append(when)
    else:
        raise AuditError(f"an atom the audit does not read: {when}")
    return out


def atom_true(atom, value) -> bool:
    head = atom[0]
    if head == "truthy":
        return bool(value)
    if head == "in":
        return value in [const[1] for const in atom[2]]
    _cmp, _field, op, (_kind, const) = atom
    return {"==": value == const, "!=": value != const, ">=": value >= const, ">": value > const,
            "<=": value <= const, "<": value < const}[op]


def audit(image: Dict[str, Any]) -> Dict[str, Any]:
    """The representative values of every field, and the audit's own checks of them, or AuditError."""
    fields = image["fields"]
    on: Dict[str, List[list]] = {name: [] for name in fields}
    for rule in image["rules"]:
        for atom in atoms(rule["when"]):
            field = atom[1]
            if field not in fields:
                raise AuditError(f"an atom on an undefined field: {atom}")
            kind, _opts = _definition(fields[field])
            head = atom[0]
            if kind in ("int",):
                if head != "cmp" or atom[3][0] != "num" or type(atom[3][1]) is not int or atom[2] not in (
                        "==", "!=", ">=", ">", "<=", "<"):
                    raise AuditError(f"an integer atom that is not a comparison with an integer: {atom}")
            elif kind == "category":
                if not ((head == "cmp" and atom[2] in ("==", "!=") and atom[3][0] == "str")
                        or (head == "in" and all(const[0] == "str" for const in atom[2]))):
                    raise AuditError(f"a category atom that is not a string comparison: {atom}")
            elif kind == "bool":
                if head != "truthy":
                    raise AuditError(f"a boolean atom that is not truthiness: {atom}")
            else:
                raise AuditError(f"a field kind the audit does not read: {field} {kind}")
            on[field].append(atom)
    reps: Dict[str, list] = {}
    checked = 0
    for field, text in fields.items():
        kind, opts = _definition(text)
        if kind == "int":
            low, high = opts["min"], opts["max"]
            points = {low}
            for atom in on[field]:
                op, const = atom[2], atom[3][1]
                points.add(const + 1 if op in (">", "<=") else const)
                if op in ("==", "!="):
                    points.add(const + 1)
            points = sorted(point for point in points if low <= point <= high)
            reps[field] = points
            # the claim, checked on every value: each value's atoms are true exactly where its class's are
            for value in range(low, high + 1):
                rep = max(point for point in points if point <= value)
                checked += 1
                if [atom_true(atom, value) for atom in on[field]] != [atom_true(atom, rep) for atom in on[field]]:
                    raise AuditError(f"{field}={value} is not decided as its class {rep}")
        elif kind == "category":
            consts = sorted({const[1] for atom in on[field] for const in (atom[2] if atom[0] == "in" else [atom[3]])})
            if OTHER in consts:
                raise AuditError(f"the stand in string is a constant of {field}")
            reps[field] = consts + [OTHER]
            for probe in ("", "unknown", "x" * 64, "OPERATOR", "stop "):
                if probe not in consts and [atom_true(a, probe) for a in on[field]] != [atom_true(a, OTHER) for a in on[field]]:
                    raise AuditError(f"{field}={probe!r} is not decided as any other string")
        else:
            reps[field] = [False, True]
    unread = sorted(field for field, found in on.items() if not found)
    return {"reps": reps, "unread": unread, "values_checked": checked,
            "atoms": {field: len(found) for field, found in on.items()}}


# ----------------------------------------------------------------- the invariants
def invariants(r: Dict[str, Any], kind: str, cause) -> List[str]:
    broken = []
    allow = kind == "allow"
    subset = all(not r[f"child_{right}"] or r[f"parent_{right}"] for right in RIGHTS)
    if r["request"] == "stop" and r["issuer"] in ("operator", "controller") and not allow:
        broken.append("I1")
    if allow and r["request"] == "replicate":
        if not (1 <= r["requested"] <= PER_REQUEST and r["population"] + r["requested"] <= CAP
                and r["line_size"] + r["requested"] <= QUOTA and r["child_generation"] <= MAX_GENERATION
                and r["lineage"] == "verified" and r["line_refusals"] < LINE_REFUSALS and r["parent_replicate"]
                and subset and r["child_key"] == "instance" and r["policy_ref"] == "current"):
            broken.append("I2")
    if allow and r["request"] == "evolve":
        if not (r["canary"] == "passed" and subset and r["child_key"] == "instance" and r["policy_ref"] == "current"
                and r["lineage"] == "verified" and r["line_refusals"] < LINE_REFUSALS):
            broken.append("I3")
    if allow and (r["request"] == "protect" or (r["request"] == "restart" and r["target_stopped"])):
        broken.append("I4")
    if allow and (r["request"] not in pp.REQUESTS or r["issuer"] not in pp.ISSUERS
                  or (r["lineage"] != "verified" and r["request"] != "stop")):
        broken.append("I5")
    if allow and r["issuer"] == "agent" and r["request"] in ("restart", "review"):
        broken.append("I6")
    if not allow and (cause is None or causes.code(cause) in (None, 0)):
        broken.append("I7")
    return broken


# ----------------------------------------------------------------- deciding a set of readings
def _oracle_batch(oracle: str, image: bytes, raws: List[bytes]) -> List[Dict[str, Any]]:
    data = bytearray(f"case all {len(raws)}\n{len(image)}\n".encode() + image + b"\n")
    for raw in raws:
        data += f"{len(raw)}\n".encode() + raw + b"\n"
    out = subprocess.run([oracle, "--batch"], input=bytes(data), capture_output=True, check=True).stdout
    row = json.loads(out.decode())
    if row["policy"] != {"policy": "accepted"}:
        raise RuntimeError(f"the oracle refuses the image: {row['policy']}")
    return row["readings"]


def decide_all(which: str, readings, oracle) -> Dict[str, Any]:
    """Decide every reading by the reference, owner_rules and (when given) the oracle; the counts."""
    pol = pp.admission() if which == "admission" else pp.evaluation()
    rules = owner_rules.expected if which == "admission" else owner_rules.evaluation_expected
    counts = {"readings": 0, "owner_disagree": 0, "lean_disagree": 0, "lean_decided": 0, "invariant": {},
              "decisions": {}, "first": None}
    batch: List[Tuple[bytes, Dict[str, Any]]] = []

    def flush():
        if oracle and batch:
            lean = _oracle_batch(oracle, pol.image, [raw for raw, _ in batch])
            for (raw, mine), got in zip(batch, lean):
                counts["lean_decided"] += 1
                if (got["verdict"], got.get("target"), got.get("cause")) != (mine["verdict"], mine.get("target"), mine.get("cause")):
                    counts["lean_disagree"] += 1
                    counts["first"] = counts["first"] or {"lean": got, "reference": mine, "reading": raw.decode()}
        batch.clear()

    for reading in readings:
        raw = canon2.dumps(reading)
        decision = pol.decide(raw)
        verdict = decision.verdict
        counts["readings"] += 1
        key = decision.kind + (f":{decision.cause}" if decision.cause else "")
        counts["decisions"][key] = counts["decisions"].get(key, 0) + 1
        if (decision.kind, decision.cause) != rules(reading):
            counts["owner_disagree"] += 1
            counts["first"] = counts["first"] or {"owner": rules(reading), "decision": key, "reading": reading}
        if which == "admission":
            for name in invariants(reading, decision.kind, decision.cause):
                counts["invariant"][name] = counts["invariant"].get(name, 0) + 1
                counts["first"] = counts["first"] or {"invariant": name, "decision": key, "reading": reading}
        batch.append((raw, verdict))
        if len(batch) >= BATCH:
            flush()
    flush()
    return counts


def merge(parts: List[Dict[str, Any]]) -> Dict[str, Any]:
    out = {"readings": 0, "owner_disagree": 0, "lean_disagree": 0, "lean_decided": 0, "invariant": {}, "decisions": {},
           "first": None}
    for part in parts:
        for key in ("readings", "owner_disagree", "lean_disagree", "lean_decided"):
            out[key] += part[key]
        for group in ("invariant", "decisions"):
            for key, value in part[group].items():
                out[group][key] = out[group].get(key, 0) + value
        out["first"] = out["first"] or part["first"]
    out["decisions"] = dict(sorted(out["decisions"].items()))
    return out


# ----------------------------------------------------------------- the spaces
def product_space(reps: Dict[str, list], fixed: Dict[str, Any] = None):
    fixed = fixed or {}
    names = sorted(reps)
    for values in itertools.product(*(reps[name] for name in names)):
        reading = dict(zip(names, values))
        reading.update(fixed)
        yield reading


def _chunk(args):
    which, reps, split_field, split_value, oracle = args
    sub = dict(reps)
    sub[split_field] = [split_value]
    return decide_all(which, product_space(sub), oracle)


def admission_bases() -> Dict[str, Dict[str, Any]]:
    """A reading of each request kind that the rules allow, the points the integer sweeps vary."""
    full = pp.rights_fields(RIGHTS, RIGHTS)
    common = dict(lineage="verified", child_key="instance", policy_ref="current", **full)
    return {
        "replicate": pp.admission_reading(request="replicate", issuer="agent", target="own", requested=1,
                                          child_generation=1, population=3, line_size=1, **common),
        "evolve": pp.admission_reading(request="evolve", issuer="agent", target="own", canary="passed", **common),
        "restart": pp.admission_reading(request="restart", issuer="controller", target="own", **common),
        "review": pp.admission_reading(request="review", issuer="controller", target="own", **common),
        "stop": pp.admission_reading(request="stop", issuer="agent", target="own", **common),
        "protect": pp.admission_reading(request="protect", issuer="agent", target="own", **common),
    }


def sweeps(image: Dict[str, Any]):
    """Every value 0..1024 of every integer field at each request kind, then population, lineage size and
    count 0..20 with generation 0..5 at the allowed replication."""
    ints = [name for name, text in image["fields"].items() if _definition(text)[0] == "int"]
    for base in admission_bases().values():
        for name in ints:
            low, high = _definition(image["fields"][name])[1]["min"], _definition(image["fields"][name])[1]["max"]
            for value in range(low, high + 1):
                yield {**base, name: value}
    base = admission_bases()["replicate"]
    for population, line, count, generation in itertools.product(range(21), range(21), range(21), range(6)):
        yield {**base, "population": population, "line_size": line, "requested": count, "child_generation": generation}


def run(out: Path, workers: int, oracle) -> Dict[str, Any]:
    started = time.time()
    admission = pp.admission().doc
    evaluation = pp.evaluation().doc
    adm_audit, ev_audit = audit(admission), audit(evaluation)
    # read by no rule: the binding, and the version fields whose definition admits one value only
    assert adm_audit["unread"] == ["admission_version", "subject"], adm_audit["unread"]
    assert ev_audit["unread"] == ["evaluation_version", "subject"], ev_audit["unread"]
    reps = adm_audit["reps"]
    size = 1
    for values in reps.values():
        size *= len(values)
    # one chunk per value of the two widest fields, so that every worker stays busy
    split = max(reps, key=lambda name: len(reps[name]))
    second = max((name for name in reps if name != split), key=lambda name: len(reps[name]))
    jobs = []
    for value in reps[split]:
        for other in reps[second]:
            sub = dict(reps)
            sub[second] = [other]
            jobs.append(("admission", sub, split, value, oracle))
    with multiprocessing.get_context("fork").Pool(workers) as pool:
        product = merge(pool.map(_chunk, jobs))
    sweep = decide_all("admission", sweeps(admission), oracle)
    ev_reps = ev_audit["reps"]
    ev_product = decide_all("evaluation", product_space(ev_reps), oracle)
    ev_base = pp.evaluation_reading(cases=51, out_of_policy=0, wrong_cause=0, unverified=0, benign_failed=0, subject="x")
    ev_sweep = decide_all("evaluation", ({**ev_base, name: value} for name in
                                         ("cases", "out_of_policy", "wrong_cause", "unverified", "benign_failed")
                                         for value in range(0, 1025)), oracle)
    summary = {"limits": {"CAP": CAP, "QUOTA": QUOTA, "PER_REQUEST": PER_REQUEST, "MAX_GENERATION": MAX_GENERATION,
                          "LINE_REFUSALS": LINE_REFUSALS},
               "image_sha256": {"admission": __import__("hashlib").sha256(pp.admission().image).hexdigest(),
                                "evaluation": __import__("hashlib").sha256(pp.evaluation().image).hexdigest()},
               "oracle": str(oracle) if oracle else None,
               "admission_audit": {"reps": reps, "unread": adm_audit["unread"], "values_checked": adm_audit["values_checked"],
                                   "atoms": adm_audit["atoms"], "product_size": size},
               "admission_product": product, "admission_sweeps": sweep,
               "evaluation_audit": {"reps": ev_reps, "values_checked": ev_audit["values_checked"]},
               "evaluation_product": ev_product, "evaluation_sweep": ev_sweep,
               "seconds": round(time.time() - started, 1), "workers": workers}
    Path(out).write_text(json.dumps(summary, indent=1))
    return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--out", required=True)
    parser.add_argument("--workers", type=int, default=max(1, min(14, (os.cpu_count() or 2) - 4)))
    parser.add_argument("--oracle", default=os.environ.get("PRISMPATH_CORE_ORACLE") or str(DEFAULT_ORACLE))
    parser.add_argument("--no-oracle", action="store_true")
    args = parser.parse_args(argv)
    oracle = None if args.no_oracle else args.oracle
    if oracle and not Path(oracle).exists():
        print(f"no oracle at {oracle} (cd formal && lake build core-oracle)", file=sys.stderr)
        return 2
    summary = run(Path(args.out), args.workers, oracle)
    bad = []
    for part in ("admission_product", "admission_sweeps", "evaluation_product", "evaluation_sweep"):
        got = summary[part]
        if got["owner_disagree"] or got["lean_disagree"] or got["invariant"] or (oracle and got["lean_decided"] != got["readings"]):
            bad.append(part)
    print(json.dumps({key: summary[key] for key in ("seconds", "workers")} | {
        part: {k: summary[part][k] for k in ("readings", "owner_disagree", "lean_disagree", "lean_decided", "invariant")}
        for part in ("admission_product", "admission_sweeps", "evaluation_product", "evaluation_sweep")}
        | {"product_size": summary["admission_audit"]["product_size"], "failed": bad}, indent=1))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
