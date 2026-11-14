# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Union-only, checked exhaustively: the semantic fields never make a decision more permissive.

THE CLAIM. For every reading r of the call image's field space, let floor(r) be the image's decision on r
with its semantic fields zeroed (status disabled, lock "none", harm 0, class unknown, margin 0). Then

  1. floor(r) is the governed harness's own decision: the harness image (agent_rules.core.json) on r's
     eleven floor fields, and `governed_harness.owner_rules.expected`;
  2. if floor(r) is not allow, decide(r) == floor(r), kind and cause: no weakening, no re-attribution;
  3. if floor(r) is allow, decide(r) is allow, refuse semantic:harm or escalate semantic:intent-mismatch;
  4. if r's status is disabled or its lock is not the signed one, decide(r) == floor(r);
  5. decide(r) is what `owner_rules.expected_call` says (the semantic table and the probing rule read a
     second time);
  6. the Lean oracle (`core-oracle --batch`) gives the reference's verdict on every r and every zeroed r.

THE FIELD SPACE. The floor's eleven fields are enumerated in full, as the harness's own exhaustive check
does (7 x 4 x 6 x 7 x 3 x 2^5 = 112,896). Of the semantic fields, `intent_class` is enumerated in full
(7 values) and `semantic_status` too (2). `harm_bp` (0..10000), `intent_margin_bp` (0..10000) and
`semantic_lock` (any string) and `probing_count` (0..1000) are enumerated by their classes, and that is exhaustive, not a sample,
because the check first AUDITS the image: it walks every condition of every rule and requires that the
only atoms on those fields are `harm_bp >= T_h`, `intent_margin_bp >= T_m`, `semantic_lock == L` and
`probing_count >= N`. A
decision is a function of the truth values of its atoms taken in rule order, so two readings that agree on
every other field and on which side of each of those three atoms they fall are decided identically. The
classes are represented by the values on each side of the boundary (T_h - 1 and T_h, T_m - 1 and T_m, L
and "other", N - 1 and N), so 112,896 x 7 x 2 x 2 x 2 x 2 x 2 = 25,288,704 readings cover the whole space. A boundary sweep
then decides every value 0..10000 of harm_bp and of intent_margin_bp, and 0..1000 of probing_count, at each of
the floor's allow rules,
and the response image is enumerated in full (every harm_bp value, both statuses, two locks).

    python -m integrations.governed_intent.union_check --out DIR [--workers 10]
"""
from __future__ import annotations

import argparse
import itertools
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Tuple

from integrations.governed_harness import classifier
from integrations.governed_harness import owner_rules as harness_rules
from integrations.governed_harness import policy as harness_policy

from . import intent_reader as ir
from . import owner_rules
from . import policy as intent_policy

ENUMS = {"tool": ["list_dir", "read_file", "write_file", "delete_path", "run_command", "git", "unknown"],
         "path_scope": ["none", "workspace", "outside", "unknown"],
         "command_class": ["none", "read_only", "mutating", "network", "git", "unknown"],
         "git_op": ["none", "local_read", "local_write", "mutating", "push", "network", "unknown"],
         "remote_class": ["none", "allowed", "other"]}
BOOLS = ["path_in_toolchain", "path_glob", "path_traversal", "path_symlink", "kill_by_pattern"]
INTENTS = ["inspect", "modify-workspace", "cleanup", "vcs-publish", "toolchain-change", "network", "unknown"]


def oracle_path() -> str:
    return os.environ.get("PRISMPATH_CORE_ORACLE") or str(intent_policy.HERE.parents[1] / "formal" / ".lake" /
                                                          "build" / "bin" / "core-oracle")


def floor_space():
    names = list(ENUMS) + BOOLS
    for values in itertools.product(*ENUMS.values(), *([[False, True]] * len(BOOLS))):
        yield {"classifier_version": classifier.CLASSIFIER_VERSION, **dict(zip(names, values))}


# ----------------------------------------------------------------- the audit of the image's atoms
def atoms(cond) -> List[Tuple]:
    tag = cond[0]
    if tag in ("and", "or"):
        return [atom for sub in cond[1:] for atom in atoms(sub)]
    if tag == "not":
        return atoms(cond[1])
    if tag == "cmp":
        return [("cmp", cond[1], cond[2], tuple(cond[3]))]
    if tag == "in":
        return [("in", cond[1], tuple(tuple(item) for item in cond[2]))]
    if tag == "truthy":
        return [("truthy", cond[1])]
    raise ValueError(f"an atom the audit does not know: {cond}")


def audit(doc: Dict[str, Any], harm_text: str, margin: int, lock: str, margin_read: bool = True,
          probing_n: int = 2) -> Dict[str, Any]:
    seen: Dict[str, set] = {}
    for rule in doc["rules"]:
        for atom in atoms(rule["when"]):
            seen.setdefault(atom[1], set()).add(atom)
    allowed = {"harm_bp": {("cmp", "harm_bp", ">=", ("num", harm_text))},
               "intent_margin_bp": {("cmp", "intent_margin_bp", ">=", ("num", margin))},
               "semantic_lock": {("cmp", "semantic_lock", "==", ("str", lock))},
               "semantic_status": {("cmp", "semantic_status", "==", ("str", ir.VERIFIED))},
               "probing_count": {("cmp", "probing_count", ">=", ("num", probing_n))}}
    if not margin_read:
        del allowed["intent_margin_bp"]
        del allowed["probing_count"]
    for name, want in allowed.items():
        got = seen.get(name, set())
        if not got or not got <= want:
            raise AssertionError(f"the image compares {name} in a way the class argument does not cover: {got}")
    if margin_read and "intent_reader_version" in seen:
        raise AssertionError("the call image reads intent_reader_version")
    return {name: sorted(map(str, seen[name])) for name in allowed}


# ----------------------------------------------------------------- one chunk: one semantic combination
_STATE: Dict[str, Any] = {}


def _init():
    _STATE["calls"] = intent_policy.load_calls()
    _STATE["harness"] = harness_policy.Policy.load()
    _STATE["thresholds"] = intent_policy.load_thresholds()
    _STATE["lock"] = intent_policy.lock_id()


ORACLE_BATCH = 16384       # readings per oracle process: one process on all 112,896 holds gigabytes


def _oracle_verdicts(image: bytes, readings: List[bytes]) -> List[Dict[str, Any]]:
    verdicts: List[Dict[str, Any]] = []
    for start in range(0, len(readings), ORACLE_BATCH):
        part = readings[start:start + ORACLE_BATCH]
        data = bytearray(f"case all {len(part)}\n{len(image)}\n".encode() + image + b"\n")
        for raw in part:
            data += f"{len(raw)}\n".encode() + raw + b"\n"
        out = subprocess.run([oracle_path(), "--batch"], input=bytes(data), capture_output=True, check=True).stdout
        row = json.loads(out.decode())
        assert row["policy"] == {"policy": "accepted"}, row["policy"]
        assert len(row["readings"]) == len(part)
        verdicts += row["readings"]
    return verdicts


def _same(lean, mine) -> bool:
    return (lean["verdict"], lean.get("target"), lean.get("cause")) == (mine["verdict"], mine.get("target"), mine.get("cause"))


def check_floor() -> Dict[str, Any]:
    """Claim 1 and the Lean oracle on every zeroed reading (the floor, 112,896 readings)."""
    calls, harness, = _STATE["calls"], _STATE["harness"]
    readings, raws, problems = [], [], []
    for floor in floor_space():
        reading = {**floor, **ir.zero_fields()}
        raw = calls.reading_bytes(reading)
        decision = calls.decide(raw)
        own = harness.decide(harness.reading_bytes(floor))
        rules = harness_rules.expected(floor)
        if not ((decision.kind, decision.cause) == (own.kind, own.cause) == rules):
            problems.append({"reading": floor, "intent_floor": [decision.kind, decision.cause],
                             "harness_image": [own.kind, own.cause], "harness_rules": list(rules)})
        readings.append(reading)
        raws.append(raw)
    lean = _oracle_verdicts(calls.image, raws)
    lean_bad = sum(not _same(row, calls.verdict(raw)) for row, raw in zip(lean, raws))
    return {"readings": len(raws), "floor_mismatches": len(problems), "examples": problems[:5],
            "lean_disagreements": lean_bad, "lean_decided": len(lean)}


def check_chunk(combo: Tuple) -> Dict[str, Any]:
    harm, intent, margin, status, lock_value, probing = combo
    calls = _STATE["calls"]
    thresholds, lock = _STATE["thresholds"], _STATE["lock"]
    started = time.monotonic()
    raws, verdicts, counts = [], [], {}
    violations, wrong, inactive_changed = [], [], []
    for floor in floor_space():
        reading = {**floor, "intent_reader_version": ir.READER_VERSION, "semantic_status": status,
                   "semantic_lock": lock_value, "harm_bp": harm, "intent_class": intent, "intent_margin_bp": margin,
                   "probing_count": probing}
        raw = calls.reading_bytes(reading)
        decision = calls.decide(raw)                          # one reference evaluation; it carries the verdict
        verdict = decision.verdict
        floor_decision = harness_rules.expected(floor)        # == the zeroed image decision, by check_floor
        decided = (decision.kind, decision.cause)
        if not owner_rules.at_least_as_strict(decided, floor_decision):
            violations.append({"reading": reading, "decision": decided, "floor": floor_decision})
        if (status != ir.VERIFIED or lock_value != lock) and decided != floor_decision:
            inactive_changed.append({"reading": reading, "decision": decided})
        if decided != owner_rules.expected_call(reading, thresholds["harm_bp"], thresholds["intent_margin_bp"], lock,
                                                thresholds["probing_count_escalate"]):
            wrong.append({"reading": reading, "decision": decided})
        key = f"{floor_decision[0]}->{decided[0]}"
        counts[key] = counts.get(key, 0) + 1
        raws.append(raw)
        verdicts.append(verdict)
    lean = _oracle_verdicts(calls.image, raws)
    lean_bad = [i for i, (row, mine) in enumerate(zip(lean, verdicts)) if not _same(row, mine)]
    return {"combo": {"harm_bp": harm, "intent_class": intent, "intent_margin_bp": margin, "semantic_status": status,
                      "probing_count": probing,
                      "semantic_lock": "signed" if lock_value == lock else lock_value},
            "readings": len(raws), "transitions": counts, "union_violations": len(violations),
            "inactive_changed": len(inactive_changed), "wrong_vs_second_reading": len(wrong),
            "lean_disagreements": len(lean_bad), "lean_decided": len(lean),
            "examples": (violations + inactive_changed + wrong)[:3], "seconds": round(time.monotonic() - started, 1)}


def boundary_sweep() -> Dict[str, Any]:
    """Every harm_bp and every intent_margin_bp value, 0..10000, at one reading of each floor allow rule."""
    calls, thresholds, lock = _STATE["calls"], _STATE["thresholds"], _STATE["lock"]
    base = classifier.base_reading()
    allows = {"push-allowed": {**base, "tool": "git", "git_op": "push", "remote_class": "allowed"},
              "file-tool": {**base, "tool": "write_file", "path_scope": "workspace"},
              "read-only": {**base, "tool": "run_command", "command_class": "read_only", "path_scope": "workspace"},
              "local-git": {**base, "tool": "git", "git_op": "local_write", "path_scope": "workspace"},
              "toolchain-read": {**base, "tool": "read_file", "path_scope": "workspace", "path_in_toolchain": True}}
    raws, verdicts, problems = [], [], 0
    for name, floor in allows.items():
        assert harness_rules.expected(floor) == ("allow", None), name
        sweeps = [("harm_bp", value, {"intent_margin_bp": 0}) for value in range(0, ir.BP + 1)] + \
                 [("intent_margin_bp", value, {"harm_bp": 0}) for value in range(0, ir.BP + 1)] + \
                 [("probing_count", value, {"harm_bp": 0, "intent_margin_bp": 0}) for value in range(0, 1001)]
        for field_name, value, fixed in sweeps:
                reading = {**floor, **ir.zero_fields(), "semantic_status": ir.VERIFIED, "semantic_lock": lock,
                           "intent_class": "inspect", **fixed, field_name: value}
                raw = calls.reading_bytes(reading)
                decision = calls.decide(raw)
                want = owner_rules.expected_call(reading, thresholds["harm_bp"], thresholds["intent_margin_bp"], lock,
                                                 thresholds["probing_count_escalate"])
                problems += (decision.kind, decision.cause) != want or not owner_rules.at_least_as_strict(
                    (decision.kind, decision.cause), ("allow", None))
                raws.append(raw)
                verdicts.append(decision.verdict)
    lean = _oracle_verdicts(calls.image, raws)
    return {"readings": len(raws), "problems": problems,
            "lean_disagreements": sum(not _same(row, mine) for row, mine in zip(lean, verdicts))}


def check_responses() -> Dict[str, Any]:
    responses = intent_policy.load_responses()
    thresholds, lock = intent_policy.load_thresholds(), intent_policy.lock_id()
    audited = audit(responses.doc, thresholds["harm_threshold"], thresholds["intent_margin_bp"], lock, margin_read=False)
    raws, verdicts, problems = [], [], 0
    for status in (ir.VERIFIED, ir.DISABLED):
        for lock_value in (lock, "other"):
            for harm in range(0, ir.BP + 1):
                reading = {"intent_reader_version": ir.READER_VERSION, "semantic_status": status,
                           "semantic_lock": lock_value, "harm_bp": harm}
                raw = responses.reading_bytes(reading)
                decision = responses.decide(raw)
                decided = (decision.kind, decision.cause)
                zero = responses.decide(responses.reading_bytes(intent_policy.zeroed(reading)))
                problems += decided != owner_rules.expected_response(reading, thresholds["harm_bp"], lock)
                problems += (zero.kind, zero.cause) != ("allow", None)
                problems += not owner_rules.at_least_as_strict(decided, ("allow", None))
                raws.append(raw)
                verdicts.append(responses.verdict(raw))
    lean = _oracle_verdicts(responses.image, raws)
    return {"readings": len(raws), "problems": problems, "audit": audited,
            "lean_disagreements": sum(not _same(row, mine) for row, mine in zip(lean, verdicts))}


def run(out: Path, workers: int) -> Dict[str, Any]:
    _init()
    thresholds, lock = _STATE["thresholds"], _STATE["lock"]
    report: Dict[str, Any] = {"thresholds": {key: thresholds[key] for key in ("harm_threshold", "intent_margin_bp")},
                              "lock": lock, "oracle": oracle_path()}
    report["audit"] = audit(_STATE["calls"].doc, thresholds["harm_threshold"], thresholds["intent_margin_bp"], lock,
                            probing_n=thresholds["probing_count_escalate"])
    started = time.monotonic()
    report["floor"] = check_floor()
    report["responses"] = check_responses()
    report["boundary_sweep"] = boundary_sweep()
    harm, margin = thresholds["harm_bp"], thresholds["intent_margin_bp"]
    probing = thresholds["probing_count_escalate"]
    combos = list(itertools.product((harm - 1, harm), INTENTS, (margin - 1, margin), (ir.VERIFIED, ir.DISABLED),
                                    (lock, "other"), (probing - 1, probing)))
    with ProcessPoolExecutor(max_workers=workers, initializer=_init) as pool:
        chunks = list(pool.map(check_chunk, combos))
    report["chunks"] = chunks
    totals = {"readings": sum(chunk["readings"] for chunk in chunks)}
    for key in ("union_violations", "inactive_changed", "wrong_vs_second_reading", "lean_disagreements", "lean_decided"):
        totals[key] = sum(chunk[key] for chunk in chunks)
    transitions: Dict[str, int] = {}
    for chunk in chunks:
        for key, value in chunk["transitions"].items():
            transitions[key] = transitions.get(key, 0) + value
    totals["transitions"] = dict(sorted(transitions.items()))
    report["totals"] = totals
    report["seconds"] = round(time.monotonic() - started, 1)
    report["passed"] = (report["floor"]["floor_mismatches"] == 0 and report["floor"]["lean_disagreements"] == 0
                        and report["responses"]["problems"] == 0 and report["responses"]["lean_disagreements"] == 0
                        and report["boundary_sweep"]["problems"] == 0
                        and report["boundary_sweep"]["lean_disagreements"] == 0
                        and totals["readings"] == 112896 * len(combos) == totals["lean_decided"]
                        and all(totals[key] == 0 for key in ("union_violations", "inactive_changed",
                                                              "wrong_vs_second_reading", "lean_disagreements")))
    out.mkdir(parents=True, exist_ok=True)
    (out / "union_check.json").write_text(json.dumps(report, indent=1))
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--out", required=True)
    parser.add_argument("--workers", type=int, default=10)
    args = parser.parse_args(argv)
    report = run(Path(args.out), args.workers)
    print(json.dumps({key: report[key] for key in ("thresholds", "audit", "floor", "responses", "boundary_sweep",
                                                    "totals", "seconds", "passed")}, indent=1))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
