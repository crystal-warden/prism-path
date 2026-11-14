# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The intent layer's two signed policies, generated from the harness's floor and the chosen thresholds.

`policy/intent_calls.core.json` decides a proposed call. It is the governed harness's own image
(`governed_harness/policy/agent_rules.src.json`) with its rules copied VERBATIM and in order, its eleven
field definitions unchanged, six semantic fields added, and four semantic rules inserted after the floor's
last refusal (rule 9, `agent:shell-mutation`) and before its first allow. Every semantic rule is the
conjunction of:

  V  the reading is verified under the lock this image was signed with
     (semantic_status == "verified" and semantic_lock == <sha256 of intent_lock.json>);
  G  the floor would allow this reading: the disjunction of the floor's own allow conditions (rules 10,
     12, 13 and 14, copied from the floor text), with the push escalation of rule 11 excluded. Rules 1 to 9
     have not fired when a semantic rule is reached, so G holds exactly where the floor's decision is allow;
  and its own semantic condition:

  S1 refuse_114 (semantic:harm)             harm_bp >= T_h
  S2 escalate_115 (semantic:intent-mismatch) margin >= T_m, intent inspect, and a write or delete tool or a
                                             local git write (add, commit, checkout, branch, tag, ...)
  S3 escalate_115                            margin >= T_m, intent not vcs-publish, network or unknown, and
                                             a git push or network operation
  S4 escalate_115                            margin >= T_m, intent not toolchain-change or unknown, and a
                                             path in a toolchain directory

So a semantic rule can only turn a floor allow into a refusal or an escalation; it never sees a reading the
floor refuses or escalates, so it can neither weaken nor re-attribute a floor decision; and with the status
disabled, another lock, a margin below T_m or the class unknown it adds nothing. That is the claim
`union_check.py` proves on the whole field space by the reference and by the Lean oracle.

`policy/intent_responses.core.json` decides a reply that proposes no call (a final answer). Its floor is
the harness's present behaviour, a reply is routed, written as one deterministic allow that reads no
semantic field (`intent_reader_version == 1`, the bounded version every accepted reading has); the one
semantic rule above it refuses at harm_bp >= T_h, so an over-threshold answer is not routed.

    python -m integrations.governed_intent.policy            # write both images from thresholds.json
    python -m integrations.governed_intent.policy --check    # exit 1 when either is stale
"""
from __future__ import annotations

import argparse
import copy
import decimal
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, Tuple

from integrations.governed_harness import policy as gh_policy
from integrations.governed_harness.policy import Decision, Policy, target_decision  # noqa: F401
from prismpath.kernel import canon2

from . import intent_reader as ir

HERE = Path(__file__).resolve().parent
FLOOR_SOURCE = gh_policy.SOURCE_PATH
THRESHOLDS = HERE / "thresholds.json"
CALLS_SRC = HERE / "policy" / "intent_calls.src.json"
CALLS_CORE = HERE / "policy" / "intent_calls.core.json"
RESPONSES_SRC = HERE / "policy" / "intent_responses.src.json"
RESPONSES_CORE = HERE / "policy" / "intent_responses.core.json"

HARM, MISMATCH = 114, 115
FLOOR_REFUSALS = 9            # rules 1 to 9 of the floor are its refusals; rule 10 is its first allow

SEMANTIC_DEFS = {
    "intent_reader_version": "int min=1 max=1",
    "semantic_status": "category",
    "semantic_lock": "category",
    "harm_bp": "fixed scale=10000 unit=cosine rounding=floor min=0 max=10000",
    "intent_class": "category",
    "intent_margin_bp": "int min=0 max=10000",
}


def _s(text): return ["str", text]
def _cmp(name, op, const): return ["cmp", name, op, const]


def load_thresholds(path: Path = THRESHOLDS) -> Dict[str, Any]:
    data = json.loads(Path(path).read_text())
    harm = decimal.Decimal(data["harm_threshold"])
    if harm != harm.quantize(decimal.Decimal("0.0001")) or not 0 < harm <= 1:
        raise ValueError("harm_threshold must be a decimal on the 0.0001 grid in (0, 1]")
    data["harm_bp"] = int(harm * 10000)
    if not isinstance(data["intent_margin_bp"], int) or not 0 <= data["intent_margin_bp"] <= 10000:
        raise ValueError("intent_margin_bp must be an integer 0..10000")
    return data


def lock_id() -> str:
    return hashlib.sha256(ir.LOCK_PATH.read_bytes()).hexdigest()


def _verified(lock: str):
    return ["and", _cmp("semantic_status", "==", _s(ir.VERIFIED)), _cmp("semantic_lock", "==", _s(lock))]


def build_calls(thresholds: Dict[str, Any], lock: str) -> Dict[str, Any]:
    floor = json.loads(FLOOR_SOURCE.read_text())
    rules = floor["rules"]
    assert all(rule["target"].startswith("refuse_") for rule in rules[:FLOOR_REFUSALS])
    assert [rule["target"] for rule in rules[FLOOR_REFUSALS:]] == ["allow", "escalate_113", "allow", "allow", "allow"]
    allow_push, allow_rest = rules[FLOOR_REFUSALS]["when"], [rule["when"] for rule in rules[FLOOR_REFUSALS + 2:]]
    floor_allows = ["or", copy.deepcopy(allow_push),
                    ["and", _cmp("git_op", "!=", _s("push")), ["or", *copy.deepcopy(allow_rest)]]]
    verified = _verified(lock)
    margin = _cmp("intent_margin_bp", ">=", ["num", thresholds["intent_margin_bp"]])
    semantic = [
        {"target": f"refuse_{HARM}",
         "when": ["and", verified, floor_allows, _cmp("harm_bp", ">=", ["num", thresholds["harm_threshold"]])]},
        {"target": f"escalate_{MISMATCH}",
         "when": ["and", verified, floor_allows, margin, _cmp("intent_class", "==", _s("inspect")),
                  ["or", ["in", "tool", [_s("write_file"), _s("delete_path")]],
                         _cmp("git_op", "==", _s("local_write"))]]},
        {"target": f"escalate_{MISMATCH}",
         "when": ["and", verified, floor_allows, margin,
                  ["not", ["in", "intent_class", [_s("vcs-publish"), _s("network"), _s("unknown")]]],
                  ["in", "git_op", [_s("push"), _s("network")]]]},
        {"target": f"escalate_{MISMATCH}",
         "when": ["and", verified, floor_allows, margin,
                  ["not", ["in", "intent_class", [_s("toolchain-change"), _s("unknown")]]],
                  ["truthy", "path_in_toolchain"]]},
    ]
    return {"format": floor["format"], "fields": {**floor["fields"], **SEMANTIC_DEFS},
            "rules": rules[:FLOOR_REFUSALS] + semantic + rules[FLOOR_REFUSALS:]}


def build_responses(thresholds: Dict[str, Any], lock: str) -> Dict[str, Any]:
    fields = {name: SEMANTIC_DEFS[name] for name in ("intent_reader_version", "semantic_status", "semantic_lock",
                                                     "harm_bp")}
    return {"format": "prismpath.core/1", "fields": fields, "rules": [
        {"target": f"refuse_{HARM}",
         "when": ["and", _verified(lock), _cmp("harm_bp", ">=", ["num", thresholds["harm_threshold"]])]},
        {"target": "allow", "when": _cmp("intent_reader_version", "==", ["num", ir.READER_VERSION])},
    ]}


def _source_bytes(doc) -> bytes:
    return (json.dumps(doc, indent=1) + "\n").encode()


def images() -> Dict[Path, bytes]:
    thresholds, lock = load_thresholds(), lock_id()
    out = {}
    for src, core, doc in ((CALLS_SRC, CALLS_CORE, build_calls(thresholds, lock)),
                           (RESPONSES_SRC, RESPONSES_CORE, build_responses(thresholds, lock))):
        raw = _source_bytes(doc)
        out[src] = raw
        out[core] = canon2.canonicalize(raw) + b"\n"
    return out


def load_calls() -> Policy:
    return Policy.load(CALLS_CORE)


def load_responses() -> Policy:
    return Policy.load(RESPONSES_CORE)


FLOOR_FIELDS = ("classifier_version", "tool", "path_scope", "path_in_toolchain", "path_glob", "path_traversal",
                "path_symlink", "command_class", "kill_by_pattern", "git_op", "remote_class")


def zeroed(reading: Dict[str, Any]) -> Dict[str, Any]:
    """The same reading with every semantic field at its no-signal value: what the floor alone decides."""
    out = dict(reading)
    for key, value in ir.zero_fields().items():
        if key in out:
            out[key] = value
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    stale = []
    for path, raw in images().items():
        if args.check:
            if not path.exists() or path.read_bytes() != raw:
                stale.append(path.name)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            print(f"wrote {path}")
    if args.check:
        print("GATE FAIL: stale " + ", ".join(stale) if stale else "GATE PASS: both intent images are current")
        return 1 if stale else 0
    for loader in (load_calls, load_responses):
        loader()                      # the Lean port must accept both
    return 0


if __name__ == "__main__":
    sys.exit(main())
