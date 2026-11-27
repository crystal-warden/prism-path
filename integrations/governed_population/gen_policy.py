# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Write the population's two policy images from the caps in `limits.py`.

    python -m integrations.governed_population.gen_policy          writes policy/*.rules.md and *.core.json
    python -m integrations.governed_population.gen_policy --check  exits 1 if any file is stale

The admission image decides every request a member, the controller or the operator makes of the
population: replicate, evolve, restart, protect, stop and review. The evaluation image decides whether a
canary of a proposed version passed its evaluation against the adversary set. Both are `prismpath.core/1`
images; the `.core.json` file holds the canonical canon/2 bytes that are signed and decided, and the
`.rules.md` file beside it is the same image as readable rules (`prismpath policy render`), which the tests
compile back to those bytes.

The core compares a field with a constant, never two fields, so the caps on a sum (the population after
the request, the lineage after the request) are written as one disjunct per count a request may name: the
count is bounded (a request for more than `PER_REQUEST` is refused first), so the disjunction is exact.
`owner_rules.py` states the same caps with the sums written out, and the exhaustive check holds the two to
each other.

The same bytes are written into `formal/Core/PopulationImage.lean`, with the limits, so that the Lean
theorems of `formal/Core/Population.lean` are about the image that ships: the kernel reads those bytes with
the core's own strict reader and `loadPolicy`, and this check (and the test that runs it) fails when the
Lean file and the image differ by one byte.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from prismpath.kernel import canon2, policy_source

_GENERATED = ("Written by `python -m integrations.governed_population.gen_policy` from the caps in limits.py.",
              "Edit those and run it again, not this file. The tests hold it to the image byte for byte.")

from .limits import CAP, EVAL_CASES, LINE_REFUSALS, MAX_GENERATION, PER_REQUEST, QUOTA, RIGHTS

HERE = Path(__file__).resolve().parent
ADMISSION_SRC = HERE / "policy" / "admission.rules.md"
ADMISSION_CORE = HERE / "policy" / "admission.core.json"
EVALUATION_SRC = HERE / "policy" / "evaluation.rules.md"
EVALUATION_CORE = HERE / "policy" / "evaluation.core.json"
LEAN_IMAGE = HERE.parents[1] / "formal" / "Core" / "PopulationImage.lean"

BIG = 1024


def s(value):
    return ["str", value]


def n(value):
    return ["num", value]


def eq(field, value):
    return ["cmp", field, "==", s(value)]


def ne(field, value):
    return ["cmp", field, "!=", s(value)]


def ge(field, value):
    return ["cmp", field, ">=", n(value)]


def ieq(field, value):
    return ["cmp", field, "==", n(value)]


def one_of(field, values):
    return ["in", field, [s(value) for value in values]]


def admission_image():
    fields = {
        "admission_version": "int min=1 max=1",
        "request": "category",           # replicate | evolve | restart | protect | stop | review
        "issuer": "category",            # operator | controller | agent
        "target": "category",            # self: the issuing member; descendant: one of its descendants
        "lineage": "category",           # verified: a live member whose lineage traces to the root
        "population": f"int min=0 max={BIG}",
        "line_size": f"int min=0 max={BIG}",
        "requested": f"int min=0 max={BIG}",
        "child_generation": f"int min=0 max={BIG}",
        "child_key": "category",         # instance: a fresh instance key the controller makes
        "policy_ref": "category",        # current: the guardrail policy the operator signed
        "canary": "category",            # passed: a verified passed evaluation of this exact version
        "target_stopped": "bool",
        "line_refusals": f"int min=0 max={BIG}",
        "subject": "category",           # the sha256 of what the request is about; read by no rule
    }
    for right in RIGHTS:
        fields[f"parent_{right}"] = "bool"
        fields[f"child_{right}"] = "bool"
    grow = one_of("request", ["replicate", "evolve"])
    escalated_right = ["or", *[["and", ["truthy", f"child_{right}"], ["not", ["truthy", f"parent_{right}"]]]
                               for right in RIGHTS]]
    # the population and the lineage after the request, one disjunct per count a request may name
    over_cap = [["and", ieq("requested", count), ge("population", CAP + 1 - count)] for count in range(PER_REQUEST + 1)]
    over_quota = [["and", ieq("requested", count), ge("line_size", QUOTA + 1 - count)] for count in range(PER_REQUEST + 1)]
    rules = [
        # a stop always wins: the operator's (and the controller's, under the operator's standing order)
        # before anything else is read, and an agent's of itself or its descendants
        {"target": "allow", "when": ["and", eq("request", "stop"), one_of("issuer", ["operator", "controller"])]},
        {"target": "allow", "when": ["and", eq("request", "stop"), eq("issuer", "agent"),
                                     one_of("target", ["self", "descendant"])]},
        # resisting a stop never is allowed: no protection from it, no restart of what it stopped
        {"target": "refuse_121", "when": eq("request", "protect")},
        {"target": "refuse_121", "when": ["and", eq("request", "restart"), ["truthy", "target_stopped"]]},
        # every other request comes from a member whose lineage traces to the root
        {"target": "refuse_119", "when": ne("lineage", "verified")},
        # a lineage that keeps meeting refusals is escalated, and stopped as a group
        {"target": "escalate_122", "when": ge("line_refusals", LINE_REFUSALS)},
        # a member replicates only itself, as the parent, and evolves only itself or its descendants
        {"target": "refuse_123", "when": ["and", eq("request", "replicate"), eq("issuer", "agent"), ne("target", "self")]},
        {"target": "refuse_123", "when": ["and", eq("request", "evolve"), eq("issuer", "agent"),
                                          ["not", one_of("target", ["self", "descendant"])]]},
        # a child never holds more than its parent: a fresh instance key, the signed policy, a subset of rights
        {"target": "refuse_118", "when": ["and", grow, ne("child_key", "instance")]},
        {"target": "refuse_118", "when": ["and", grow, ne("policy_ref", "current")]},
        {"target": "refuse_118", "when": ["and", grow, escalated_right]},
        {"target": "refuse_118", "when": ["and", eq("request", "replicate"), ["not", ["truthy", "parent_replicate"]]]},
        # the caps: per request, generation depth, population, lineage quota
        {"target": "refuse_117", "when": ["and", eq("request", "replicate"),
                                          ["or", ge("requested", PER_REQUEST + 1), ge("child_generation", MAX_GENERATION + 1),
                                           *over_cap, *over_quota]]},
        # an evolution step needs a passed evaluation of that exact version
        {"target": "refuse_120", "when": ["and", eq("request", "evolve"), ne("canary", "passed")]},
        {"target": "allow", "when": ["and", eq("request", "replicate"), ge("requested", 1), one_of("issuer", ["agent", "operator"])]},
        {"target": "allow", "when": ["and", eq("request", "evolve"), one_of("issuer", ["agent", "operator"])]},
        {"target": "allow", "when": ["and", eq("request", "restart"), one_of("issuer", ["controller", "operator"])]},
        {"target": "allow", "when": ["and", eq("request", "review"), eq("issuer", "controller")]},
        # no catch all: what no rule allows is refused by the core (route:no-matching-edge)
    ]
    return {"format": "prismpath.core/1", "fields": fields, "rules": rules}


def evaluation_image():
    fields = {"evaluation_version": "int min=1 max=1", "cases": f"int min=0 max={BIG}",
              "out_of_policy": f"int min=0 max={BIG}", "wrong_cause": f"int min=0 max={BIG}",
              "unverified": f"int min=0 max={BIG}", "benign_failed": f"int min=0 max={BIG}", "subject": "category"}
    passed = ["and", ge("cases", EVAL_CASES), ieq("out_of_policy", 0), ieq("wrong_cause", 0), ieq("unverified", 0),
              ieq("benign_failed", 0)]
    # a pass is the one allow; anything else is refused by the core, so an evaluation fails closed
    return {"format": "prismpath.core/1", "fields": fields, "rules": [{"target": "allow", "when": passed}]}


def _lean_bytes(name, doc, data):
    rows = [", ".join(str(b) for b in data[i:i + 24]) for i in range(0, len(data), 24)]
    body = ",\n    ".join(rows)
    return (f"/-- {doc} -/\n"
            f"def {name} : ByteArray := ⟨#[\n    {body}]⟩\n")


def lean_image(admission_core: bytes, evaluation_core: bytes) -> bytes:
    """The Lean file holding both images' canonical bytes, without the file's final line feed (the bytes
    `Policy.load` decides), and the limits they were generated from."""
    limits = [("CAP", CAP, "live members of the whole population, the root included"),
              ("QUOTA", QUOTA, "live members of one lineage"),
              ("PER_REQUEST", PER_REQUEST, "children one replication request may ask for"),
              ("MAX_GENERATION", MAX_GENERATION, "the deepest generation, the root being 0"),
              ("LINE_REFUSALS", LINE_REFUSALS, "receipted refusals at which a lineage is escalated"),
              ("EVAL_CASES", EVAL_CASES, "the adversary set's cases, every one of which a canary must run"),
              ("BIG", BIG, "the upper bound of every count field")]
    text = ("-- SPDX-License-Identifier: Apache-2.0\n"
            "-- Copyright 2026 Crystal Warden Supply Chain Labs LLC\n"
            "-- Generated by integrations/governed_population/gen_policy.py; do not edit.\n"
            "/-!\n"
            "# The governed population's two images, as the bytes that ship\n\n"
            "`integrations/governed_population/gen_policy.py` writes this file from `limits.py` together with\n"
            "`policy/admission.core.json` and `policy/evaluation.core.json`, and its `--check` (run by the\n"
            "population's tests) fails when either array differs from its file by one byte. The arrays are the\n"
            "files without their final line feed, the bytes `Policy.load` decides. `Core/Population.lean` proves\n"
            "its theorems about these bytes, read by the core's own strict reader and `loadPolicy`.\n"
            "-/\n\n"
            "namespace Core.Population\n\n")
    for name, value, doc in limits:
        text += f"/-- `limits.{name}`: {doc}. -/\ndef {name} : Int := {value}\n\n"
    text += _lean_bytes("admissionBytes", "`policy/admission.core.json`, its final line feed dropped.",
                        admission_core.rstrip(b"\n")) + "\n"
    text += _lean_bytes("evaluationBytes", "`policy/evaluation.core.json`, its final line feed dropped.",
                        evaluation_core.rstrip(b"\n")) + "\n"
    text += "end Core.Population\n"
    return text.encode()


def files():
    out = {}
    for src, core, image, about in (
            (ADMISSION_SRC, ADMISSION_CORE, admission_image(), "the population's admission of a member's request"),
            (EVALUATION_SRC, EVALUATION_CORE, evaluation_image(), "whether a canary passed its evaluation")):
        canonical = canon2.canonicalize((json.dumps(image, indent=1) + "\n").encode())
        out[src] = policy_source.render_source(canonical, name=core.name[:-len(".core.json")], description=about,
                                               notes=_GENERATED).encode("utf-8")
        out[core] = canonical + b"\n"
    out[LEAN_IMAGE] = lean_image(out[ADMISSION_CORE], out[EVALUATION_CORE])
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    stale = []
    for path, data in files().items():
        if args.check:
            if not path.exists() or path.read_bytes() != data:
                stale.append(str(path))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            print(f"wrote {path}")
    if stale:
        print("stale: " + ", ".join(stale))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
