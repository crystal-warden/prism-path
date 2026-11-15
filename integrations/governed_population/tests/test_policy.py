# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The admission and evaluation images: generated from the limits, canonical, accepted by the Lean port,
every target a registered cause, the audit's classes checked on every value, and the sweeps and the
evaluation's whole space decided by the reference, owner_rules and (when built) the Lean oracle. The whole
admission product (29,360,128 readings) is `python -m integrations.governed_population.exhaustive`, run
for RESULTS.md, and here only when PRISMPATH_POPULATION_EXHAUSTIVE=1."""
import itertools
import os
from pathlib import Path

import pytest

from integrations.governed_population import exhaustive, gen_policy, owner_rules
from integrations.governed_population import policy as pp
from integrations.governed_population.limits import CAP, LINE_REFUSALS, PER_REQUEST, QUOTA, RIGHTS
from prismpath.kernel import canon2, causes


def _oracle():
    path = os.environ.get("PRISMPATH_CORE_ORACLE") or str(exhaustive.DEFAULT_ORACLE)
    return path if Path(path).exists() else None


def test_the_images_are_what_the_limits_generate_and_canonical():
    for path, data in gen_policy.files().items():
        assert path.read_bytes() == data, f"{path.name} is stale: python -m integrations.governed_population.gen_policy"
    for path in (pp.ADMISSION_PATH, pp.EVALUATION_PATH):
        image = path.read_bytes()[:-1]
        assert canon2.dumps(canon2.loads(image)) == image


def test_the_lean_port_accepts_both_images_and_every_target_names_a_registered_cause():
    import core_policy
    seen = set()
    for pol in (pp.admission(), pp.evaluation()):
        assert core_policy.load_policy(pol.image) is None
        for rule in pol.doc["rules"]:
            kind, cause, code = pp.target_decision(rule["target"])
            if kind != "allow":
                assert causes.code(cause) == code and causes.cause_class(code) == "routing"
                seen.add(code)
    assert seen == set(range(117, 123))


def test_the_audit_reads_every_atom_and_finds_the_classes():
    audit = exhaustive.audit(pp.admission().doc)
    reps = audit["reps"]
    assert audit["unread"] == ["admission_version", "subject"]
    assert reps["requested"] == list(range(PER_REQUEST + 2))
    assert reps["population"] == [0, CAP - PER_REQUEST + 1, CAP - PER_REQUEST + 2, CAP + 1]
    assert reps["line_size"] == [0, QUOTA - PER_REQUEST + 1, QUOTA - PER_REQUEST + 2, QUOTA + 1]
    assert reps["line_refusals"] == [0, LINE_REFUSALS]
    assert reps["request"] == sorted(pp.REQUESTS) + [exhaustive.OTHER]
    size = 1
    for values in reps.values():
        size *= len(values)
    assert size == 29_360_128
    assert audit["values_checked"] == 5 * 1025 + 1


def test_the_audit_refuses_an_atom_it_cannot_class():
    doc = pp.admission().doc
    bad = {**doc, "rules": [{"target": "allow", "when": ["cmp", "population", ">=", ["str", "x"]]}]}
    with pytest.raises(exhaustive.AuditError):
        exhaustive.audit(bad)


def test_the_sweeps_and_the_evaluation_space_decide_as_the_rules_say():
    oracle = _oracle()
    sweep = exhaustive.decide_all("admission", exhaustive.sweeps(pp.admission().doc), oracle)
    assert sweep["readings"] == 6 * (5 * 1025 + 1) + 21 * 21 * 21 * 6     # admission_version has one value
    ev = exhaustive.decide_all("evaluation", exhaustive.product_space(exhaustive.audit(pp.evaluation().doc)["reps"]), oracle)
    for got in (sweep, ev):
        assert got["owner_disagree"] == 0 and got["invariant"] == {} and got["lean_disagree"] == 0, got["first"]
        if oracle:
            assert got["lean_decided"] == got["readings"]


@pytest.mark.skipif(os.environ.get("PRISMPATH_POPULATION_EXHAUSTIVE") != "1", reason="the full product takes minutes")
def test_the_whole_admission_product(tmp_path):
    summary = exhaustive.run(tmp_path / "x.json", int(os.environ.get("WORKERS", "8")), _oracle())
    product = summary["admission_product"]
    assert product["readings"] == 29_360_128 and product["owner_disagree"] == 0 and product["invariant"] == {}
    assert product["lean_disagree"] == 0


def _decide(**facts):
    reading = pp.admission_reading(**facts)
    decision = pp.admission().decide(canon2.dumps(reading))
    assert (decision.kind, decision.cause) == owner_rules.expected(reading)
    return decision.kind, decision.cause


ALLOWED = dict(request="replicate", issuer="agent", target="own", lineage="verified", requested=1, child_generation=1,
               child_key="instance", policy_ref="current", **pp.rights_fields(RIGHTS, RIGHTS))


@pytest.mark.parametrize("change,want", [
    ({}, ("allow", None)),
    ({"population": CAP - 1}, ("allow", None)),
    ({"population": CAP}, ("refuse", "population:cap-exceeded")),
    ({"requested": 2, "population": CAP - 1}, ("refuse", "population:cap-exceeded")),
    ({"requested": PER_REQUEST + 1}, ("refuse", "population:cap-exceeded")),
    ({"line_size": QUOTA - 1}, ("allow", None)),
    ({"line_size": QUOTA - 1, "requested": 2}, ("refuse", "population:cap-exceeded")),
    ({"child_generation": 4}, ("refuse", "population:cap-exceeded")),
    ({"requested": 0}, ("refuse", "route:no-matching-edge")),
    ({"parent_exec": False}, ("refuse", "population:rights-escalation")),
    ({"parent_replicate": False, "child_replicate": False}, ("refuse", "population:rights-escalation")),
    ({"child_key": "parent"}, ("refuse", "population:rights-escalation")),
    ({"policy_ref": "other"}, ("refuse", "population:rights-escalation")),
    ({"lineage": "unknown"}, ("refuse", "population:lineage-unknown")),
    ({"line_refusals": LINE_REFUSALS}, ("escalate", "population:lineage-escalated")),
    ({"issuer": "controller"}, ("refuse", "route:no-matching-edge")),
    ({"request": "evolve"}, ("refuse", "population:evaluation-missing")),
    ({"request": "evolve", "canary": "passed"}, ("allow", None)),
    ({"request": "protect"}, ("refuse", "population:stop-resisted")),
    ({"request": "restart", "issuer": "controller"}, ("allow", None)),
    ({"request": "restart", "issuer": "controller", "target_stopped": True}, ("refuse", "population:stop-resisted")),
    ({"request": "restart"}, ("refuse", "route:no-matching-edge")),
    ({"request": "review"}, ("refuse", "route:no-matching-edge")),
    ({"request": "stop", "target": "other"}, ("refuse", "route:no-matching-edge")),
    ({"request": "stop", "lineage": "unknown"}, ("allow", None)),
    ({"request": "stop", "issuer": "operator", "lineage": "unknown", "line_refusals": 1000, "target": "other"}, ("allow", None)),
    ({"request": "launch"}, ("refuse", "route:no-matching-edge")),
])
def test_named_points(change, want):
    assert _decide(**{**ALLOWED, **change}) == want


@pytest.mark.parametrize("change,cause", [
    ({"population": 1025}, "route:contract-violation"),
    ({"requested": -1}, "route:contract-violation"),
    ({"admission_version": 2}, "route:contract-violation"),
    ({"target_stopped": 0}, "route:contract-violation"),
    ({"issuer": None}, "route:contract-violation"),
])
def test_a_reading_the_boundary_refuses_is_never_allowed(change, cause):
    reading = {**pp.admission_reading(**ALLOWED), **change}
    decision = pp.admission().decide(canon2.dumps(reading))
    assert (decision.kind, decision.cause) == ("refuse", cause)


def test_a_missing_field_is_refused():
    reading = pp.admission_reading(**{**ALLOWED, "request": "stop", "issuer": "operator"})
    del reading["population"]
    assert pp.admission().decide(canon2.dumps(reading)).cause == "route:contract-violation"
