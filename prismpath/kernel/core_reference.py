# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The Python reference's decision on a core case (docs/design/spec-verified-core.md, sections 6 and 8).

A case is a policy image, the flow text it renders to (or None, with why), and readings. The reference
decides it as the frozen field definition vectors compose it: `parser.parse` on the flow (which lowers and
checks the policy), then for each reading the strict canon/2 reader, `field_definitions.system_boundary`,
`engine.first_deterministic`, with `field_definitions.policy_check` beside it. These are the python leg of
the differential harness (`formal/diff/core_diff.py`, which imports them from here) and the replay of the
package's evidence verifier (`prismpath.ledgers.core_evidence`), one implementation for both; every result
is in the oracle's shape, so the two compare it to the oracle and to a receipt alike. Standard library and
the kernel only.
"""
from __future__ import annotations


# The causes of an image or a reading the strict reader refuses: a reader rule, or a document that is not its
# canonical spelling, which has a cause of its own (spec section 3.2).
UNREADABLE_POLICY = ("policy:unreadable", "policy:not-canonical")


def reading_cause(rule):
    return "reading:not-canonical" if rule == "not-canonical" else "reading:unreadable"


def unreadable_policy(why):
    from prismpath.kernel import causes
    rule = why.split(":", 1)[1]
    cause = "policy:not-canonical" if rule == "not-canonical" else "policy:unreadable"
    return {"policy": "refused", "cause": cause, "reason": rule, "code": causes.code(cause), "causes": [cause]}


def python_decision(graph, raw):
    """The reference's decision on one reading's bytes alone: the strict reader, the system boundary and the first
    deterministic rule, without the policy check beside them that `python_reading` adds."""
    from prismpath.kernel import canon2, causes

    def refuse(cause, **detail):
        return {"verdict": "refuse", "cause": cause, "code": causes.code(cause), **detail}

    try:
        doc = canon2.loads(raw)
    except canon2.Canon2Error as error:
        return refuse(reading_cause(error.rule), reason=error.rule), None
    except RecursionError:
        return {"verdict": "refuse", "cause": "crash", "reason": "RecursionError in canon2.loads"}, None
    if not isinstance(doc, dict):
        return refuse("reading:not-object"), None
    return _python_verdict(graph, doc, refuse), doc


def python_reading(graph, raw):
    from prismpath.kernel import field_definitions
    verdict, doc = python_decision(graph, raw)
    if doc is None:
        return verdict
    try:
        check = field_definitions.policy_check(graph, doc)
    except Exception as error:   # noqa: BLE001
        return {"verdict": "refuse", "cause": "crash", "reason": f"policy_check {type(error).__name__}: {error}"[:200]}
    verdict["policy_check"] = "pass" if check is None else {"field": check[0], "reason": check[1]}
    return verdict


def _python_verdict(graph, doc, refuse):
    from prismpath.kernel import engine, field_definitions
    try:
        refused = field_definitions.system_boundary(graph, doc)
        if refused is not None:
            return refuse("route:contract-violation", field=refused[0], reason=refused[1])
        target, _cond = engine.first_deterministic(graph.nodes[graph.start].edges, doc)
    except Exception as error:   # noqa: BLE001 - an exception is itself the finding
        return {"verdict": "refuse", "cause": "crash", "reason": f"{type(error).__name__}: {error}"[:200]}
    if target is None:
        return refuse("route:no-matching-edge")
    return {"verdict": "route", "target": target}


def python_leg(cases):
    from prismpath.kernel.field_definitions import FieldDefinitionError
    from prismpath.kernel.parser import parse
    out = {}
    for case in cases:
        flow, why = case["flow"], case["flow_why"]
        if flow is None and why.startswith("unreadable:"):
            out[case["id"]] = unreadable_policy(why)
            continue
        if flow is None:
            out[case["id"]] = {"policy": why}
            continue
        try:
            graph = parse(flow)
        except FieldDefinitionError as error:
            out[case["id"]] = {"policy": "refused", "reason": str(error)[:300], "cause": error.cause,
                               "code": error.code, "field": error.field, "policy_reason": error.reason,
                               "causes": [problem.cause for problem in error.problems]}
            continue
        except ValueError as error:
            out[case["id"]] = {"policy": "refused", "reason": str(error)[:300], "cause": None, "code": None,
                               "causes": []}
            continue
        except Exception as error:   # noqa: BLE001
            out[case["id"]] = {"policy": "crash", "reason": f"{type(error).__name__}: {error}"[:300]}
            continue
        out[case["id"]] = {"policy": "accepted", "defines": bool(graph.fields),
                           "readings": [python_reading(graph, raw) for raw in case["readings"]]}
    return out
