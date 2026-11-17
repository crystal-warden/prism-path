# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The OpenTelemetry attributes of a governed decision: the outcome, the registered cause, the receipt."""
import pytest

from prismpath.agent import otel
from prismpath.agent.policy import Decision
from prismpath.kernel import causes


def test_an_allow_carries_no_cause():
    out = otel.attributes("allow", receipt_index=0, run="s1", tool_name="Read", call_id="c1")
    assert out == {"prismpath.decision.outcome": "allow", "prismpath.decision.decider": "prismpath.core/1",
                   "prismpath.decision.receipt.index": 0, "prismpath.decision.receipt.run": "s1",
                   "gen_ai.tool.name": "Read", "gen_ai.tool.call.id": "c1"}


def test_a_refusal_carries_its_registered_cause_and_the_registry_it_came_from():
    out = otel.attributes("refuse", cause_code=111, receipt_index=1, policy_sha256="ab" * 32)
    assert out["prismpath.decision.outcome"] == "deny"
    assert out["prismpath.decision.cause.code"] == 111
    assert out["prismpath.decision.cause.name"] == causes.name(111) == "agent:outside-workspace"
    assert out["prismpath.decision.cause.class"] == causes.cause_class(111)
    assert out["prismpath.decision.cause.registry"] == causes.registry_sha256()
    assert out["prismpath.decision.policy.sha256"] == "ab" * 32


def test_an_escalation_is_ask_and_the_proposed_names_carry_the_same_values():
    vendor = otel.attributes("escalate", cause_code=113)
    proposed = otel.attributes("escalate", cause_code=113, proposed_names=True)
    assert vendor["prismpath.decision.outcome"] == "ask"
    assert {k.replace(otel.PROPOSED, otel.VENDOR): v for k, v in proposed.items()} == vendor
    assert all(k.startswith(otel.PROPOSED) for k in proposed)


def test_values_are_only_strings_and_integers():
    for value in otel.attributes("refuse", cause_code=105, receipt_index=3, run="r").values():
        assert type(value) in (str, int)


@pytest.mark.parametrize("kind,code", [("allow", 111), ("refuse", None), ("escalate", None), ("maybe", None)])
def test_a_kind_and_cause_that_do_not_agree_are_refused(kind, code):
    with pytest.raises(ValueError):
        otel.attributes(kind, cause_code=code)


def test_an_unregistered_cause_is_refused():
    with pytest.raises(ValueError):
        otel.attributes("refuse", cause_code=250)


def test_from_a_decision():
    decision = Decision(kind="refuse", cause="agent:kill-by-pattern", cause_code=105, verdict={})
    assert otel.from_decision(decision, receipt_index=7)["prismpath.decision.cause.code"] == 105
