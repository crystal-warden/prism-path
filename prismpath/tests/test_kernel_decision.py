# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The decision harness in the kernel (`prismpath.kernel.decision`, `prismpath.kernel.domain`).

The agent's `Policy` is the kernel's class bound to the agent's reading domain, so every shipped starter decides alike
through either name. The domain is an argument: a domain that lists other values for a category gives a different out
of domain answer, and the agent's domain holds the session fields' restrictive values. The trust path's modules import
the kernel and no agent module."""
from __future__ import annotations

import ast
import itertools
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from prismpath.agent import policy as agent_policy, profile, session_state  # noqa: E402
from prismpath.kernel import canon2, decision, domain  # noqa: E402

PACKAGE = Path(decision.__file__).resolve().parents[1]


def _starters():
    return [agent_policy.starter_path(name).read_bytes() for name in agent_policy.STARTERS]


def test_the_agent_policy_is_the_kernel_class_bound_to_the_agent_domain():
    assert issubclass(agent_policy.Policy, decision.Policy)
    assert agent_policy.Decision is decision.Decision
    assert agent_policy.OutsideDomain is decision.OutsideDomain
    assert agent_policy.target_decision is decision.target_decision
    assert profile.ProfileError is domain.DomainError
    assert profile.KNOWN_CATEGORIES is profile.AGENT_DOMAIN.categories
    assert profile.CLASSIFIER_ONLY is profile.AGENT_DOMAIN.unproduced
    assert agent_policy.Policy(_starters()[0]).domain is profile.AGENT_DOMAIN


def test_the_agent_domain_gives_the_session_fields_their_restrictive_values():
    assert dict(profile.AGENT_DOMAIN.defaults) == session_state.RESTRICTIVE
    assert tuple(profile.AGENT_DOMAIN.defaults) == session_state.FIELDS


def test_every_starter_decides_alike_through_the_kernel_and_the_agent_names():
    for image in _starters():
        agent, core = agent_policy.Policy(image), decision.Policy(image, profile.AGENT_DOMAIN)
        assert agent.stateful == core.stateful
        names, constant, groups = profile.domain_classes([agent.doc])
        assert (names, constant, groups) == domain.domain_classes([core.doc], profile.AGENT_DOMAIN)
        for combo in itertools.islice(itertools.product(*groups), 0, None, 997):     # a fixed sample, a few dozen
            reading = dict(zip(names, (group[0] for group in combo)), **constant)
            raw = agent.reading_bytes(reading)
            assert raw == core.reading_bytes(reading)
            assert agent.decide(raw) == core.decide(raw)
            assert decision.kind_of(core, reading) == core.decide(raw).kind


def test_the_domain_is_an_argument():
    image = agent_policy.starter_path("strict").read_bytes()
    narrow = domain.ReadingDomain(name="narrow", categories={**profile.AGENT_DOMAIN.categories,
                                                             "tool": ("read_file", "unknown")})
    with pytest.raises(decision.OutsideDomain):
        decision.Policy(image, narrow)
    wide = domain.ReadingDomain(name="wide", categories={**profile.AGENT_DOMAIN.categories,
                                                         "tool": profile.AGENT_DOMAIN.categories["tool"] + ("mcp",)})
    policy = decision.Policy(image, wide)
    assert not policy.stateful                       # this domain gives no defaults, so nothing is opted in to
    reading = {"tool": "mcp"}
    assert domain.reading_outside_domain(policy.doc["fields"], reading, wide) is None
    assert "outside" in domain.reading_outside_domain(policy.doc["fields"], reading, profile.AGENT_DOMAIN)


def test_a_domain_with_no_name_field_reads_zone_name_as_a_plain_category():
    when = ["cmp", "zone_name", "!=", ["str", "a"]]
    assert domain.name_problem(when, profile.AGENT_DOMAIN)
    assert not domain.name_problem(when, domain.ReadingDomain(name="plain", categories={}))


def test_holds_is_eval_condition_with_the_parse_kept():
    from prismpath.kernel import predicates
    reading = {"tool": "read_file", "classifier_version": 3}
    for condition in ('when tool == "read_file"', 'when tool != "read_file" or classifier_version > 2', "always",
                      "never", "when tool(", "when __import__('os')"):
        try:
            expected = predicates.eval_condition(condition, reading)
        except predicates.PredicateError:
            expected = False
        assert predicates.holds(condition, reading) is expected
        assert predicates.holds(condition, reading) is expected      # the second answer comes from the kept parse


def test_the_trust_path_decides_through_the_kernel_and_imports_no_agent_module():
    for name in ("floor.py", "heartbeat.py", "kinds.py", "widening.py"):
        tree = ast.parse((PACKAGE / "distribution" / name).read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
            elif isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
        assert not {module for module in imported if module.startswith(("prismpath.agent.policy",
                                                                         "prismpath.agent.profile"))}, name
        assert "prismpath.kernel.decision" in imported, name


def test_kind_of_gives_a_stateful_policy_the_restrictive_session_values():
    image = agent_policy.starter_path("session").read_bytes()
    policy = decision.Policy(image, profile.AGENT_DOMAIN)
    assert policy.stateful
    raw = policy.reading_bytes({"tool": "read_file"})
    assert {key: canon2.loads(raw)[key] for key in session_state.FIELDS} == session_state.RESTRICTIVE
