# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""GR5 (spec-policy-distribution.md, section 13.2): the shipped gateway policy is grant monotone.

`formal/Core/Grant.lean` proves that a grant only narrows what a grant monotone policy allows: an `invalid` or
`expired` grant is allowed only where no grant is. This test checks that hypothesis of the shipped gateway policy
by deciding every reading the gateway can give it, each field over every value `reading.py` names (the route table's
classes are the policy's own), with the grant set to each of its four values. It also checks the policy is not
trivially monotone: a valid grant opens something no grant does."""
import itertools
from pathlib import Path

from prismpath.agent.policy import Policy

import prismpath

DEMO = Path(prismpath.__file__).resolve().parent / "gateway" / "policy" / "demo.core.json"

DOMAINS = {
    "http_reading_version": (1,),
    "method_class": ("read", "write", "delete", "other", "unknown"),
    "path_class": ("admin", "orders", "other", "unknown"),
    "body_class": ("none", "small", "large", "oversize", "unknown"),
    "content_class": ("none", "json", "form", "text", "other", "unknown"),
    "query": ("none", "present", "unknown"),
}
GRANTS = ("none", "valid", "invalid", "expired")


def _decisions():
    policy = Policy.load(DEMO)
    assert set(policy.fields) == set(DOMAINS) | {"grant"}
    names = sorted(DOMAINS)
    for values in itertools.product(*(DOMAINS[name] for name in names)):
        rest = dict(zip(names, values))
        yield rest, {grant: policy.decide(policy.reading_bytes({**rest, "grant": grant})).kind for grant in GRANTS}


def test_the_shipped_gateway_policy_is_grant_monotone():
    checked = opened = 0
    for rest, kinds in _decisions():
        checked += 1
        for bad in ("invalid", "expired"):
            if kinds[bad] == "allow":
                assert kinds["none"] == "allow", (rest, bad)
        if kinds["valid"] == "allow" and kinds["none"] != "allow":
            opened += 1
    assert checked == 1 * 5 * 4 * 5 * 6 * 3
    assert opened > 0
