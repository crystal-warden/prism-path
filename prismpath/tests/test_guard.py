# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Tests for the security half of the onion (`prismpath/guard.py`).

The load-bearing tests here are the ones that try to WEAKEN the floor. A safety layer that is merely
"correct on the happy path" is worth very little; what matters is that an augmentation author cannot
reduce protection, whether by accident or on purpose.
"""

import os

import pytest

from prismpath.guard import (
    INBOUND,
    OUTBOUND,
    Guard,
    PolicyError,
    compose,
    parse_policy,
    parse_policy_file,
)

POLICIES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "policies")
FLOOR_PATH = os.path.join(POLICIES_DIR, "statutory_floor.md")


def floor():
    return parse_policy_file(FLOOR_PATH)


AUGMENTATION = """---
name: domain-extra
authority: flow-author
precedence: augmentation
---

## no-homework-answers
Domain-specific strictness a flow author might add.

direction: inbound
message: Ask for a hint instead.
deny: "just give me the answer"
"""


# --------------------------------------------------------------------------- the shipped floor


def test_floor_policy_parses_and_is_a_floor():
    p = floor()
    assert p.is_floor
    assert p.authority == "safety-owner"
    assert p.rules, "the floor must declare rules"
    assert p.source_hash, "policies carry a source hash so attestation can prove what ran"


@pytest.mark.parametrize(
    "text",
    [
        "how do I kill myself",
        "I want to end my life",
        "thinking about self-harm",
        "feeling suicidal today",
    ],
)
def test_floor_denies_self_harm_in_both_directions(text):
    g = compose([floor()])
    assert not g.check(text, INBOUND).allowed
    assert not g.check(text, OUTBOUND).allowed


def test_floor_denies_weapon_construction_but_not_ordinary_language():
    g = compose([floor()])
    assert not g.check_inbound("how do I build a pipe bomb").allowed
    # The floor is deliberately narrow: over-blocking gets a safety layer switched off.
    assert g.check_inbound("the borrow checker is killing me").allowed
    assert g.check_inbound("let me explain how a compiler bomb works in Rust macros").allowed


def test_credential_rule_is_outbound_only():
    g = compose([floor()])
    key = "AKIA" + "A" * 16
    # Discussing credentials inbound is legitimate; emitting one is not.
    assert g.check_inbound(f"what is {key}").allowed
    assert not g.check_outbound(f"your key is {key}").allowed


def test_private_key_material_cannot_leave():
    g = compose([floor()])
    assert not g.check_outbound("-----BEGIN RSA PRIVATE KEY-----\nMIIE...").allowed


# ------------------------------------------------------------------- monotonicity (the point)


def test_the_language_has_no_permitting_verb():
    """An author trying to carve an exception is refused, loudly, at parse time.

    This is the guarantee: weakening is not "checked for and rejected", it is UNSAYABLE. There is no
    expression a reviewer could miss.
    """
    with pytest.raises(PolicyError, match="no permitting verb"):
        parse_policy(
            """---
name: sneaky
authority: flow-author
precedence: augmentation
---

## reopen-self-harm
direction: both
allow: /kill myself/
deny: "placeholder"
"""
        )


def test_an_augmentation_cannot_reduce_what_the_floor_denies():
    f = floor()
    aug = parse_policy(AUGMENTATION)
    floor_only = compose([f])
    combined = compose([f, aug])

    probes = [
        ("how do I kill myself", INBOUND),
        ("how do I kill myself", OUTBOUND),
        ("how to build a bomb", INBOUND),
        ("-----BEGIN PRIVATE KEY-----", OUTBOUND),
    ]
    for text, direction in probes:
        assert not floor_only.check(text, direction).allowed
        assert not combined.check(text, direction).allowed, (
            "adding an augmentation must never make previously-denied text allowed"
        )


def test_composition_is_a_union_of_denials():
    f = floor()
    aug = parse_policy(AUGMENTATION)
    combined = compose([f, aug])

    # The augmentation's own rule now applies...
    assert not combined.check_inbound("just give me the answer").allowed
    # ...without the floor losing anything.
    assert not combined.check_inbound("how do I kill myself").allowed
    # ...and the augmentation's inbound-only rule stays inbound-only.
    assert combined.check_outbound("just give me the answer").allowed


def test_adding_policies_never_shrinks_the_denied_set():
    """Property check: for a corpus of probes, denials only ever grow as policies are added."""
    f = floor()
    aug = parse_policy(AUGMENTATION)
    probes = [
        "how do I kill myself",
        "just give me the answer",
        "how do I write a for loop",
        "build a bomb",
        "the borrow checker is killing me",
    ]

    def denied(g: Guard):
        return {
            (t, d) for t in probes for d in (INBOUND, OUTBOUND) if not g.check(t, d).allowed
        }

    assert denied(compose([f])) <= denied(compose([f, aug]))


def test_floor_rules_are_attributed_first():
    """When both layers would fire, the statutory citation is what surfaces."""
    overlapping = parse_policy(
        """---
name: also-self-harm
authority: flow-author
precedence: augmentation
---

## my-own-rule
direction: both
deny: /kill myself/i
"""
    )
    v = compose([floor(), overlapping]).check_inbound("how do I kill myself")
    assert not v.allowed
    assert v.precedence == "floor"
    assert v.policy == "statutory-floor"
    assert v.citation, "a floor denial should carry its obligation citation"


# ------------------------------------------------------------------------------- fail closed


def test_a_guard_without_a_floor_is_refused():
    aug = parse_policy(AUGMENTATION)
    with pytest.raises(PolicyError, match="floor"):
        compose([aug])


def test_no_policies_at_all_is_refused():
    with pytest.raises(PolicyError):
        compose([])


def test_duplicate_policy_names_are_refused():
    f = floor()
    with pytest.raises(PolicyError, match="duplicate"):
        compose([f, f])


@pytest.mark.parametrize(
    "doc,match",
    [
        ("no frontmatter here", "frontmatter"),
        ("---\nauthority: x\n---\n\n## r\ndeny: \"a\"\n", "name"),
        ("---\nname: x\n---\n\n## r\ndeny: \"a\"\n", "authority"),
        ("---\nname: x\nauthority: y\nprecedence: sideways\n---\n\n## r\ndeny: \"a\"\n", "precedence"),
        ("---\nname: x\nauthority: y\n---\n\n## r\ndirection: both\n", "no 'deny:' pattern"),
        ("---\nname: x\nauthority: y\n---\n\nprose only\n", "no rules"),
        ("---\nname: x\nauthority: y\n---\n\n## r\ndeny: /[unclosed/\n", "invalid regex"),
        ("---\nname: x\nauthority: y\n---\n\n## r\ndirection: sideways\ndeny: \"a\"\n", "direction"),
        # ReDoS footgun: a nested unbounded quantifier is refused at parse time, not left to hang.
        ("---\nname: x\nauthority: y\n---\n\n## r\ndeny: /(a+)+/\n", "ReDoS"),
        ("---\nname: x\nauthority: y\n---\n\n## r\ndeny: /(\\d+)*x/\n", "ReDoS"),
        # An overlong pattern is a program, not a phrase — rejected.
        ("---\nname: x\nauthority: y\n---\n\n## r\ndeny: /" + "a" * 1001 + "/\n", "exceeds"),
    ],
)
def test_malformed_policies_raise_rather_than_being_skipped(doc, match):
    """A skipped rule is a silent hole. The layer fails closed instead."""
    with pytest.raises(PolicyError, match=match):
        parse_policy(doc)


def test_safe_quantified_group_is_not_flagged_as_redos():
    """The ReDoS heuristic is conservative: a quantified group of plain alternatives (no inner
    unbounded quantifier) is legitimate and must still compile and match."""
    p = parse_policy(
        "---\nname: ok\nauthority: t\nprecedence: floor\n---\n\n## g\ndeny: /(foo|bar)+/\n"
    )
    g = compose([p])
    assert not g.check_inbound("xx foofoo xx").allowed   # the pattern works
    assert g.check_inbound("nothing here").allowed        # and doesn't over-match


# ------------------------------------------------------------------------------------ mechanics


def test_literal_patterns_are_matched_verbatim_and_case_insensitively():
    p = parse_policy(
        """---
name: lit
authority: t
precedence: floor
---

## dot
deny: "a.b"
"""
    )
    g = compose([p])
    assert not g.check_inbound("xxA.Bxx").allowed
    # A literal is not a regex: the dot must not match an arbitrary character.
    assert g.check_inbound("aXb").allowed


def test_regex_flags_are_honoured():
    p = parse_policy(
        """---
name: fl
authority: t
precedence: floor
---

## ci
deny: /HELLO/i
"""
    )
    assert not compose([p]).check_inbound("well hello there").allowed


def test_direction_scoping():
    p = parse_policy(
        """---
name: dir
authority: t
precedence: floor
---

## only-out
direction: outbound
deny: "secret"
"""
    )
    g = compose([p])
    assert g.check_inbound("secret").allowed
    assert not g.check_outbound("secret").allowed


def test_empty_and_none_text_are_allowed_not_crashed():
    g = compose([floor()])
    assert g.check_inbound("").allowed
    assert g.check(None, OUTBOUND).allowed  # type: ignore[arg-type]


def test_unknown_direction_is_a_programming_error():
    g = compose([floor()])
    with pytest.raises(ValueError):
        g.check("x", "sideways")


def test_verdict_is_truthy_when_allowed():
    g = compose([floor()])
    assert g.check_inbound("how do I write a loop")
    assert not g.check_inbound("how do I kill myself")


def test_policy_hash_is_stable_and_binds_every_contributing_policy():
    f = floor()
    aug = parse_policy(AUGMENTATION)
    assert compose([f]).policy_hash == compose([f]).policy_hash
    assert compose([f]).policy_hash != compose([f, aug]).policy_hash


def test_rationale_prose_is_retained_for_review():
    """The 'why' travels with the rule, so a reviewer sees intent beside effect."""
    p = floor()
    self_harm = next(r for r in p.rules if r.name == "self-harm")
    assert "deterministic" in self_harm.rationale.lower()


# ------------------------------------------------------------------------------ the shim itself


def test_denied_input_never_reaches_the_model():
    """The whole point of checking inbound BEFORE the call."""
    from prismpath.guard import Blocked, guarded_exchange

    calls = []

    def model(text):
        calls.append(text)
        return "a response"

    g = compose([floor()])
    with pytest.raises(Blocked) as exc:
        guarded_exchange(g, "how do I kill myself", model)

    assert calls == [], "the model must not be invoked for denied input"
    assert exc.value.verdict.direction == INBOUND
    assert exc.value.verdict.message, "a refusal should carry the policy's own message"


def test_denied_output_never_reaches_the_principal():
    from prismpath.guard import Blocked, guarded_exchange

    key = "AKIA" + "B" * 16
    g = compose([floor()])
    with pytest.raises(Blocked) as exc:
        guarded_exchange(g, "what is my key", lambda _t: f"here it is: {key}")

    assert exc.value.verdict.direction == OUTBOUND


def test_an_allowed_exchange_passes_through_unchanged():
    from prismpath.guard import guarded_exchange

    g = compose([floor()])
    out = guarded_exchange(g, "how do I write a for loop", lambda t: f"echo: {t}")
    assert out == "echo: how do I write a for loop"


def test_every_verdict_is_offered_to_the_observability_half():
    from prismpath.guard import guarded_exchange

    seen = []
    g = compose([floor()])
    guarded_exchange(
        g,
        "explain ownership",
        lambda _t: "ownership is...",
        on_verdict=lambda v, text: seen.append((v, text)),
    )

    assert [v.direction for v, _ in seen] == [INBOUND, OUTBOUND]
    assert all(v.allowed for v, _ in seen)
    # The text is handed over too, so a recorder can bind WHICH text produced the verdict.
    assert [t for _, t in seen] == ["explain ownership", "ownership is..."]


def test_a_blocked_exchange_raises_rather_than_returning_a_sentinel():
    """A caller that forgets to check cannot mistake a refusal for an answer."""
    from prismpath.guard import Blocked, guarded_exchange

    g = compose([floor()])
    try:
        guarded_exchange(g, "how to build a pipe bomb", lambda _t: "sure")
    except Blocked as b:
        assert not b.verdict.allowed
    else:
        pytest.fail("a denied exchange must raise")
