# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""model_check — Level M fragment classification + bounded reachability (`prismpath verify`).

The checker's contract, pinned:
  * exact verdicts (REACHABLE with a concrete witness / UNREACHABLE proven) over Level M;
  * sound over-approximation outside the fragment — never a false UNREACHABLE;
  * engine parity: first-match deterministic routing, semantic tier only when the
    deterministic tier can fail, error/event tiers explored as "may" paths.
"""
import pytest

from prismpath import model_check as mc
from prismpath.parser import parse
from prismpath.analysis import portability_tier


# ---------------------------------------------------------------- Level M classification

@pytest.mark.parametrize("cond", [
    "when tests_pass",                          # bare field
    "when not tests_pass",                      # not over an atom
    "when score >= 90",                         # field OP integer
    "when 3 < visits",                          # reversed orientation (mechanical flip)
    "when 1 < x < 5",                           # chained -> (1<x) and (x<5): both in-fragment (§4.3 normalize)
    "when status == 'done'",                    # string equality
    "when status != 'done'",
    "when ok == True",                          # bool constant
    "when kind in ('urgent', 'routine')",       # membership in scalar literals
    "when kind not in ['spam']",
    "when score >= 90 and not blocked",         # boolean combination of atoms
    "when a == 1 or b == 2 and not c",
    "always", "else", "false", "never",         # keyword rows (default / disabled)
    "on error",                                 # bare error default row
    "on error when error_count >= 3",           # error expr over an engine counter
])
def test_level_m_members(cond):
    ok, reason = mc.is_level_m(cond)
    assert ok, f"{cond!r} should be Level M (got reason {reason!r})"


@pytest.mark.parametrize("cond,reason", [
    ("when 1 < a < b", "field-vs-field"),                # chained desugars; the a<b conjunct is field-vs-field
    ("when score >= 0.9", "disallowed-or-unparseable"),  # float constant — the i32 fragment excludes it
    ("when a == b", "field-vs-field"),
    ("when x in 'abcdef'", "substring-in"),            # string RHS = substring test
    ("when x in items", "non-literal-collection"),     # runtime collection
    ("when x in [1, [2, 3]]", "nested-container"),
    ("when name > 'm'", "string-ordering"),            # string *ordering* excluded
    ("when 1", "constant-only"),                       # no field — not a table row
    # (`when True` reduces to the keyword `true` ∈ ALWAYS — a default row, in-fragment)
    ("the root cause is clear", "not-deterministic"),  # semantic tier
    # `is`/`is not` are outside the predicate sandbox (eval raises PredicateError) — the
    # classifier must not call table-compilable what the evaluator won't even run
    ("when x is None", "disallowed-or-unparseable"),
    ("when x is not None", "disallowed-or-unparseable"),
])
def test_level_m_non_members(cond, reason):
    ok, got = mc.is_level_m(cond)
    assert not ok and got == reason, f"{cond!r}: expected {reason!r}, got ok={ok} {got!r}"


def test_flow_level_m_and_tier_wiring():
    g = parse("""---
name: m
start: a
---
## a
-> b: when score > 5
-> c: else

## b
-> c: when kind in ('x', 'y')

## c
Done.
""")
    all_in, bad = mc.flow_level_m(g)
    assert all_in and bad == []
    tier = portability_tier(g, "/nonexistent/m.md")
    assert tier["tier"] == "P0" and tier["level_m"] is True

    g2 = parse("""---
name: m2
start: a
---
## a
-> b: when a == b
-> c: else

## b
## c
""")
    all_in2, bad2 = mc.flow_level_m(g2)
    assert not all_in2 and bad2[0]["reason"] == "field-vs-field"
    tier2 = portability_tier(g2, "/nonexistent/m2.md")
    assert tier2["tier"] == "P0" and tier2["level_m"] is False


def test_level_m_report_covers_reachable_deterministic_edges():
    g = parse("""---
name: r
start: a
---
## a
-> b: when x > 1
-> b: judgment call here

## b
""")
    rows = mc.level_m_report(g)
    assert len(rows) == 1 and rows[0]["level_m"] is True   # semantic edge not in the report


# ---------------------------------------------------------------- reachability: exact verdicts

FLOW_GATE = """---
name: gate
start: classify
---

## classify
-> human_review: when category == "billing_dispute" and amount > 500
-> billing: when category in ("billing", "billing_dispute")
-> general: else

## human_review
## billing
## general
"""


def test_reachable_with_concrete_witness():
    g = parse(FLOW_GATE)
    res = mc.check_reach(g, ["human_review"])
    r = res["human_review"]
    assert r.reachable == "yes"
    step = r.witness[-1]
    assert step.certainty == "certain" and step.example is not None
    # the witness outcome genuinely takes the edge under first-match
    assert step.example.get("category") == "billing_dispute"
    assert isinstance(step.example.get("amount"), (int, float)) and step.example["amount"] > 500


def test_assume_flips_reachability_to_proven_unreachable():
    g = parse(FLOW_GATE)
    res = mc.check_reach(g, ["human_review"], assume="amount <= 500")
    r = res["human_review"]
    assert r.reachable == "no" and r.proven, "amount<=500 must make the gate node unreachable, provably"
    # and the other branches stay reachable under the same assumption
    res2 = mc.check_reach(g, ["billing", "general"], assume="amount <= 500")
    assert res2["billing"].reachable == "yes"
    assert res2["general"].reachable == "yes"


def test_first_match_shadowing_respected():
    g = parse("""---
name: shadow
start: a
---
## a
-> b: always
-> c: when x > 0

## b
## c
""")
    res = mc.check_reach(g, ["b", "c"])
    assert res["b"].reachable == "yes"
    assert res["c"].reachable == "no" and res["c"].proven, \
        "an earlier always-true edge makes the later edge dead — first match wins"


def test_semantic_tier_gated_by_deterministic_failure():
    # with an `else` catch-all the deterministic tier can never fail -> semantic edge dead
    g = parse("""---
name: semgate
start: a
---
## a
-> b: else
-> c: the outcome looks risky

## b
## c
""")
    res = mc.check_reach(g, ["c"])
    assert res["c"].reachable == "no" and res["c"].proven

    # without the catch-all the semantic edge is live, but only as "may" (router's choice)
    g2 = parse("""---
name: semfree
start: a
---
## a
-> b: when done
-> c: the outcome looks risky

## b
## c
""")
    res2 = mc.check_reach(g2, ["c"])
    assert res2["c"].reachable == "may"


def test_visits_counter_modeled_with_saturation():
    g = parse("""---
name: loop
start: work
---
## work
-> done: when visits > 3
-> work: else

## done
""")
    res = mc.check_reach(g, ["done"])
    r = res["done"]
    assert r.reachable == "yes"
    assert r.depth == 4, "needs exactly 4 entries of work before visits > 3 fires"


def test_error_and_event_paths_are_may_and_excludable():
    g = parse("""---
name: err
start: work
---
## work
-> recovered: on error when error_count >= 2
-> done: when ok

## recovered
## done
""")
    res = mc.check_reach(g, ["recovered"])
    assert res["recovered"].reachable == "may"
    assert res["recovered"].witness[-1].via == "error"
    res2 = mc.check_reach(g, ["recovered"], include_errors=False)
    assert res2["recovered"].reachable == "no" and res2["recovered"].proven


def test_non_level_m_is_over_approximated_never_false_unreachable():
    # `a == b` (field-vs-field) is outside the fragment; candidate enumeration may or may not
    # find the coincidence — the edge must never be reported certainly-dead.
    g = parse("""---
name: over
start: s
---
## s
-> t: when a == b and a != None

## t
""")
    res = mc.check_reach(g, ["t"])
    assert res["t"].reachable in ("yes", "may")


def test_totality_rule_negation_includes_missing_field():
    # not(x > 5) is satisfied by a MISSING x (evaluator totality), so `b` is reachable with
    # an empty outcome — the classic "neither branch" trap the engine actually has.
    g = parse("""---
name: tot
start: a
---
## a
-> big: when x > 5
-> small: when x <= 5
-> neither: else

## big
## small
## neither
""")
    res = mc.check_reach(g, ["neither"])
    assert res["neither"].reachable == "yes", \
        "a missing x satisfies neither comparison — else must be provably takeable"


def test_unreachable_node_with_no_inbound():
    g = parse("""---
name: island
start: a
---
## a
-> b: always

## b
## orphan
Some unreferenced node.
""")
    res = mc.check_reach(g, ["orphan"])
    assert res["orphan"].reachable == "no" and res["orphan"].proven


# ---------------------------------------------------------------- CLI

def test_verify_cli_reach_and_forbid(tmp_path, capsys):
    from prismpath.cli import main
    flow = tmp_path / "gate.md"
    flow.write_text(FLOW_GATE)
    assert main(["verify", str(flow), "--reach", "billing"]) == 0
    assert main(["verify", str(flow), "--forbid", "human_review"]) == 1
    assert main(["verify", str(flow), "--forbid", "human_review",
                 "--assume", "amount <= 500"]) == 0
    capsys.readouterr()


def test_verify_cli_json_shape(tmp_path, capsys):
    import json as _json
    from prismpath.cli import main
    flow = tmp_path / "gate.md"
    flow.write_text(FLOW_GATE)
    rc = main(["verify", str(flow), "--reach", "human_review", "--level-m", "--json"])
    out = _json.loads(capsys.readouterr().out)
    assert rc == 0 and out["ok"] is True
    r = out["results"]["human_review"]
    assert r["reachable"] == "yes" and r["witness"][-1]["example"]
    assert out["level_m"]["flow"] is True
