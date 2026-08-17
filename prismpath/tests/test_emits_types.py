# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Follow-on to item #1: `@emits(x=type)` cross-checked against the predicate-inferred type
(`emits-type-mismatch`, warning). The declaration and the node's own `when` edges must agree."""
from prismpath.parser import parse
from prismpath import analysis


def _codes(g):
    return [f for f in analysis.analyze(g) if f.code == "emits-type-mismatch"]


def _flow(emits, edges):
    body = "\n".join(f"-> t{i}: {c}" for i, c in enumerate(edges))
    targets = "\n\n".join(f"## t{i}\nDone." for i in range(len(edges)))
    return parse(f"""---
name: t
start: a
---

## a
{emits}
{body}
-> fallback: else

## fallback
Done.

{targets}
""")


def test_matching_declaration_is_silent():
    g = _flow("@emits(ok=bool, action=str, score=number)",
              ['when ok', 'when action == "fix"', 'when score > 3'])
    assert _codes(g) == []


def test_bool_declared_but_read_as_string_enum():
    g = _flow("@emits(action=bool)", ['when action == "fix"'])
    f = _codes(g)
    assert len(f) == 1 and f[0].node == "a"
    assert "declares boolean" in f[0].message and "as string" in f[0].message


def test_string_declared_but_read_numerically():
    g = _flow("@emits(score=str)", ["when score > 3"])
    assert len(_codes(g)) == 1


def test_int_token_maps_to_number_family():
    g = _flow("@emits(n=int)", ["when n >= 2"])
    assert _codes(g) == []


def test_bare_and_unknown_tokens_are_skipped():
    g = _flow("@emits(action, weird=frobnicate)", ['when action == "fix"'])
    assert _codes(g) == []                      # untyped + unrecognized: never guess


def test_declared_but_unread_field_is_skipped():
    g = _flow("@emits(extra=bool)", ["when other"])
    assert _codes(g) == []                      # no predicate reads `extra` -> nothing to compare


def test_numeric_enum_agrees_with_number_declaration():
    g = _flow("@emits(priority=number)", ["when priority == 3"])
    assert _codes(g) == []


def test_upstream_type_match():
    # Node a emits ok=bool. Node b is downstream of a and reads ok as a boolean context.
    g = parse("""---
name: t
start: a
---

## a
@emits(ok=bool)
-> b: always

## b
@emits(status=str)
-> done: when ok
-> done: else

## done
Done.
""")
    # No type mismatch, and also 'ok' is not flagged as undeclared on node b because it is declared upstream!
    findings = analysis.analyze(g)
    assert not [f for f in findings if f.code in ("emits-type-mismatch", "upstream-type-mismatch", "undeclared-field")]


def test_upstream_type_mismatch():
    # Node a emits status=str. Node b reads status as a number (status > 3)
    g = parse("""---
name: t
start: a
---

## a
@emits(status=str)
-> b: always

## b
-> done: when status > 3
-> done: else

## done
Done.
""")
    findings = analysis.analyze(g)
    mismatches = [f for f in findings if f.code == "upstream-type-mismatch"]
    assert len(mismatches) == 1
    assert mismatches[0].node == "b"
    assert "reads field 'status' as number" in mismatches[0].message and "declares it as string" in mismatches[0].message

