# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Follow-on to item #1: `@emits(x=type)` cross-checked against the predicate-inferred type
(`emits-type-mismatch`, warning). The declaration and the node's own `when` edges must agree."""
from prismpath.kernel.parser import parse
from prismpath.kernel import analysis

def _codes(graph):
    return [finding for finding in analysis.analyze(graph) if finding.code == "emits-type-mismatch"]


def _flow(emits, edges):
    body = "\n".join(f"-> t{index}: {condition}" for index, condition in enumerate(edges))
    targets = "\n\n".join(f"## t{index}\nDone." for index in range(len(edges)))
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
    graph = _flow("@emits(ok=bool, action=str, score=number)",
              ['when ok', 'when action == "fix"', 'when score > 3'])
    assert _codes(graph) == []


def test_bool_declared_but_read_as_string_enum():
    graph = _flow("@emits(action=bool)", ['when action == "fix"'])
    findings = _codes(graph)
    assert len(findings) == 1 and findings[0].node == "a"
    assert "declares boolean" in findings[0].message and "as string" in findings[0].message


def test_string_declared_but_read_numerically():
    graph = _flow("@emits(score=str)", ["when score > 3"])
    assert len(_codes(graph)) == 1


def test_int_token_maps_to_number_family():
    graph = _flow("@emits(n=int)", ["when n >= 2"])
    assert _codes(graph) == []


def test_bare_and_unknown_tokens_are_skipped():
    graph = _flow("@emits(action, weird=frobnicate)", ['when action == "fix"'])
    assert _codes(graph) == []                      # untyped + unrecognized: never guess


def test_declared_but_unread_field_is_skipped():
    graph = _flow("@emits(extra=bool)", ["when other"])
    assert _codes(graph) == []                      # no predicate reads `extra` -> nothing to compare


def test_numeric_enum_agrees_with_number_declaration():
    graph = _flow("@emits(priority=number)", ["when priority == 3"])
    assert _codes(graph) == []


def test_upstream_type_match():
    # Node a emits ok=bool. Node b is downstream of a and reads ok as a boolean context.
    graph = parse("""---
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
    findings = analysis.analyze(graph)
    assert not [finding for finding in findings if finding.code in ("emits-type-mismatch", "upstream-type-mismatch", "undeclared-field")]


def test_upstream_type_mismatch():
    # Node a emits status=str. Node b reads status as a number (status > 3)
    graph = parse("""---
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
    findings = analysis.analyze(graph)
    mismatches = [finding for finding in findings if finding.code == "upstream-type-mismatch"]
    assert len(mismatches) == 1
    assert mismatches[0].node == "b"
    assert "reads field 'status' as number" in mismatches[0].message and "declares it as string" in mismatches[0].message

