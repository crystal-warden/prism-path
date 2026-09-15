# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Tranche 4 of item #4: static analysis that CROSSES THE FLOW BOUNDARY (the data-not-code stress
test — the whole composition tree is inspectable without running anything).

Two layers:
  * in-graph (analysis.analyze): a @spawn node with no matching `on event <join>` edge would deadlock.
  * cross-file (analysis.analyze_composition): the child flow must exist, parse, reach a terminal, and
    satisfy the parent's @expect against the child's @emits.
"""
from prismpath.kernel.parser import parse, parse_file
from prismpath.kernel import analysis

def _codes(findings):
    return {finding.code for finding in findings}


# --- in-graph: the deadlock check ----------------------------------------------------
def test_spawn_without_join_edge_is_a_deadlock_error():
    graph = parse("""---
name: p
start: dispatch
---

## dispatch
Fan out but forget the join edge.
@spawn(child=child.md, join=all_done)
-> escalate: on timeout

## escalate
Human.
""")
    findings = analysis.analyze(graph)
    assert "spawn-no-join-edge" in _codes(findings)
    assert any(finding.severity == "error" for finding in findings if finding.code == "spawn-no-join-edge")


def test_spawn_join_edge_present_no_error():
    graph = parse("""---
name: p
start: dispatch
---

## dispatch
@spawn(child=child.md, join=all_done)
-> aggregate: on event all_done

## aggregate
Combine.
""")
    assert "spawn-no-join-edge" not in _codes(analysis.analyze(graph))


def test_quorum_join_requires_on_event_quorum_edge():
    graph = parse("""---
name: p
start: dispatch
---

## dispatch
@spawn(child=child.md, join=quorum:2)
-> aggregate: on event all_done

## aggregate
Combine.
""")
    # declared quorum but only an all_done edge -> the quorum event has nowhere to land
    assert "spawn-no-join-edge" in _codes(analysis.analyze(graph))


def test_spawn_without_child_arg_errors():
    graph = parse("""---
name: p
start: dispatch
---

## dispatch
@spawn(join=all_done)
-> aggregate: on event all_done

## aggregate
Combine.
""")
    assert "spawn-no-child" in _codes(analysis.analyze(graph))


# --- cross-file: child existence / terminal / contract -------------------------------
VALID_CHILD = """---
name: child
start: review
---

## review
Review one item.
@emits(verdict)
-> done: always

## done
Done.
"""


def _parent(tmp_path, spawn_line, expect_line=""):
    body = f"""---
name: parent
start: dispatch
---

## dispatch
Fan out.
{spawn_line}
{expect_line}
-> aggregate: on event all_done

## aggregate
Combine.
"""
    path = tmp_path / "parent.md"
    path.write_text(body)
    return path


def test_missing_child_file_is_an_error(tmp_path):
    parent_path = _parent(tmp_path, "@spawn(child=nope.md, join=all_done)")
    graph = parse_file(str(parent_path))
    assert "spawn-missing-child" in _codes(analysis.analyze_composition(graph, str(parent_path)))


def test_child_without_terminal_is_an_error(tmp_path):
    (tmp_path / "loop.md").write_text("""---
name: loop
start: a
---

## a
Never terminates.
-> a: always
""")
    parent_path = _parent(tmp_path, "@spawn(child=loop.md, join=all_done)")
    graph = parse_file(str(parent_path))
    assert "spawn-child-no-terminal" in _codes(analysis.analyze_composition(graph, str(parent_path)))


def test_valid_composition_has_no_spawn_findings(tmp_path):
    (tmp_path / "child.md").write_text(VALID_CHILD)
    parent_path = _parent(tmp_path, "@spawn(child=child.md, join=all_done)", "@expect(verdict)")
    graph = parse_file(str(parent_path))
    comp = analysis.analyze_composition(graph, str(parent_path))
    assert not [finding for finding in comp if finding.code.startswith("spawn-")]      # child exists, terminal, @expect met


def test_expect_not_emitted_by_child_warns(tmp_path):
    (tmp_path / "child.md").write_text(VALID_CHILD)                  # child @emits(verdict), not `score`
    parent_path = _parent(tmp_path, "@spawn(child=child.md, join=all_done)", "@expect(verdict, score)")
    graph = parse_file(str(parent_path))
    comp = analysis.analyze_composition(graph, str(parent_path))
    unmet = [finding for finding in comp if finding.code == "spawn-expect-unmet"]
    assert unmet and unmet[0].severity == "warning" and "score" in unmet[0].message


def test_expect_silent_when_child_declares_no_emits(tmp_path):
    # no false positives: a child that never @emits opts out of the contract check
    (tmp_path / "bare.md").write_text("""---
name: bare
start: review
---

## review
Review.
-> done: always

## done
Done.
""")
    parent_path = _parent(tmp_path, "@spawn(child=bare.md, join=all_done)", "@expect(verdict)")
    graph = parse_file(str(parent_path))
    assert "spawn-expect-unmet" not in _codes(analysis.analyze_composition(graph, str(parent_path)))


def test_composition_check_is_separate_from_pure_analyze(tmp_path):
    # analyze() must stay pure/in-graph: it does NOT read the child file, so a missing child is not
    # reported by analyze() alone — only analyze_composition() (which does I/O) surfaces it.
    parent_path = _parent(tmp_path, "@spawn(child=ghost.md, join=all_done)")
    graph = parse_file(str(parent_path))
    assert "spawn-missing-child" not in _codes(analysis.analyze(graph))
    assert "spawn-missing-child" in _codes(analysis.analyze_composition(graph, str(parent_path)))


def test_spawn_expect_type_mismatch(tmp_path):
    (tmp_path / "child.md").write_text("""---
name: child
start: review
---

## review
@emits(score=bool)
-> done: always

## done
Done.
""")
    # Parent expects score to be a number, but child emits it as a bool
    parent_path = _parent(tmp_path, "@spawn(child=child.md, join=all_done)", "@expect(score=number)")
    graph = parse_file(str(parent_path))
    comp = analysis.analyze_composition(graph, str(parent_path))
    mismatches = [finding for finding in comp if finding.code == "spawn-expect-type-mismatch"]
    assert len(mismatches) == 1
    assert mismatches[0].node == "dispatch"
    assert "expects number" in mismatches[0].message
    assert "declares 'score' as boolean" in mismatches[0].message
