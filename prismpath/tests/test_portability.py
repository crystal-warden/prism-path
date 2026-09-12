# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Item #5 T1: the portability boundary — `analysis.portability` / `portability_tree`.

A flow is PORTABLE (runs on the ML-free port) iff every edge on every REACHABLE node is decidable:
`when` predicates, error edges, event edges. Semantic edges are exactly the violations.
"""
from prismpath.kernel.parser import parse, parse_file
from prismpath.kernel import analysis

def test_deterministic_only_flow_is_portable():
    graph = parse("""---
name: p
start: a
---

## a
-> b: when ok
-> c: else

## b
Done.

## c
-> a: on error
-> b: on event ping
""")
    assert analysis.portability(graph) == []


def test_semantic_edge_is_the_violation():
    graph = parse("""---
name: p
start: a
---

## a
-> b: the fix looks correct and complete
-> c: when visits > 3

## b
Done.

## c
Done.
""")
    findings = analysis.portability(graph)
    assert len(findings) == 1 and findings[0].code == "not-portable-edge" and findings[0].node == "a"
    assert findings[0].severity == "warning"                  # legal in the full engine, just not portable


def test_unreachable_semantic_edge_does_not_count():
    # portability is about what can actually execute — a semantic edge on an unreachable node is moot
    graph = parse("""---
name: p
start: a
---

## a
-> b: when ok

## b
Done.

## orphan
-> b: it seems finished
""")
    assert analysis.portability(graph) == []


def test_portability_tree_crosses_the_spawn_boundary(tmp_path):
    (tmp_path / "child.md").write_text("""---
name: child
start: r
---

## r
-> ok: the answer looks right
-> bad: when visits > 2

## ok
Done.

## bad
Done.
""")
    (tmp_path / "parent.md").write_text("""---
name: parent
start: d
---

## d
@spawn(child=child.md, join=all_done)
-> agg: on event all_done

## agg
Done.
""")
    graph = parse_file(str(tmp_path / "parent.md"))
    assert analysis.portability(graph) == []               # parent alone is portable
    tree = analysis.portability_tree(graph, str(tmp_path / "parent.md"))
    assert len(tree) == 1 and tree[0].code == "not-portable-edge"
    assert tree[0].node.startswith("child.md:")        # violation attributed to the child


def test_portability_tree_survives_a_cyclic_composition(tmp_path):
    (tmp_path / "a.md").write_text("""---
name: a
start: d
---

## d
@spawn(child=b.md, join=all_done)
-> f: on event all_done

## f
Done.
""")
    (tmp_path / "b.md").write_text("""---
name: b
start: d
---

## d
@spawn(child=a.md, join=all_done)
-> f: on event all_done

## f
Done.
""")
    graph = parse_file(str(tmp_path / "a.md"))
    assert analysis.portability_tree(graph, str(tmp_path / "a.md")) == []   # terminates, no findings


def test_shipping_soc_flow_is_portable():
    # the load-bearing example: the production triage flow's ROUTING is entirely decidable — the LLM
    # lives in the workers, not the control flow. This is the consulting story in one assert.
    # (path resolved relative to this test file so it works in both repo layouts)
    import pathlib
    flow = pathlib.Path(__file__).resolve().parent.parent / "flows" / "wazuh_triage.md"
    graph = parse_file(str(flow))
    assert analysis.portability(graph) == []


# --- tiered portability (P0/P1/P2) — a lint-computable flow property ----------------------
SEM_FLOW = """---
name: sem
start: route
---

## route
-> good: the change is correct and complete
-> bad: when visits > 3

## good
Done.

## bad
Done.
"""


def _write(tmp_path, name, body):
    path = tmp_path / name
    path.write_text(body)
    return path


def test_tier_p0_no_semantic_edges(tmp_path):
    flow_path = _write(tmp_path, "det.md", """---
name: det
start: a
---

## a
-> b: when ok
-> c: else

## b
Done.

## c
Done.
""")
    tier = analysis.portability_tier(parse_file(str(flow_path)), str(flow_path))
    assert tier["tier"] == "P0" and tier["semantic_edges"] == [] and tier["lock"] is None


def test_tier_p2_semantic_without_lock(tmp_path):
    flow_path = _write(tmp_path, "sem.md", SEM_FLOW)
    tier = analysis.portability_tier(parse_file(str(flow_path)), str(flow_path))
    assert tier["tier"] == "P2"
    assert tier["unlocked"] == ["the change is correct and complete"]


def test_tier_p1_semantic_fully_locked(tmp_path):
    import json
    flow_path = _write(tmp_path, "sem.md", SEM_FLOW)
    # a minimal lock covering the one reachable semantic condition (no embedder needed to test tiers)
    (tmp_path / "sem.lock").write_text(json.dumps({
        "version": 1, "flow": "sem", "flow_hash": "sha256:x",
        "embedder": {"name": "stub", "dim": 8, "probe": "p", "probe_vec": ""},
        "delta": 0.05,
        "conditions": {"the change is correct and complete": ""}}))
    tier = analysis.portability_tier(parse_file(str(flow_path)), str(flow_path))
    assert tier["tier"] == "P1" and tier["unlocked"] == [] and tier["lock"].endswith("sem.lock")


def test_tier_p2_when_lock_is_partial(tmp_path):
    import json
    body = SEM_FLOW.replace("-> bad: when visits > 3", "-> bad: it is broken beyond repair")
    flow_path = _write(tmp_path, "sem.md", body)
    (tmp_path / "sem.lock").write_text(json.dumps({
        "version": 1, "flow": "sem", "flow_hash": "sha256:x",
        "embedder": {"name": "stub", "dim": 8, "probe": "p", "probe_vec": ""},
        "delta": 0.05,
        "conditions": {"the change is correct and complete": ""}}))   # second condition missing
    tier = analysis.portability_tier(parse_file(str(flow_path)), str(flow_path))
    assert tier["tier"] == "P2" and tier["unlocked"] == ["it is broken beyond repair"]


def test_tree_tier_is_the_worst_across_children(tmp_path):
    _write(tmp_path, "child.md", SEM_FLOW)                 # P2 (no lock)
    flow_path = _write(tmp_path, "parent.md", """---
name: parent
start: d
---

## d
@spawn(child=child.md, join=all_done)
-> agg: on event all_done

## agg
Done.
""")
    tree = analysis.portability_tier_tree(parse_file(str(flow_path)), str(flow_path))
    assert tree["tier"] == "P2"                            # P0 parent + P2 child -> P2 deployment
    tiers = {path.split("/")[-1]: tier["tier"] for path, tier in tree["flows"].items()}
    assert tiers["parent.md"] == "P0" and tiers["child.md"] == "P2"
