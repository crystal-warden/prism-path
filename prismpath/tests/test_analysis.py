# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Static-analysis tests — "your flow compiles".

Two halves:
  * every broken fixture in tests/fixtures/broken/ must surface its target check (the corpus is
    the spec — one deliberately-broken flow per failure class);
  * every SHIPPING flow must have zero ERRORS and zero FALSE-POSITIVE warnings (the warnings that
    do fire on real flows are pinned below and are all genuine).
"""
import glob
import os

import pytest

from prismpath.kernel.parser import parse, parse_file
from prismpath.kernel import analysis

HERE = os.path.dirname(__file__)
BROKEN = os.path.join(HERE, "fixtures", "broken")
FLOWS = os.path.join(os.path.dirname(HERE), "flows")


def _shipping_flows():
    # `.tests.md` files are routing fixtures (Markdown tables), not flows — exclude them.
    return sorted(path for path in glob.glob(os.path.join(FLOWS, "*.md")) if not path.endswith(".tests.md"))


def _codes(graph):
    return {finding.code for finding in analysis.analyze(graph)}


# --- the broken-flow corpus: filename -> the code it must surface -----------------------
CORPUS = {
    "undefined_target.md": "undefined-target",
    "undefined_start.md": "undefined-start",
    "unsafe_predicate.md": "unsafe-predicate",
    "unreachable_node.md": "unreachable-node",
    "no_terminal.md": "no-terminal",
    "stuck_node.md": "possible-stuck",
    "shadowed_edge.md": "shadowed-edge",
    "shadowed_error_edge.md": "shadowed-error-edge",
    "shadowed_event_edge.md": "shadowed-event-edge",
    "undeclared_field.md": "undeclared-field",
    "field_only_violation.md": "field-only-violation",
    "unbounded_cycle.md": "unbounded-cycle",
    "always_false.md": "always-false-edge",
    "duplicate_condition.md": "duplicate-condition",
    "spiral_no_baseline.md": "spiral-no-baseline",
    "spiral_baseline_not_last.md": "spiral-baseline-not-last",
    "spiral_multi_baseline.md": "spiral-multi-baseline",
    "stateful_migration_undeclared.md": "stateful-migration-undeclared",
    "refresh_missing_param.md": "refresh-missing-param",
    "refresh_bad_param.md": "refresh-bad-param",
    "refresh_stale_bound.md": "refresh-stale-bound",
    "refresh_stale_tight.md": "refresh-stale-tight",
}


@pytest.mark.parametrize("fname,code", sorted(CORPUS.items()))
def test_broken_fixture_surfaces_its_check(fname, code):
    graph = parse_file(os.path.join(BROKEN, fname))
    assert code in _codes(graph), f"{fname} should surface {code}, got {_codes(graph)}"


def test_error_edge_ordering(tmp_path):
    from prismpath.kernel.parser import parse
    # correct order: conditional `on error when …` BEFORE the bare catch-all -> no shadowing
    ok = parse("---\nname: e\nstart: w\n---\n## w\nGo.\n-> d: it worked\n"
               "-> retry: on error when error_count < 3\n-> giveup: on error\n## retry\n-> w: always\n"
               "## giveup\n## d\n")
    assert "shadowed-error-edge" not in {finding.code for finding in analysis.analyze(ok)}
    # wrong order: bare `on error` first makes the later conditional dead
    bad = parse("---\nname: e\nstart: w\n---\n## w\nGo.\n-> d: it worked\n"
                "-> giveup: on error\n-> retry: on error when error_count < 3\n## retry\n-> w: always\n"
                "## giveup\n## d\n")
    assert "shadowed-error-edge" in {finding.code for finding in analysis.analyze(bad)}


def test_corpus_covers_every_analysis_code():
    # guard against a check with no fixture: every code the analyzer can emit is exercised.
    emitted = set()
    for fname in CORPUS:
        emitted |= _codes(parse_file(os.path.join(BROKEN, fname)))
    known = {"undefined-target", "undefined-start", "unsafe-predicate", "unreachable-node",
             "no-terminal", "possible-stuck", "shadowed-edge", "shadowed-error-edge",
             "shadowed-event-edge", "undeclared-field", "field-only-violation",
             "unbounded-cycle", "always-false-edge", "duplicate-condition"}
    assert known <= emitted


# --- zero false positives on real flows -------------------------------------------------
# Warnings that genuinely fire on shipping flows (all true positives, verified by hand):
#   bugfix / pr_review — cycles with no visits cap (rely on max_steps)
#   creator2 / release — deterministic-only nodes that aren't provably exhaustive
KNOWN_REAL_WARNINGS = {
    "bugfix.md": {"unbounded-cycle"},
    "pr_review.md": {"unbounded-cycle"},
    "creator2.md": {"possible-stuck"},
    "release.md": {"possible-stuck"},
}


@pytest.mark.parametrize("path", _shipping_flows())
def test_shipping_flows_have_no_errors(path):
    graph = parse_file(path)
    errors = [finding for finding in analysis.analyze(graph) if finding.severity == "error"]
    assert not errors, f"{os.path.basename(path)} has errors: {[finding.message for finding in errors]}"


@pytest.mark.parametrize("path", _shipping_flows())
def test_shipping_flow_warnings_are_only_the_known_true_positives(path):
    graph = parse_file(path)
    codes = {finding.code for finding in analysis.analyze(graph) if finding.severity == "warning"}
    allowed = KNOWN_REAL_WARNINGS.get(os.path.basename(path), set())
    assert codes <= allowed, (
        f"{os.path.basename(path)} produced unexpected warning(s) {codes - allowed} — "
        f"likely a false positive")


# --- targeted unit checks for the trickier reasoning ------------------------------------

def test_complementary_pair_is_exhaustive_no_stuck_warning():
    graph = parse("""---
start: t
---
## t
-> done: when tests_pass
-> retry: when visits > 3
-> t: when not tests_pass
## retry
-> done: when always
## done
""")
    assert "possible-stuck" not in _codes(graph)   # tests_pass / not tests_pass covers all


def test_two_distinct_flags_are_not_exhaustive_stuck_warning():
    graph = parse("""---
start: t
---
## t
-> ok: when passed
-> bad: when failed
## ok
-> done: when always
## bad
-> done: when always
## done
""")
    assert "possible-stuck" in _codes(graph)       # passed / failed are different fields


def test_visits_capped_cycle_is_not_flagged():
    graph = parse("""---
start: loop
---
## loop
-> done: when visits > 5
-> loop: keep working, not done yet
## done
""")
    assert "unbounded-cycle" not in _codes(graph)


def test_always_false_interval_contradiction():
    graph = parse("""---
start: a
---
## a
-> x: when visits > 10 and visits < 4
-> done: when always
## x
-> done: when always
## done
""")
    assert "always-false-edge" in _codes(graph)


def test_false_keyword_is_not_flagged_as_dead():
    # `false`/`never` deliberately disable an edge — not an "always-false" mistake.
    graph = parse("""---
start: a
---
## a
-> x: when false
-> done: when always
## x
-> done: when always
## done
""")
    assert "always-false-edge" not in _codes(graph)


def test_findings_json_shape():
    graph = parse_file(os.path.join(BROKEN, "no_terminal.md"))
    for finding in analysis.analyze(graph):
        finding_dict = finding.as_dict()
        assert set(finding_dict) == {"severity", "code", "node", "message"}
        assert finding_dict["severity"] in ("error", "warning")


# ---------------------------------------------------------------- spiral packing profile

def _severities(graph):
    return {finding.code: finding.severity for finding in analysis.analyze(graph)}


def test_spiral_gate_codes_are_errors_and_registered():
    """The profile's gate rule (owner-mandated): a convention-violating flow FAILS validate and is
    refused at bake in every materialization. That requires error severity + ERROR_CODES membership
    — pinned here so a refactor cannot silently demote the gates to warnings again."""
    assert "spiral-no-baseline" in analysis.ERROR_CODES
    assert "spiral-baseline-not-last" in analysis.ERROR_CODES
    graph = parse("""---
start: decide
packing: spiral
---
## decide
-> watch: else
-> page: when level >= 300
## page
## watch
""")
    assert _severities(graph).get("spiral-baseline-not-last") == "error"
    g2 = parse("""---
start: decide
packing: spiral
---
## decide
-> page: when level >= 300
## page
""")
    assert _severities(g2).get("spiral-no-baseline") == "error"


def test_spiral_profile_conformant_flow_is_clean():
    graph = parse("""---
start: decide
packing: spiral
---
## decide
-> page: when level >= 300
-> ticket: when level >= 200
-> watch: else
## page
## ticket
## watch
""")
    assert not [code for code in _codes(graph) if code.startswith("spiral")]


def test_spiral_profile_requires_baseline_last():
    graph = parse("""---
start: decide
packing: spiral
---
## decide
-> watch: else
-> page: when level >= 300
## page
## watch
""")
    assert "spiral-baseline-not-last" in _codes(graph)


def test_spiral_profile_requires_a_baseline():
    graph = parse("""---
start: decide
packing: spiral
---
## decide
-> page: when level >= 300
-> ticket: when level >= 200
## page
## ticket
""")
    assert "spiral-no-baseline" in _codes(graph)


def test_spiral_profile_multi_baseline_warns():
    graph = parse("""---
start: decide
packing: spiral
---
## decide
-> page: when level >= 300
-> watch: else
-> hold: when always
## page
## watch
## hold
""")
    assert "spiral-multi-baseline" in _codes(graph)


def test_spiral_rules_silent_without_declaration():
    # the identical convention-violating flow, undeclared: profile rules must not fire
    graph = parse("""---
start: decide
---
## decide
-> page: when level >= 300
-> ticket: when level >= 200
## page
## ticket
""")
    assert not [code for code in _codes(graph) if code.startswith("spiral")]


def test_graph_meta_carries_frontmatter():
    graph = parse("""---
start: a
packing: spiral
---
## a
-> done: else
## done
""")
    assert graph.meta.get("packing") == "spiral"
    assert graph.meta.get("start") == "a"
